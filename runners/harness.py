#!/usr/bin/env python3
"""Matrix harness: chains x runners -> results/results.json + MATRIX.md.

Per chain: normalize a bundle (root/int/leaf/chain.pem), start the host
openssl s_server (3.5.5, the only stack here that can present PQ chains),
invoke every runner per CONTRACT.md, collect cells. Raw client output lands in
results/evidence/<chain>/<client>/. MATRIX.md is generated, never hand-edited.
"""
import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNNERS = sorted(p.parent for p in (ROOT / "runners").glob("*/run.sh"))
RESULTS = ROOT / "results"
PORT = 14433

# chain name -> (chain dir, CA dir). CA dir differs for catalyst (phase0 ECDSA CA).
GEN = ROOT / "gen" / "chains"
P0 = ROOT / "phase0" / "chains"
CHAINS = {
    "ecdsa": (GEN / "ecdsa", GEN / "ecdsa"),
    "mldsa44": (GEN / "mldsa44", GEN / "mldsa44"),
    "mldsa65": (GEN / "mldsa65", GEN / "mldsa65"),
    "mldsa87": (GEN / "mldsa87", GEN / "mldsa87"),
    "slhroot": (GEN / "slhroot", GEN / "slhroot"),
    "mixed": (GEN / "mixed", GEN / "mixed"),
    "catalyst": (P0 / "catalyst", P0 / "ecdsa"),
    "composite": (ROOT / "composite" / "chains", None),  # self-signed, no key kept
}


def bundle(name: str) -> Path:
    src, ca = CHAINS[name]
    b = RESULTS / "bundles" / name
    b.mkdir(parents=True, exist_ok=True)
    if name == "composite":
        leaf = src / "composite-selfsigned.crt"
        shutil.copy(leaf, b / "leaf.crt")
        shutil.copy(leaf, b / "root.crt")  # self-signed: trust anchor is itself
        shutil.copy(leaf, b / "chain.pem")
        return b
    shutil.copy(src / "leaf.crt", b / "leaf.crt")
    shutil.copy(ca / "root.crt", b / "root.crt")
    shutil.copy(ca / "int.crt", b / "int.crt")
    (b / "chain.pem").write_bytes(
        (src / "leaf.crt").read_bytes() + (ca / "int.crt").read_bytes()
    )
    key = src / "leaf.key"
    if key.exists():
        shutil.copy(key, b / "leaf.key")
    return b


def redact(text: str) -> str:
    """Strip the checkout's absolute path out of anything we are about to commit.

    Runners must receive absolute bundle paths because docker mounts need them,
    and tools echo those paths back: `openssl verify` prints the full path of the
    certificate it checked. That puts the machine's account name into committed
    evidence, which this repo publishes. Redacting once here, at the point of
    collection, covers every runner including ones added later.
    """
    return text.replace(str(ROOT), "<repo>")


def redact_tree(d: Path) -> None:
    """Redact every text file a runner wrote into its evidence directory."""
    for f in d.rglob("*"):
        if not f.is_file():
            continue
        try:
            original = f.read_text(errors="replace")
        except OSError:
            continue  # binary or unreadable; nothing path-shaped to leak
        cleaned = redact(original)
        if cleaned != original:
            f.write_text(cleaned)


def wait_port(timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", PORT), 0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main() -> None:
    cells, failures = [], []
    for name in CHAINS:
        b = bundle(name)
        server = "-"
        proc = None
        if (b / "leaf.key").exists():
            proc = subprocess.Popen(
                ["openssl", "s_server", "-accept", str(PORT), "-quiet",
                 "-cert", str(b / "leaf.crt"), "-key", str(b / "leaf.key"),
                 "-cert_chain", str(b / "int.crt")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if wait_port():
                host = "matrix-hybrid.test" if name == "catalyst" else "matrix.test"
                server = f"{host}:{PORT}"
            else:
                proc.terminate()
                proc = None
                print(f"WARN: server failed to start for {name}", file=sys.stderr)

        for rdir in RUNNERS:
            client = rdir.name
            ev = RESULTS / "evidence" / name / client
            ev.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(
                [str(rdir / "run.sh"), str(b), server, str(ev)],
                capture_output=True, text=True,
            )
            if r.returncode != 0:
                failures.append(f"{client}/{name}: rc={r.returncode} {redact(r.stderr.strip())[:200]}")
                continue
            redact_tree(ev)
            cell = json.loads(redact(r.stdout))
            cell["chain"] = name
            cells.append(cell)
            t = cell["tests"]
            print(f"{name:10s} {client:14s} "
                  f"parse={t['parse']['status']:4s} verify={t['verify']['status']:4s} "
                  f"handshake={t['handshake']['status']}")

        if proc:
            proc.terminate()
            proc.wait(timeout=5)

    (RESULTS / "results.json").write_text(json.dumps(cells, indent=2) + "\n")
    write_matrix(cells)
    print(f"\n{len(cells)} cells -> results/results.json, MATRIX.md")
    for f in failures:
        print("RUNNER FAILURE:", f)


MARK = {"ok": "&check;", "fail": "&cross;", "skip": "&ndash;"}


def write_matrix(cells: list) -> None:
    clients = sorted({c["client"] for c in cells})
    by = {(c["chain"], c["client"]): c["tests"] for c in cells}
    versions = {c["client"]: c["client_version"] for c in cells}

    md = ["# Client compatibility matrix",
          "",
          "Generated by `runners/harness.py` from `results/results.json`; do not",
          "hand-edit. Cell format: parse / offline chain verify / TLS 1.3 handshake.",
          "&check; ok, &cross; fail, &ndash; skipped. Exact client error text lives in",
          "`results/results.json` and raw output in `results/evidence/`.",
          "",
          "| Chain | " + " | ".join(clients) + " |",
          "|---|" + "---|" * len(clients)]
    for chain in CHAINS:
        row = [chain]
        for cl in clients:
            t = by.get((chain, cl))
            row.append(" / ".join(MARK[t[k]["status"]] for k in ("parse", "verify", "handshake")) if t else "n/a")
        md.append("| " + " | ".join(row) + " |")
    md += ["", "Client versions:", ""]
    md += [f"- {c}: {versions[c]}" for c in clients]
    (ROOT / "MATRIX.md").write_text("\n".join(md) + "\n")


if __name__ == "__main__":
    main()
