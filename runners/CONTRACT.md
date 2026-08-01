# Runner contract, v1

Every client runner is `runners/<client-id>/run.sh`. The harness treats runners as
black boxes that obey this contract; nothing else about a runner is assumed.

## Invocation

    run.sh <bundle-dir> <server> <evidence-dir>

- `bundle-dir` (read-only): the chain under test, normalized by the harness:
  - `root.crt` trust anchor (PEM). For self-signed rows this is the leaf itself.
  - `leaf.crt` end-entity cert (PEM)
  - `int.crt` intermediate (PEM), absent for self-signed rows
  - `chain.pem` leaf followed by intermediate (what a server sends)
- `server`: `host:port` of a live TLS 1.3 server presenting `chain.pem` with the
  leaf key, or `-` when there is no handshake test (runner must emit skip).
  The host part is the leaf's expected hostname (usually `matrix.test`); docker
  runners map it to 127.0.0.1 with `--add-host` and use `--network host`.
- `evidence-dir` (writable): the runner MUST write the raw, unedited output of
  each test here: `parse.txt`, `verify.txt`, `handshake.txt`.

## Output

stdout: exactly one JSON object, nothing else.

    {
      "client": "openssl-3.0",
      "client_version": "OpenSSL 3.0.13 30 Jan 2024",
      "tests": {
        "parse":     {"status": "ok|fail|skip", "detail": "..."},
        "verify":    {"status": "ok|fail|skip", "detail": "..."},
        "handshake": {"status": "ok|fail|skip", "detail": "..."}
      }
    }

- `parse`: can the client parse/print the leaf certificate.
- `verify`: offline chain validation, `root.crt` as the only trust anchor.
- `handshake`: TLS connection to `server` with certificate validation against
  `root.crt`. ok requires the connection to be established AND validated.
- `detail` on fail carries the client's exact error text (last lines, max ~400
  chars). Never editorialize: the error text IS the data. skip requires a reason.

## Exit code

0 means the runner ran and the JSON is valid, regardless of test outcomes.
Nonzero means runner infrastructure failure (missing image, bad invocation); the
harness reports it and excludes the cell.

## Shared emitter

`runners/lib/emit.py` builds the JSON from captured return codes and evidence
files; use it instead of hand-writing JSON.
