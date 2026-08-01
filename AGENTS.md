# pqc-cert-matrix — agent context

The PQC certificate compatibility matrix: measured client behavior for
post-quantum and hybrid X.509 chains. Flagship of the "operational evidence
layer" strategy. Plan and status: `SCOPE.md`. Findings: `phase0/FINDINGS.md`.

Rules:
- **Evidence standard is the product.** Every published cell is Verified (script
  plus captured output in the repo) or an explicit "not constructible / not
  testable" with the reason. No recalled claims, no hand-edited result tables:
  `SIZES.md` and future matrix tables are generated from JSON.
- **This repo is PUBLIC.** Write everything accordingly: no secrets, no employer
  names or material, no vendor-account artifacts, no personal handles or aliases,
  and no absolute paths from the machine it was built on (the harness redacts the
  checkout path out of captured evidence; keep it that way). Private keys are
  gitignored and generators recreate them.
- Open-source stacks only; no vendor product testing (keeps it reproducible and
  keeps the day-job boundary clean).
- Writing style: `~/.rocky/steering/writing-style.md` (no em dashes, plain
  English) for all prose.
- Related but separate: the book manuscript repo (pqc-lab) is private
  permanently; nothing from it lands here. The book's content freeze is
  legally load-bearing; matrix findings feed articles on carrdigital.dev, not
  the registered manuscript.
