# Contributing

The evidence standard is the product here. A patch that adds code is easy to review. A
patch that adds a *claim* has to arrive with the artifact that proves it.

Read `PRIOR-ART.md` before writing anything that will be published. It records, per
finding, what existing work already covers, and it has demoted claims in this project
more than once.

## The rules I hold myself to

**Every published cell is Verified or explicitly not testable.** Verified means a
script and its captured output ship in the repo. The alternative is an explicit "not
constructible" or "not testable" with the reason stated. There is no third option, and
a recalled claim is not one.

**Result tables are generated, never hand-edited.** `SIZES.md` and the matrix tables
come from JSON. A number typed by hand is a number nobody can reproduce.

**Stamp every claim.** Verified means measured here. Reported means cited to a primary
source that was actually opened. Proposed means designed or projected under stated
assumptions, and not measured. Blurring the three is how a corpus stops being worth
citing.

**Verify load-bearing citations by downloading the full text and grepping it.** Never
from a search summary. This project family has logged several fabricated or
misattributed summaries, which is why the rule exists rather than being advice.

**Open-source stacks only.** No vendor product testing, so every cell stays
reproducible by a stranger with no accounts.

**Write it as public, because it is.** No secrets, no personal handles, and no
absolute paths from the machine it was built on. The harness redacts the checkout path
out of captured evidence at collection time; keep it that way, because scrubbing a
corpus afterward means scrubbing git history too. Private keys are gitignored and the
generators recreate them.

## Words that do not appear here

"First", "only", and "no one has". `PRIOR-ART.md` carries the permitted wording
verbatim, and it is deliberately narrower: we found no published X, searching a named
list of sources, on a stated date. Do not paraphrase it stronger.

## Prose

No em dashes. Plain English, sentence-case headings, and a number wherever an adjective
would do.

## Corrections

If a figure here is wrong, open an issue with the command that shows it. Corrections
are recorded rather than quietly edited, because a corpus that hides its retractions is
worth less than one that publishes them.
