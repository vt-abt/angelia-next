# Release validation (25 October 2026)

## Phase 6: case crash triage

`case crash` now runs capture → analyze → classify and retains separately
hashed copies of the executable, exact input, initial capture JSON, classified
JSON, and minidump. `case crashes` groups repeat runs by executable and input
hash. The case report shows the instruction, rationale, full artifact, source
IDs, and a warning when verdict buckets differ. `case verify` detects missing
or modified retained files.

The controlled run used one `vuln_stack_off` capture and three captures each
for `vuln_heap_off`, `vuln_heap_gs`, and `vuln_heap_full`, all with a 256-byte
cyclic pattern. The stack capture was classified `Exploitable` with a recorded
saved-return-address pattern hit. All nine heap captures were classified
`Unknown` at 0.25 confidence. These heap runs did **not** disagree with each
other in this session. Their `Unknown` result is a limit of the current rules;
it must not be treated as evidence that the programs are safe. The repeat-run
comparison remains visible so future disagreements are not hidden.
The explicit `--input FILE` capture path was also exercised with the retained
cyclic input from the stack run; it produced the same verdict shape and all
five retained sources verified.

The automated crash-case smoke test captures the stack example and two heap
runs, checks that source IDs and crash evidence are present, generates the HTML
report, deliberately changes a retained source in its temporary test case,
checks that verification fails, restores it, and checks that verification
passes again.

## Phase 7: package and first-use check

The 0.4.0 zip includes `angelia.exe`, its staged debugging DLLs, the three x64
MSVC runtime DLLs imported by the executable, a quick-start
guide, a synthetic event example, and `demo.ps1`. The demo was run from a fresh
extraction outside the build output. It created a case, imported nine example
events, generated three named findings, verified the retained source, and
exported a standalone report without an administrator shell or network access.
The example intentionally includes a false alarm and a missed scenario; its
finding count is not an accuracy claim.

All 29 configured tests passed on this development machine. The exported
report was opened in Edge through Playwright at desktop and 390 px mobile
width. Page title and content loaded, there were no page or console errors,
the timeline filter reduced nine rows to one for `notepad`, and the mobile
layout had no horizontal page overflow after the layout fix. The Browser
plugin was unavailable, so the check used local Playwright with installed
Edge. The report contains no remote assets.

Network use in `angelia writeup` now requires an explicit `--send`; `--dry-run`
prints the full prompt locally. Case files and HTML exports still contain
sensitive evidence and must be kept in a private location.

## Elevated live capture

The new automatic process-snapshot path was validated on this machine with a
30-second elevated ETW capture. Source #1 retained 306 initial process
identities; source #2 retained 428,276 events. Angelia linked 426,947 events to
snapshot identities, including 3,273 events from a controlled process that
was already running before collection. Only 211 events lacked process identity.
ETW reported zero lost events or buffers, and Angelia reported zero pool or
queue drops. Both retained sources passed SHA-256 verification. The detailed
record is in `cases/snapshot-validation-20261025T105334Z/VALIDATION.md`
in the development workspace; the live case is not bundled in the runtime zip.

**Remaining field checks:** The zip has not yet been run on a separate clean
Windows installation. Its successful local extraction and bundled runtime
files are sufficient for the current local use check, but do not prove
portability to every Windows installation. The memory walker still lacks the
two genuine-image comparisons recorded in [MEMORY_VALIDATION.md](MEMORY_VALIDATION.md).
The live capture also contained 64,214 unmapped event kinds. The finding rules
still need evaluation on more diverse real activity.
