# Investigation cases

Angelia keeps each investigation in a directory with `case.db` and a
`sources/` folder. Every imported input is copied into `sources/` under its
SHA-256 hash. Normalized rows store a source ID and original record number;
`angelia case status DIR` lists the source paths and hashes. Re-importing the
same source type and hash is idempotent.

## Commands

Run from a PowerShell in the repository root after building Angelia:

For the runtime zip, replace `build\default\bin\angelia.exe` with
`.\angelia.exe` after extracting it.

```powershell
$a = 'build\default\bin\angelia.exe'
& $a case init cases\investigation-1
& $a case collect cases\investigation-1 --duration 60
& $a case import-evtx cases\investigation-1 C:\evidence\Sysmon.evtx
& $a case import-etw cases\investigation-1 C:\evidence\collector.db
& $a case import-pcap cases\investigation-1 C:\evidence\traffic.pcap
& $a case add-pe cases\investigation-1 C:\evidence\program.exe
& $a case analyze cases\investigation-1
& $a case findings cases\investigation-1
& $a case verify cases\investigation-1
& $a case status cases\investigation-1
& $a case processes cases\investigation-1
& $a case timeline cases\investigation-1 --contains 'AppData' --limit 200
& $a case timeline cases\investigation-1 --pid 4242 --json
& $a case report cases\investigation-1 --out cases\investigation-1\timeline.html
```

Live `case collect` requires an elevated Windows shell. `case import-evtx`
reads saved Windows Event Log files via the Windows Event Log API; Sysmon
process, network, file, image-load, registry, and DNS events receive typed
names. Other Windows events are preserved as `WindowsEvent` with their raw
XML. `case import-xml` accepts one exported `<Event>` or an `<Events>`
collection, which is useful for a small shared case or integration testing.

Live collection now saves a process snapshot immediately before ETW starts.
Its PID, image name, and process creation time let the case associate activity
from processes already running when tracing began. The snapshot is retained as
a hashed source. This association is a time-based lead: a missed process-start
event or unusual PID reuse can still make it wrong. A manual `case import-etw`
does not infer this link unless you first run `case import-snapshot DIR FILE`
and pass `--snapshot-source ID` to `case import-etw`.

`case import-pcap` currently indexes classic PCAP files containing Ethernet
or raw IPv4 TCP/UDP packets, including up to two Ethernet VLAN tags. The
original PCAP is preserved even when a packet cannot be indexed. PCAPNG,
IPv6, noninitial IP fragments, and other protocols need explicit support
before their packets will appear in the timeline.

## Process and packet links

Sysmon events use `ProcessGuid`, which remains distinct when Windows reuses
a numeric PID. Parent links use `ParentProcessGuid`. ETW sources lack that
field here, so Angelia creates a process key from an observed process-start
record and associates subsequent events with the latest observed start for
that PID within the same import. If the start is absent, the process key is
left empty.

Packets are assigned a process only when a Sysmon `NetworkConnect` event
has the same protocol, source and destination addresses, ports, and a
timestamp within two seconds. Reverse-direction packets can match the
same connection. If the window contains different process identities, the
packet is marked `ambiguous`; if no match exists, it stays `unlinked`.
These links are investigative hints, not proof that the captured packet was
sent by that process.

`case timeline` supports `--pid`, `--process KEY`, `--contains TEXT`,
`--from YYYY-MM-DDTHH:MM:SSZ`, `--to ...`, `--limit N`, and `--json`.
The HTML report provides instant search across its first 5,000 timeline
rows. Use the CLI for queries over the full case.

## Collection quality

The live collector keeps its SQLite database by default and refuses to
overwrite an existing path. Its output reports its own pool and queue drops
alongside ETW's lost events and lost buffers. `case collect` saves those
statistics in the ETW source's notes. When Windows cannot provide the ETW
counters, the result is explicitly marked unavailable.

The kernel file provider IDs were checked against the installed Windows
provider manifest. The previous mapping mislabeled several file events,
including reads and writes; new captures use the corrected map. Old
collector databases retain their original numeric `kind` values, so their
file labels may be wrong and should be interpreted with their provider and
event ID where available.

## Findings

`case analyze DIR` generates named behavior findings for auto-start Run-key
writes, image loads from commonly user-writable paths, and one process writing
at least 50 distinct file paths. `case add-pe DIR program.exe` preserves and
hashes a binary and stores its existing static PE features as named findings.
`case findings DIR --json` includes the exact source IDs and source record
numbers for behavior evidence; static findings point to the retained binary
hash and include the underlying import and section data. Re-running behavior
analysis replaces its earlier results, while static findings remain attached
to their binary source. If a Sysmon process record carries the same SHA-256
as an added PE, the static finding lists that process as a hash match.

The findings are investigative leads. Each includes a severity rationale and
a limitation; they do not assert malicious intent. The coverage section reports
events without a process identity and ETW loss counters when available. An
incomplete case cannot establish that an activity did not occur. The HTML
report shows findings and their evidence alongside the timeline.

For a reproducible controlled evaluation with both a false alarm and a missed
scenario, use the labeled fixture in `tests/fixtures/case_findings_labels.json`
with `tools/evaluation/eval_case.py`. Its four tiny scenarios check the rule
plumbing; they are not a field accuracy estimate.

## Crash triage inside a case

`case crash DIR --binary PROGRAM --input FILE --repeat N` runs the existing
capture → analyze → classify pipeline on the specified executable and input.
Use `--gen-pattern 256` in place of `--input FILE` for a cyclic test pattern.
Run only programs and inputs that you intend to execute on the test machine.
Each run retains the binary, input, initial capture JSON, classified JSON, and
available minidump as separately hashed sources. The final artifact includes
the exception, registers, instruction bytes and disassembly, pattern offsets,
mitigation state, evidence entries, verdict rationale, and confidence.

`case crashes DIR [--json]` groups runs by binary and input SHA-256, lists
their verdicts, and marks disagreement. Agreement does not establish that a
verdict is correct; inspect each run and the minidump. A missing minidump is
shown as source `#0`. The HTML report embeds the same details and links them
to numbered sources. Crash captures do not add host activity events to the
timeline; they are a separate evidence type within the case.

To replay a verdict, run `case crashes DIR --json` to find its
`capture_source_id`. Run `case verify DIR --json` to map that ID to its retained
`sources/<hash>.json` path. Copy that initial capture JSON to a scratch file,
then run `angelia analyze scratch.json` and `angelia classify scratch.json`.
Compare the resulting `analysis` and `verdict` with the case's classified
artifact. The retained minidump can be inspected separately in a debugger.

`case verify DIR [--json]` checks that every retained source file is still
inside the case and matches its import-time SHA-256. It returns a failure code
for missing, changed, or unsafe paths. Reports run this check and show the
result. The report is self-contained for review, while replaying the case
requires its `case.db` and `sources/` folder.

Case files and reports can contain sensitive paths, command lines, program
inputs, and process memory. Keep them private. Case operations and report
export run locally. The optional `angelia writeup` command requires `--send`
before it transmits the full crash artifact JSON to an external AI service.
