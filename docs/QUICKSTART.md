# Angelia quick start

Angelia turns Windows events and crash artifacts into a local investigation
case. It copies imported evidence into `sources/`, records SHA-256 hashes, and
exports a standalone HTML report. The program does not send case data to a
service during normal case commands.

## First run

Extract the zip into a folder on a Windows 10 or 11 x64 machine. In PowerShell,
from that folder, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\demo.ps1
```

The script creates a new case under your temporary directory and prints the
path to `report.html`. The example is synthetic and includes an ordinary
process, a process that triggers two findings, a benign installer that creates
a false alarm, and a scenario the current rules miss. Open the report, read
the findings and source IDs, then search the timeline. No administrator rights
or network connection are required for this example.

## Use your own evidence

```powershell
.\angelia.exe case init C:\Cases\investigation-1
.\angelia.exe case import-evtx C:\Cases\investigation-1 C:\Evidence\Sysmon.evtx
.\angelia.exe case analyze C:\Cases\investigation-1
.\angelia.exe case verify C:\Cases\investigation-1
.\angelia.exe case report C:\Cases\investigation-1 --out C:\Cases\investigation-1\report.html
```

You can also import an Angelia ETW database, a classic PCAP, an event XML
export, or a PE executable; run `angelia case --help` for the commands.
Live `case collect` needs an elevated shell. The report shows event attribution
gaps and collection loss counters when available. Findings are investigative
leads, so review the source records and stated limits.

For a program you intentionally want to test for crashes:

```powershell
.\angelia.exe case crash C:\Cases\investigation-1 --binary C:\Lab\program.exe --input C:\Lab\input.bin --repeat 3
.\angelia.exe case crashes C:\Cases\investigation-1
```

Run crash capture only against a program and input you trust to execute on the
test machine. Angelia keeps the input, binary, initial capture, classified
artifact, and minidump in the case. Repeated runs are compared by binary and
input hash. A classification may vary or remain `Unknown`; inspect each run.

Cases and reports can contain personal paths, command lines, file contents,
and memory from the captured process. Keep them in a private folder and share
them only with the intended reviewer. `angelia writeup` is separate from case
analysis: `--dry-run` prints the full prompt locally; only `--send` transmits
the full crash artifact to the configured AI service.

## Supported inputs and limits

See [CASES.md](CASES.md) for import formats, process and packet linking,
finding rules, and coverage limits. See [MEMORY_VALIDATION.md](MEMORY_VALIDATION.md)
for the currently supported memory format and the pending real-image check.
