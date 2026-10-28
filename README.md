# Angelia

Angelia is a local Windows investigation workbench. It collects live host activity or imports saved evidence into a case, keeps hashed copies of original sources, builds a process-centered timeline, records explainable findings, and exports a standalone HTML report..

The current release is **0.4.0** for Windows 10/11 x64. The [technical report](reports/ANGELIA_TECHNICAL_PROJECT_REPORT.md) describes the design and measured results; the [PDF version](output/pdf/Angelia_Technical_Project_Report.pdf) is ready to share.

## What it does

| Area | Capability |
| --- | --- |
| Evidence intake | Live ETW collection; saved EVTX/XML, Angelia ETW SQLite, classic PCAP, and PE files |
| Case management | Retained sources with SHA-256 hashes, source-record references, integrity check, process and event queries |
| Analysis | Process-aware timeline, cautious packet correlation, behavioral findings, PE scoring, controlled crash triage |
| Output | Searchable standalone HTML case report; JSON output for selected commands |
| Memory | Separate process inventory for a restricted x64 Windows `PAGEDU64` image format |

Findings are investigative leads. The report keeps the triggering records, the rule explanation, and relevant uncertainty visible.

## Try the packaged demo

Download or build the 0.4.0 zip, extract it, and run this from the extracted folder in PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\demo.ps1
```

The demo uses synthetic Windows events and creates a case under your temporary directory. It needs no administrator rights or network access. The script prints the path to the generated `report.html`. See the [quick start](docs/QUICKSTART.md) for a walkthrough.

## Investigate your own evidence

After extracting the package, run these commands in PowerShell. Choose a private case directory outside the repository:

```powershell
.\angelia.exe case init C:\Cases\investigation-1
.\angelia.exe case import-evtx C:\Cases\investigation-1 C:\Evidence\Sysmon.evtx
.\angelia.exe case analyze C:\Cases\investigation-1
.\angelia.exe case findings C:\Cases\investigation-1
.\angelia.exe case verify C:\Cases\investigation-1
.\angelia.exe case report C:\Cases\investigation-1 --out C:\Cases\investigation-1\report.html
```

`case collect C:\Cases\investigation-1 --duration 60` captures live activity and requires an elevated shell. The import, query, analysis, verification, and report commands run without elevation. [Case documentation](docs/CASES.md) lists the supported inputs and all commands.

Cases and reports can contain file paths, command lines, executable bytes, and crash memory. Keep them private. The ordinary case workflow is local; the optional `writeup --send` action transmits a crash artifact to the configured AI service after an explicit command.

## Build from source

Install Visual Studio 2026 with MSVC x64 and the Windows SDK, CMake 3.25 or newer, Ninja, Git, and PowerShell. The first build uses the internet to bootstrap the pinned vcpkg dependencies.

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\cmake\build.ps1 -Preset default
ctest --preset default
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\dist\pack.ps1 -SkipBuild
```

The executable is written to `build\default\bin\angelia.exe`; the runtime zip is written to `dist\angelia-0.4.0.zip`. Build details and dependency versions are in [CMake presets](CMakePresets.json), [the package manifest](vcpkg.json), and [the build script](cmake/build.ps1).

## Repository guide

- [`src/`](src/) contains the collector, case logic, scoring, crash triage, and memory modules.
- [`tools/angelia/`](tools/angelia/) contains the consolidated command-line entry point.
- [`tests/`](tests/) contains automated tests and synthetic fixtures.
- [`docs/`](docs/) contains the quick start, case guide, validation records, and supporting evidence summaries.
- [`reports/ANGELIA_TECHNICAL_PROJECT_REPORT.md`](reports/ANGELIA_TECHNICAL_PROJECT_REPORT.md) is the editable project report; the PDF is generated from it by [`tools/report/render_project_report.py`](tools/report/render_project_report.py) using ReportLab.

Local cases, crash dumps, build outputs, distribution staging, and temporary files are excluded by [`.gitignore`](.gitignore). The PDF report is the only generated output kept for sharing in the repository.

To rebuild the PDF on Windows, install the [report dependency](tools/report/requirements.txt) with `python -m pip install -r tools/report/requirements.txt`, then run `python tools/report/render_project_report.py`.

## Supported scope

Live collection uses Windows ETW and records both internal drop counters and available ETW loss counters. Process links from an initial snapshot are marked as time-based. Packet links require a matching Sysmon network tuple within two seconds and can remain ambiguous or unlinked. PCAP import currently indexes supported IPv4 TCP/UDP records in classic PCAP; PCAPNG and IPv6 are outside that parser's scope. The HTML report displays the first 5,000 timeline rows, while the CLI can query the full case.

The [validation record](docs/RELEASE_VALIDATION.md), [findings evaluation](docs/FINDINGS_VALIDATION.md), and [memory method](docs/MEMORY_VALIDATION.md) provide the exact checks and interpretation. See the technical report for the complete project assessment.

## License

Angelia project code is licensed under the [GNU Affero General Public License, version 3](LICENSE) (`AGPL-3.0-only`). Third-party components retain their own licenses.
