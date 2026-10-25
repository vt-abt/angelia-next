# Phase 0 baseline (25 October 2026)

This file records a fresh run of the current consolidated build. The older
technical report is historical: its 16-binary evaluation included four
standalone tool executables that no longer exist. The current corpus has 13
binaries (7 positive, 6 negative). Do not compare its confusion matrix with
the older report as if the sample sets were identical.

## Reproduce on Windows

Run from the repository root in PowerShell. The first build needs internet
access to fetch vcpkg and its packages; later builds reuse the local cache.
The build script uses the vcpkg revision pinned in `cmake/build.ps1`, and
`vcpkg.json` pins the corresponding package baseline.

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File cmake/build.ps1 -Preset default
build\default\bin\common_tests.exe
build\default\bin\angelia.exe bench --producers 4 --events 1000000
```

Run the controlled crash and evaluation demonstration with Git Bash:

```powershell
& 'C:\Program Files\Git\bin\bash.exe' tools/case_study/run.sh
```

The driver prints a new `case_study/<run-id>/` path for its crash artifacts,
evaluation CSV/JSON, and two HTML reports. These generated files are ignored
by Git. Run commands from the repository root because corpus paths are
relative to it.

## Results of the Phase 0 run

Environment: Windows x64, MSVC 19.51, Windows SDK 10.0.26100, CMake 4.3.1,
vcpkg revision `0c2a9ace1964b818b15f7ae50ba1c42404918a7b`.

| Check | Result |
|---|---|
| Clean configure and build | Passed; `angelia.exe`, `common_tests.exe`, and seven corpus executables produced |
| Unit suite | 24/24 passed |
| One-million-event synthetic collector run | 1,000,000 committed; zero pool drops; zero queue drops; pass |
| Missing evaluation binary | Exits 2 with path and error; no output directory created |
| Six controlled crash targets | Six artifacts captured, analyzed, and classified |
| Evaluation, corrected corpus | 13 binaries; best threshold 0.05: TP 5, FP 0, TN 6, FN 2, F1 0.833 |
| Report generation | Hero and stack-variant HTML reports produced |
| Runtime zip | `tools/dist/pack.ps1 -SkipBuild` produced `dist/angelia-0.1.0.zip` |

The three stack variants classified as Exploitable (mitigations off),
NotExploitable (stack cookie), and NotExploitable (full mitigations). The three
heap variants classified as Unknown in this run; heap verdicts are known to
vary between runs. The evaluation's six negative examples are only two
project binaries and four Windows binaries. Its 1.000 precision on that small,
selected set is not evidence of real-world malware-detection accuracy.

## Scope of this baseline

- The million-event run is synthetic and does not establish whether ETW
  itself lost events. A new elevated live-collection run is still needed.
- Memory analysis passed synthetic unit tests but has not been validated on
  a genuine supported memory image end to end.
- The AI writeup was not called; it requires an external API key.
- Generated reports are demonstration artifacts, not independently verified
  forensic conclusions.
- The runtime zip omits the deliberately vulnerable corpus executables, so
  the built-in evaluation is reproduced from a source build, not from the zip.

These are the starting checks for the case-format and evidence-ingestion
work in the next phase.
