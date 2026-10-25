# Elevated live snapshot validation — 25 October 2026

This 30-second capture used Angelia 0.4.0. The test started a PowerShell
workload process before collection, then triggered file and registry actions
after ETW began. The collector ran elevated; the workload ran under the
ordinary user token.

## Result

| Check | Observed |
| --- | ---: |
| ETW events imported | 428,276 |
| Initial processes retained | 306 |
| Events associated with a snapshot process | 426,947 |
| Events without process identity | 211 (0.05%) |
| Angelia pool/queue drops | 0 / 0 |
| ETW lost events/log buffers/realtime buffers | 0 / 0 / 0 |
| Retained source hashes verified | 2 / 2 |

Source #1 is the pre-collection process snapshot. Source #2 is the ETW SQLite
capture. Both are retained in the local case's `sources/` and pass
`angelia case verify`. The raw case is excluded from the public repository
because host event records can contain private paths and process data.

The pre-existing workload had PID 6656 and process key
`snapshot:1:6656:134373992141750673`. Angelia associated 3,273 of its
events with this key. Evidence examples from ETW source #2:

| Source record | Observation |
| ---: | --- |
| 47030 | Opened `incoming/workload/sample-0.txt` |
| 47032 | Created `incoming/workload/sample-0.txt` |
| 50094 | Renamed the file to `renamed-0.txt` |
| 51096 | Created `Software\AngeliaLiveValidation\snapshot-validation-20261025T105334Z` |
| 51480 | Set the `Marker` registry value |
| 53025 | Process ended |

The helper's remaining 67 events were emitted just after its `ProcessEnd`
event and are deliberately left unattributed to avoid guessing across PID
reuse. Six other PIDs account for the other 144 unattributed events. The
process snapshot greatly reduced the identity gap seen in the earlier capture,
but this run does not prove every PID association is correct. Snapshot links
remain marked as time-based in the report.

`angelia case analyze` produced zero behavior findings for this benign
workload. This checks the case pipeline, not the rules' sensitivity or false
alarm rate. The capture still contains 64,214 `Unknown` event kinds, led by
Kernel-Process ID 21; these require separate provider mapping work.

On the machine retaining the case, its HTML report shows source hashes,
coverage, and the first 5,000 timeline rows. The controlled workload occurred
later than those rows; query it with:

```powershell
& .\build\default\bin\angelia.exe case timeline .\cases\snapshot-validation-20261025T105334Z --pid 6656 --contains 'sample-0.txt' --limit 20
& .\build\default\bin\angelia.exe case timeline .\cases\snapshot-validation-20261025T105334Z --pid 6656 --contains 'AngeliaLiveValidation' --limit 20
```
