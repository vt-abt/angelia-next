# Findings validation (25 October 2026)

Angelia's case rules were checked with four labeled, controlled process
scenarios in `tests/fixtures/case_findings.xml`. The label file is
`tests/fixtures/case_findings_labels.json`; `tools/evaluation/eval_case.py`
computes the outcomes from `case findings --json`.

| Scenario | Expected | Result |
| --- | --- | --- |
| Normal system application | No finding | True negative |
| Run-key write and user-writable image load | Finding | True positive |
| Normal installer writing a Run key | No finding | False positive |
| Encoded command with no covered indicator | Finding | False negative |

Totals: **1 true positive, 1 false positive, 1 false negative, 1 true
negative**. Precision and recall are each 0.5 **on this four-scenario
fixture only**. These values are a regression check and must not be
presented as accuracy on real incidents. Each generated finding points to a
source record; the normal installer result makes the false-alarm risk visible.

For a normal real binary, `C:\Windows\System32\notepad.exe` was imported
with `case add-pe` on this host. Its static score was 0.000 with no named
static findings. This checks one common program; it does not establish a
false-positive rate. The previous 30-second live case yielded zero behavior
findings, but 755,708 of 759,156 events lacked a process identity because
those processes were already running. A later [elevated live validation](evidence/LIVE_SNAPSHOT_VALIDATION.md)
of the initial process snapshot associated 426,947 of 428,276 events with
already-running processes; 211 events lacked process identity.

The rules are leads for review. Run-key writes occur in legitimate installers,
user-writable paths may host legitimate code, and high file-write counts can
come from backups and builds. The case report keeps each rule's stated limit
beside its evidence.
