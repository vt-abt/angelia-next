# Project plan — verbatim brief

The following was handed to the project as the working plan. Kept in the
repo so the constraints and pass conditions stay authoritative when the
implementation gets edited.

---

**P0.1 — ETW pipeline under real load.** Build the KrabsETW →
object-pool-backed EventRecord → ConcurrentQueue → single writer thread →
SQLite WAL path, with full in-callback materialization from day one — the
payload-lifetime fix belongs here, not retrofitted later. Drive it with
100k+ events, not a token sample. Measure dropped events, queue depth over
time, writer throughput, SQLite commit latency, CPU. **Pass condition:**
zero drops, stable queue depth under sustained load.

**P0.2 — Dump format identification.** Feed the parser your acquisition
tool's actual output. Read the first 8 bytes, check for `PAGE` + `DU64`.
Present means a header-bearing dump, and you know exactly where
`DirectoryTableBase` and `PsActiveProcessHead` live. Absent means clean
rejection with a message saying what you actually got, not a silent wrong
assumption. This is also where you settle, for real, which acquisition
tool and flag combination produces the header-bearing format.

**P0.3 — PDB type resolution.** One known Windows kernel build, its
matching PDB, walk `_EPROCESS → ActiveProcessLinks` → resolved offset via
`TI_GET_CHILDREN` / `TI_GET_SYMNAME` / `TI_GET_OFFSET`. Then deliberately
hand it a mismatched PDB and confirm it fails safely instead of returning
garbage. **Pass condition:** correct offset on match, clean rejection on
mismatch.

**P0.4 — Crash artifact, no classification.** One vulnerable build, one
mitigated build, crash both. Produce the normalized artifact — exception
code, ip, sp, fault address, faulting instruction, register state,
mitigation flags, pattern-match result — as a self-contained record.
Nothing interprets it yet.

**P0.5 — Zydis correlation.** Feed P0.4's artifact through Zydis, extract
the actual operands of the faulting instruction, correlate against the
cyclic pattern. Still no verdict — just proof the evidence extraction is
correct against a known crash.

Any of these five failing tells you that immediately, with nothing else
built on top of the broken assumption.

## Stage 1 — Component 1, full build

Take P0.1's proven pipeline and extend it to the real provider set:
Kernel-Process, Kernel-File, Kernel-Registry. Define the actual
`EventRecord` schema per event type — a process-start event and a
registry-write event don't need identical shape, parse only what each type
needs. Design the SQLite timeline table properly, indexed by PID and
timestamp, since Components 3 and 4 both query against it downstream.
Comes out of this stage as a working live collector producing a queryable
timeline, already stress-tested at real volume.

## Stage 2 — Component 2, full build

From P0.2/P0.3: implement the full 4-level page table walker (CR3 → PML4 →
PDPT → PD → PT → physical frame). Wire up dynamic `_EPROCESS` offset
resolution with per-build caching so it doesn't re-resolve every run. Walk
`ActiveProcessLinks` raw across the whole process list, cross-reference
against a `ZwQuerySystemInformation(SystemProcessInformation)` snapshot
taken at acquisition time, flag anything in the raw walk that's missing
from the documented enumeration. Output is a structured process inventory
with cross-source differences marked for review, not a printout.

## Stage 3 — Component 3, risk scoring

Static leg first, since it's the known quantity: PE header parsing,
per-section entropy, import-table pattern matching for the injection triad
and ransomware shape. Behavioural leg starts deterministic: extract
sequence features over Component 1's timeline (ProcessStart → ImageLoad →
RegistryModification → FileWrite → NetworkActivity) and check, on a small
labeled test set, whether those features actually separate benign from
suspicious behavior. Only add the Markov / n-gram scorer on top if they
show real signal. If they don't, ship the deterministic rules as the final
behavioural leg and say so plainly in the report — "tested for signal,
found it insufficient to justify a model" is a legitimate result, not a
failure.

## Stage 4 — Component 4, crash triage

Build the corpus first: three compiled variants of each vulnerable binary
— baseline with GS / CFG / ASLR / DEP all off, GS-only, full mitigations
on. Three rows, enough to attribute behavior to a specific mitigation
without doubling the build/test surface.

Keep the pipeline decoupled: fuzzer produces a crash, VEH captures it,
`MiniDumpWriteDump` writes it, and that crash artifact is a complete,
serializable record independent of whatever analyzes it later. The offline
analyzer is a separate stage consuming that artifact — Zydis decode of the
actual faulting operand, cyclic-pattern correlation, stack-cookie
detection, `GetProcessMitigationPolicy` read — all of it becomes an
evidence list attached to the crash, not silently baked into a single
number.

Classifier sits on top of the evidence list: bucket into the MSEC
`!exploitable` taxonomy as the headline verdict, but every verdict carries
its evidence and a confidence score, so "mitigated" means "here's what was
actually observed and what it rules in or out." LLM writeup layer goes
last, once the deterministic verdict and evidence are stable — it
**explains** the verdict, it doesn't produce it.

## Stage 5 — Integration

Confirmed overflow findings from Component 4 feed into Component 3's risk
score as a feature. Build the single per-incident report laying out
timeline, memory findings, risk score, and crash triage side by side —
this is the artifact an investigator actually uses, worth real effort, not
something bolted on at the end.

## Stage 6 — Evaluation and writeup

Precision / recall for the static overflow detector against your own
corpus, now with mitigation-level granularity so you can show the same bug
getting a different verdict across the three builds. One full worked case
study run end to end through all four components. Report names both
modules explicitly — Windows Forensics (Capturing Volatile Data, Memory
Analysis) and Reverse Engineering (Heap Overflow, Stack Overflow) — cites
the MSEC taxonomy by name, shows real output in the results section rather
than architecture diagrams standing in for results.
