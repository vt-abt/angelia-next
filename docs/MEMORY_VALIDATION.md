# Memory image validation

Angelia's memory walker currently supports x64 Windows `PAGEDU64` images with
a readable 8 KiB dump header and a physical-memory run table. It rejects raw
physical images, x86 `PAGEDUMP`, user-mode minidumps, truncated run tables,
impossible memory ranges, and images without a DTB or process-list head.
`mem-id` recognizes both Windows header signatures, but `mem-analyze` only
walks x64 `PAGEDU64` at present. Kernel, complete, active, and automatic dumps
can contain different subsets of memory; a matching header alone does not
guarantee that Angelia can walk the process list.

## Compare a genuine image

Use a genuine x64 Windows memory image from an isolated test system. On a
supported Windows version, Task Manager can create a **Full live kernel memory
dump** from the System process without crashing the machine; run Task Manager
as administrator and choose **Create live kernel memory dump file → Full live
kernel memory dump**. The default output directory is
`%LocalAppData%\Microsoft\Windows\TaskManager\LiveKernelDumps`. Check each
file with `mem-id` before the rest of the workflow, because a `.dmp` extension
alone does not establish that Angelia supports its contents. These images can
contain sensitive memory; use an isolated test machine and keep them local.
[Microsoft's Task Manager procedure](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/task-manager-live-dump)
describes the capture and its resource requirements.

Record its capture time, Windows build, dump type, acquisition method, and SHA-256.
Run the following steps for **two different images**. Use a kernel image/PDB
matching each image's Windows build; the default `ntoskrnl.exe` on a different
machine may resolve incompatible `_EPROCESS` offsets.

```powershell
& .\angelia.exe mem-id C:\evidence\memory.dmp
& .\angelia.exe mem-analyze --dump C:\evidence\memory.dmp `
    --kernel-image C:\evidence\matching-ntoskrnl.exe `
    --sym 'srv*C:\symbols*https://msdl.microsoft.com/download/symbols' `
    --out C:\evidence\angelia-processes.json
python C:\path\to\vol.py -f C:\evidence\memory.dmp -r json `
    windows.pslist.PsList > C:\evidence\volatility-pslist.json
python tools\memory_validation\compare.py --dump C:\evidence\memory.dmp `
    --angelia C:\evidence\angelia-processes.json `
    --volatility C:\evidence\volatility-pslist.json `
    --out C:\evidence\comparison.json
```

The comparator checks the same dump's PIDs, image names, and `_EPROCESS`
addresses where both tools report them. It refuses a partial Angelia walk and
records SHA-256 hashes of the dump and both outputs. Differences need manual
investigation; a failed comparison must not be reported as a validated result.

A separate `sys-snapshot` can help investigate what was running at another
time, but a process present only in the dump may simply have exited before
the snapshot. Angelia marks such differences `raw_only` for review and does
not label them hidden processes.

## Current validation state

Synthetic memory and comparison tests pass. No genuine `PAGEDU64` images were
available in this workspace for the required two-image comparison. Therefore
the memory walker is **not yet validated on real captures**. Keep this status
until both real comparisons and discrepancy reviews are recorded.

References: [Microsoft dump varieties](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files),
[Volatility 3 Windows tutorial](https://github.com/volatilityfoundation/volatility3/blob/develop/doc/source/getting-started-windows-tutorial.rst).
