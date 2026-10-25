// P0.4 — parent-debugger crash capture.
//
// Runs the target binary as a debuggee via CreateProcessW(DEBUG_ONLY_THIS_
// PROCESS) so we see the same exception path whether the process crashed
// via a plain AV (baseline corpus) or via fast-fail from a mitigation
// (GS/CFG-triggered STATUS_STACK_BUFFER_OVERRUN 0xC0000409). VEH inside
// the target can't see fast-fail; the debugger channel can.
//
// Writes:
//   <out>/<basename>.<pid>.dmp   MiniDumpWithFullMemory
//   <out>/<basename>.<pid>.json  normalised CrashArtifact
//
// Usage:
//   p04_capture --binary <path> --input <file> --out <dir>
//   p04_capture --binary <path> --gen-pattern 256 --out <dir>

#include <windows.h>
#include <dbghelp.h>
#include <processthreadsapi.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "crashtriage/CrashArtifact.h"
#include "crashtriage/CyclicPattern.h"

#pragma comment(lib, "dbghelp.lib")

using angelia::crashtriage::CrashArtifact;
using angelia::crashtriage::MitigationFlags;
using angelia::crashtriage::RegisterSnapshot;

namespace {

struct Args {
    std::filesystem::path binary;
    std::filesystem::path input;
    std::filesystem::path out{"crashes"};
    std::size_t           gen_pattern = 0;   // 0 == use --input as-is
};

[[noreturn]] void die(const std::string& msg) {
    std::fprintf(stderr, "p04_capture: %s\n", msg.c_str());
    std::exit(2);
}

Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string_view k = argv[i];
        auto need = [&](std::string_view name) -> std::string {
            if (i + 1 >= argc) die(std::string("missing value for ") + std::string(name));
            return argv[++i];
        };
        if      (k == "--binary")      a.binary = need(k);
        else if (k == "--input")       a.input  = need(k);
        else if (k == "--out")         a.out    = need(k);
        else if (k == "--gen-pattern") a.gen_pattern = std::stoull(need(k));
        else die("unknown arg: " + std::string(k));
    }
    if (a.binary.empty()) die("--binary is required");
    if (a.input.empty() && a.gen_pattern == 0)
        die("either --input or --gen-pattern is required");
    return a;
}

std::string iso8601_utc_now() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

void query_mitigations(HANDLE hProc, MitigationFlags& out) {
    PROCESS_MITIGATION_DEP_POLICY dep{};
    if (GetProcessMitigationPolicy(hProc, ProcessDEPPolicy, &dep, sizeof(dep)))
        out.dep_enabled = dep.Enable;

    PROCESS_MITIGATION_ASLR_POLICY aslr{};
    if (GetProcessMitigationPolicy(hProc, ProcessASLRPolicy, &aslr, sizeof(aslr))) {
        out.aslr_bottom_up      = aslr.EnableBottomUpRandomization;
        out.aslr_force_relocate = aslr.EnableForceRelocateImages;
        out.aslr_high_entropy   = aslr.EnableHighEntropy;
    }

    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
    if (GetProcessMitigationPolicy(hProc, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg))) {
        out.cfg_enabled            = cfg.EnableControlFlowGuard;
        out.cfg_export_suppression = cfg.EnableExportSuppression;
        out.cfg_strict_mode        = cfg.StrictMode;
    }

    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY cet{};
    if (GetProcessMitigationPolicy(hProc, ProcessUserShadowStackPolicy, &cet, sizeof(cet))) {
        out.cet_user_shadow_stack         = cet.EnableUserShadowStack;
        out.cet_set_context_ip_validation = cet.SetContextIpValidation;
        out.cet_block_non_cet_binaries    = cet.BlockNonCetBinaries;
    }

    PROCESS_MITIGATION_IMAGE_LOAD_POLICY img{};
    if (GetProcessMitigationPolicy(hProc, ProcessImageLoadPolicy, &img, sizeof(img))) {
        out.image_load_no_low_label = img.NoLowMandatoryLabelImages;
    }
}

void snapshot_registers(const CONTEXT& c, RegisterSnapshot& r) {
    r.rip = c.Rip; r.rsp = c.Rsp; r.rbp = c.Rbp;
    r.rax = c.Rax; r.rbx = c.Rbx; r.rcx = c.Rcx; r.rdx = c.Rdx;
    r.rsi = c.Rsi; r.rdi = c.Rdi;
    r.r8  = c.R8;  r.r9  = c.R9;  r.r10 = c.R10; r.r11 = c.R11;
    r.r12 = c.R12; r.r13 = c.R13; r.r14 = c.R14; r.r15 = c.R15;
    r.eflags = c.EFlags;
    r.cs = c.SegCs; r.ss = c.SegSs;
}

// Copy up to `cap` bytes at `rip` from the debuggee. Whatever ReadProcessMemory
// gives us — a short read at page boundary is fine; we record how many.
uint32_t read_insn(HANDLE hProc, uint64_t rip, uint8_t* out, uint32_t cap) {
    SIZE_T got = 0;
    if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(rip), out, cap, &got))
        return 0;
    return static_cast<uint32_t>(got);
}

bool write_minidump(HANDLE hProc, DWORD pid, HANDLE hFile,
                    DWORD threadId, const EXCEPTION_RECORD& er,
                    const CONTEXT& ctx) {
    // MiniDumpWriteDump wants EXCEPTION_POINTERS living in the target
    // process; the "canonical" pattern is to VirtualAllocEx a scratch
    // block, WriteProcessMemory the CONTEXT / EXCEPTION_RECORD /
    // EXCEPTION_POINTERS in, then pass ClientPointers=TRUE.
    const SIZE_T ctx_sz = sizeof(CONTEXT);
    const SIZE_T er_sz  = sizeof(EXCEPTION_RECORD);
    const SIZE_T ep_sz  = sizeof(EXCEPTION_POINTERS);
    const SIZE_T total  = ctx_sz + er_sz + ep_sz + 64;

    LPVOID base = VirtualAllocEx(hProc, nullptr, total, MEM_COMMIT, PAGE_READWRITE);
    if (!base) return false;

    auto ctx_addr = reinterpret_cast<uint8_t*>(base);
    auto er_addr  = ctx_addr + ctx_sz;
    auto ep_addr  = er_addr  + er_sz;

    SIZE_T wrote = 0;
    if (!WriteProcessMemory(hProc, ctx_addr, &ctx, ctx_sz, &wrote) || wrote != ctx_sz) return false;
    if (!WriteProcessMemory(hProc, er_addr,  &er,  er_sz,  &wrote) || wrote != er_sz)  return false;
    EXCEPTION_POINTERS ep{};
    ep.ExceptionRecord = reinterpret_cast<PEXCEPTION_RECORD>(er_addr);
    ep.ContextRecord   = reinterpret_cast<PCONTEXT>(ctx_addr);
    if (!WriteProcessMemory(hProc, ep_addr, &ep, ep_sz, &wrote) || wrote != ep_sz)     return false;

    MINIDUMP_EXCEPTION_INFORMATION mei{};
    mei.ThreadId          = threadId;
    mei.ExceptionPointers = reinterpret_cast<PEXCEPTION_POINTERS>(ep_addr);
    mei.ClientPointers    = TRUE;

    // MiniDumpWithFullMemory: keep everything. This is a coursework tool,
    // dumps are small (KBs–low MB for our vuln targets).
    const auto dump_type = static_cast<MINIDUMP_TYPE>(
        MiniDumpWithFullMemory | MiniDumpWithHandleData |
        MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules);

    BOOL ok = MiniDumpWriteDump(hProc, pid, hFile, dump_type, &mei, nullptr, nullptr);
    VirtualFreeEx(hProc, base, 0, MEM_RELEASE);
    return ok == TRUE;
}

// Exceptions the debugger delivers that are not "the crash" — filter them.
bool is_noise_exception(DWORD code) {
    return code == EXCEPTION_BREAKPOINT   ||   // loader break
           code == 0x4001000A             ||   // DBG_PRINTEXCEPTION_C
           code == 0x4001000B             ||   // DBG_PRINTEXCEPTION_WIDE_C
           code == 0x406D1388;                 // MS_VC_EXCEPTION (SetThreadName)
}

}  // namespace

int angelia_cli_run_capture(int argc, char** argv) {
    Args a = parse_args(argc, argv);
    std::error_code ec;
    std::filesystem::create_directories(a.out, ec);

    if (a.gen_pattern > 0) {
        auto genpath = a.out / "pattern.bin";
        std::ofstream f(genpath, std::ios::binary | std::ios::trunc);
        auto s = angelia::crashtriage::generate_pattern(a.gen_pattern);
        f.write(s.data(), static_cast<std::streamsize>(s.size()));
        f.close();
        a.input = genpath;
        std::fprintf(stderr, "p04_capture: wrote %zu-byte cyclic pattern to %s\n",
                     s.size(), genpath.string().c_str());
    }

    // Build a mutable command line: "<binary>" <input>
    std::wstring cmdline = L"\"" + a.binary.wstring() + L"\" \"" + a.input.wstring() + L"\"";
    std::vector<wchar_t> cmdbuf(cmdline.begin(), cmdline.end());
    cmdbuf.push_back(L'\0');

    STARTUPINFOW        si{};  si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(a.binary.wstring().c_str(), cmdbuf.data(),
                        nullptr, nullptr, FALSE,
                        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                        nullptr, nullptr, &si, &pi)) {
        std::fprintf(stderr, "p04_capture: CreateProcessW failed (GetLastError=0x%08lx)\n",
                     GetLastError());
        return 1;
    }
    std::fprintf(stderr, "p04_capture: spawned pid=%lu\n", pi.dwProcessId);

    bool captured = false;
    int  ret_code = 3;                          // no crash seen
    DEBUG_EVENT ev{};

    while (WaitForDebugEvent(&ev, INFINITE)) {
        DWORD continueStatus = DBG_EXCEPTION_NOT_HANDLED;

        switch (ev.dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT: {
                const auto& er = ev.u.Exception.ExceptionRecord;
                if (is_noise_exception(er.ExceptionCode)) {
                    continueStatus = DBG_CONTINUE;
                    break;
                }
                if (captured) {
                    // Second-chance re-raise after we already snapshotted:
                    // just let it die.
                    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                    break;
                }

                // First real exception — this is the crash. Snapshot now.
                CrashArtifact art;
                art.binary_path         = a.binary.string();
                art.input_path          = a.input.string();
                art.capture_iso8601_utc = iso8601_utc_now();
                art.exception_code      = er.ExceptionCode;
                art.exception_flags     = er.ExceptionFlags;
                art.first_chance        = ev.u.Exception.dwFirstChance != 0;
                if (er.ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
                    er.NumberParameters >= 2) {
                    art.fault_access_type = static_cast<uint32_t>(er.ExceptionInformation[0]);
                    art.fault_address     = er.ExceptionInformation[1];
                }

                HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                            FALSE, ev.dwThreadId);
                CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_ALL;
                if (hThread && GetThreadContext(hThread, &ctx)) {
                    snapshot_registers(ctx, art.registers);
                    art.insn_bytes_len = read_insn(pi.hProcess, ctx.Rip,
                                                    art.insn_bytes.data(),
                                                    static_cast<uint32_t>(art.insn_bytes.size()));
                    art.stack_bytes_len = read_insn(pi.hProcess, ctx.Rsp,
                                                     art.stack_bytes.data(),
                                                     static_cast<uint32_t>(art.stack_bytes.size()));
                }

                query_mitigations(pi.hProcess, art.mitigations);

                // Write minidump next to the JSON. Name by pid so multiple
                // captures in one out dir don't collide.
                auto stem = a.binary.stem().string();
                auto dump_path = a.out / (stem + "." + std::to_string(pi.dwProcessId) + ".dmp");
                auto json_path = a.out / (stem + "." + std::to_string(pi.dwProcessId) + ".json");
                HANDLE hFile = CreateFileW(dump_path.wstring().c_str(),
                                            GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hFile == INVALID_HANDLE_VALUE) {
                    std::fprintf(stderr, "cannot open %s for write\n", dump_path.string().c_str());
                } else {
                    if (write_minidump(pi.hProcess, pi.dwProcessId, hFile,
                                       ev.dwThreadId, er, ctx)) {
                        art.minidump_path = dump_path.string();
                    } else {
                        std::fprintf(stderr, "MiniDumpWriteDump failed (GetLastError=0x%08lx)\n",
                                     GetLastError());
                    }
                    CloseHandle(hFile);
                }

                {
                    auto js = angelia::crashtriage::to_json(art);
                    std::ofstream j(json_path, std::ios::binary | std::ios::trunc);
                    j.write(js.data(), static_cast<std::streamsize>(js.size()));
                }
                std::fprintf(stderr, "p04_capture: wrote artifact %s\n", json_path.string().c_str());

                if (hThread) CloseHandle(hThread);
                captured = true;
                ret_code = 0;
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                break;
            }
            case EXIT_PROCESS_DEBUG_EVENT:
                goto done;
            case CREATE_PROCESS_DEBUG_EVENT:
                if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
                continueStatus = DBG_CONTINUE;
                break;
            case LOAD_DLL_DEBUG_EVENT:
                if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
                continueStatus = DBG_CONTINUE;
                break;
            default:
                continueStatus = DBG_CONTINUE;
                break;
        }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continueStatus);
    }
done:
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (!captured) {
        std::fprintf(stderr, "p04_capture: process exited without a captured exception\n");
    }
    return ret_code;
}
