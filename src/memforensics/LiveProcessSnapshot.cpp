#include "memforensics/LiveProcessSnapshot.h"

#include <windows.h>
#include <winternl.h>

#include <nlohmann/json.hpp>

#include <fmt/format.h>

#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <vector>

using json = nlohmann::json;

namespace angelia::memforensics {

namespace {

// SystemProcessInformation is enum value 5 of SYSTEM_INFORMATION_CLASS
// as declared in winternl.h; keep our own copy of the layout we need.
struct SYSTEM_PROCESS_INFORMATION_MIN {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  Reserved[3];
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    ULONG          BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    // …trailing fields omitted; we advance by NextEntryOffset.
};

std::string wide_to_utf8(const wchar_t* p, USHORT bytes) {
    if (!p || bytes == 0) return {};
    const int chars = bytes / static_cast<int>(sizeof(wchar_t));
    const int need = WideCharToMultiByte(CP_UTF8, 0, p, chars,
                                          nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string s(static_cast<std::size_t>(need), '\0');
    WideCharToMultiByte(CP_UTF8, 0, p, chars, s.data(), need, nullptr, nullptr);
    return s;
}

std::string iso8601_now() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char b[32];
    std::snprintf(b, sizeof(b), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return b;
}

}  // namespace

bool capture_live(LiveSnapshot& out, std::string& err) {
    out.processes.clear();
    out.captured_iso8601_utc = iso8601_now();

    std::vector<uint8_t> buf(256 * 1024);
    ULONG needed = 0;
    NTSTATUS status = 0;
    for (int attempt = 0; attempt < 6; ++attempt) {
        status = NtQuerySystemInformation(SystemProcessInformation,
                                          buf.data(), static_cast<ULONG>(buf.size()),
                                          &needed);
        if (status == 0) break;   // STATUS_SUCCESS
        if (status == 0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */) {
            buf.resize(std::max<std::size_t>(needed + 65536, buf.size() * 2));
            continue;
        }
        err = fmt::format("NtQuerySystemInformation status=0x{:08x}",
                          static_cast<uint32_t>(status));
        return false;
    }
    if (status != 0) { err = "NtQuerySystemInformation kept requesting more space"; return false; }

    auto* p = buf.data();
    for (;;) {
        const auto* spi = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION_MIN*>(p);
        LiveProcess lp;
        lp.pid   = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(spi->UniqueProcessId));
        lp.image = wide_to_utf8(spi->ImageName.Buffer, spi->ImageName.Length);
        lp.create_time_100ns = static_cast<uint64_t>(spi->CreateTime.QuadPart);
        // pid 0 is System Idle Process; keep it as-is for accounting.
        out.processes.push_back(std::move(lp));
        if (spi->NextEntryOffset == 0) break;
        p += spi->NextEntryOffset;
    }
    return true;
}

bool save_snapshot(const LiveSnapshot& s, const std::filesystem::path& path,
                   std::string& err) {
    json j;
    j["captured_iso8601_utc"] = s.captured_iso8601_utc;
    j["processes"] = json::array();
    for (const auto& lp : s.processes) {
        j["processes"].push_back({{"pid", lp.pid}, {"image", lp.image},
                                   {"create_time_100ns", lp.create_time_100ns}});
    }
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) { err = "cannot write " + path.string(); return false; }
    f << j.dump(2);
    return true;
}

bool load_snapshot(const std::filesystem::path& path, LiveSnapshot& out,
                   std::string& err) {
    std::ifstream f(path);
    if (!f) { err = "cannot open " + path.string(); return false; }
    try {
        json j; f >> j;
        out.captured_iso8601_utc = j.value("captured_iso8601_utc", "");
        out.processes.clear();
        if (j.contains("processes") && j["processes"].is_array()) {
            for (const auto& e : j["processes"]) {
                LiveProcess lp;
                lp.pid   = e.value("pid", uint32_t{0});
                lp.image = e.value("image", "");
                lp.create_time_100ns = e.value("create_time_100ns", uint64_t{0});
                out.processes.push_back(std::move(lp));
            }
        }
    } catch (const std::exception& e) { err = e.what(); return false; }
    return true;
}

}  // namespace angelia::memforensics
