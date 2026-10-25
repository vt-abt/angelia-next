// p07_writeup — LLM writeup layer over a fully-classified crash artifact.
//
// The plan is explicit: the LLM *explains* the verdict, it does not
// produce it. This tool refuses to run on an artifact without both an
// `analysis` and a `verdict` block; the prompt makes the model treat
// those as provisional evidence and does not silently change the bucket.
//
// Uses native WinHTTP only when --send is explicitly supplied. Requires
// ANTHROPIC_API_KEY in the environment. --dry-run emits the prompt locally.
//
// Output goes next to the artifact as <basename>.writeup.md unless
// --out is given.

#include <windows.h>
#include <winhttp.h>

#include <nlohmann/json.hpp>

#include <fmt/format.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "crashtriage/CrashArtifact.h"

#pragma comment(lib, "winhttp.lib")

namespace ac = angelia::crashtriage;
using json  = nlohmann::json;

namespace {

std::string read_env(const char* name, const char* fallback = "") {
    char buf[8192];
    DWORD n = GetEnvironmentVariableA(name, buf, sizeof(buf));
    if (n == 0 || n >= sizeof(buf)) return fallback;
    return std::string(buf, n);
}

std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                       static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        w.data(), n);
    return w;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(),
                                       static_cast<int>(w.size()),
                                       nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                        s.data(), n, nullptr, nullptr);
    return s;
}

std::string build_prompt(const std::string& artifact_json) {
    // We hand the model the entire artifact and ask for prose that
    // grounds every claim in the evidence entries. The verdict is
    // authoritative — the model must not second-guess it.
    return
        "The JSON below is a crash artifact from a Windows investigation. "
        "It was produced by a deterministic pipeline: p04_capture "
        "wrote the exception + register + mitigation state, p05_analyze added the "
        "`analysis` block (Zydis disassembly + cyclic-pattern correlation + typed "
        "evidence entries), and p06_classify assigned the MSEC !exploitable bucket "
        "in the `verdict` block. Treat that bucket as a provisional tool result.\n"
        "\n"
        "Write a concise triage report in markdown for an investigator. Requirements:\n"
        "\n"
        "1. State the bucket and confidence up front. Do NOT propose a different "
        "   bucket, but explain its limits and any uncertainty.\n"
        "2. Explain in plain English WHY the classifier reached this verdict, "
        "   quoting the specific evidence entries by their `detail` strings.\n"
        "3. Interpret the faulting instruction (from `analysis.zydis_disasm`) in "
        "   context of the register state.\n"
        "4. If mitigations intercepted the crash (fast-fail, GS, CFG), name the "
        "   mitigation and describe what it prevented.\n"
        "5. If the cyclic pattern correlates a specific offset, name the offset "
        "   and what it tells the operator about attacker control.\n"
        "6. Do NOT invent facts. Do NOT speculate about exploit payloads. If a "
        "   field is missing or the classifier returned Unknown, say so.\n"
        "\n"
        "Artifact:\n"
        "```json\n" + artifact_json + "\n```\n";
}

// Minimal request bundle for the Messages API. Uses x-api-key auth per
// the current Anthropic documentation.
struct HttpResult {
    bool         ok = false;
    unsigned     status = 0;
    std::string  body;
    std::string  error;
};

HttpResult post_anthropic(std::string_view api_key,
                          std::string_view host,       // "api.anthropic.com"
                          std::string_view path,       // "/v1/messages"
                          std::string_view body_utf8)
{
    HttpResult r;
    HINTERNET hSes  = nullptr;
    HINTERNET hCon  = nullptr;
    HINTERNET hReq  = nullptr;
    auto cleanup = [&]() {
        if (hReq) WinHttpCloseHandle(hReq);
        if (hCon) WinHttpCloseHandle(hCon);
        if (hSes) WinHttpCloseHandle(hSes);
    };

    hSes = WinHttpOpen(L"angelia-p07/0.0.1",
                       WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                       WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) { r.error = "WinHttpOpen failed"; cleanup(); return r; }

    auto whost = widen(host);
    hCon = WinHttpConnect(hSes, whost.c_str(),
                          INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hCon) { r.error = "WinHttpConnect failed"; cleanup(); return r; }

    auto wpath = widen(path);
    hReq = WinHttpOpenRequest(hCon, L"POST", wpath.c_str(), nullptr,
                              WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                              WINHTTP_FLAG_SECURE);
    if (!hReq) { r.error = "WinHttpOpenRequest failed"; cleanup(); return r; }

    std::wstring headers =
        L"Content-Type: application/json\r\n"
        L"anthropic-version: 2023-06-01\r\n"
        L"x-api-key: " + widen(api_key) + L"\r\n";

    if (!WinHttpSendRequest(hReq, headers.c_str(), static_cast<DWORD>(-1),
                            const_cast<char*>(body_utf8.data()),
                            static_cast<DWORD>(body_utf8.size()),
                            static_cast<DWORD>(body_utf8.size()), 0)) {
        r.error = fmt::format("WinHttpSendRequest failed (GetLastError=0x{:08x})",
                              static_cast<uint32_t>(GetLastError()));
        cleanup(); return r;
    }
    if (!WinHttpReceiveResponse(hReq, nullptr)) {
        r.error = fmt::format("WinHttpReceiveResponse failed (GetLastError=0x{:08x})",
                              static_cast<uint32_t>(GetLastError()));
        cleanup(); return r;
    }

    DWORD status = 0, size = sizeof(status);
    if (!WinHttpQueryHeaders(hReq,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)) {
        r.error = "WinHttpQueryHeaders(status) failed"; cleanup(); return r;
    }
    r.status = status;

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hReq, &avail)) break;
        if (avail == 0) break;
        std::string chunk(avail, '\0');
        DWORD got = 0;
        if (!WinHttpReadData(hReq, chunk.data(), avail, &got)) break;
        chunk.resize(got);
        r.body += chunk;
    }
    r.ok = true;
    cleanup();
    return r;
}

}  // namespace

int angelia_cli_run_writeup(int argc, char** argv) {
    std::filesystem::path in_path, out_path;
    bool dry_run = false, send = false;
    for (int i = 1; i < argc; ++i) {
        std::string_view k = argv[i];
        if      (k == "--out"     && i + 1 < argc) out_path = argv[++i];
        else if (k == "--dry-run")                 dry_run = true;
        else if (k == "--send")                    send = true;
        else if (k[0] != '-')                      in_path = std::string(k);
        else { std::fprintf(stderr, "unknown arg: %.*s\n", (int)k.size(), k.data()); return 2; }
    }
    if (in_path.empty()) {
        std::fprintf(stderr,
            "usage: angelia writeup <artifact.json> [--out <path.md>] (--dry-run | --send)\n"
            "env: ANTHROPIC_API_KEY (required unless --dry-run)\n"
            "     ANTHROPIC_MODEL   (default: claude-sonnet-5)\n");
        return 2;
    }

    std::ifstream f(in_path);
    if (!f) { std::fprintf(stderr, "cannot open %s\n", in_path.string().c_str()); return 1; }
    std::stringstream ss; ss << f.rdbuf();
    std::string js = ss.str();

    ac::CrashArtifact a;
    std::string err;
    if (!ac::from_json_str(js, a, err)) {
        std::fprintf(stderr, "parse: %s\n", err.c_str()); return 1;
    }
    if (!a.analysis || !a.verdict) {
        std::fprintf(stderr,
            "artifact needs BOTH analysis and verdict blocks; "
            "run p05_analyze and p06_classify first.\n");
        return 1;
    }

    if (dry_run == send) {
        std::fprintf(stderr,"choose --dry-run for local prompt review or --send to transmit the full artifact JSON\n");
        return 2;
    }

    std::string prompt = build_prompt(js);

    if (dry_run) {
        std::printf("--- prompt (%zu bytes) ---\n%s\n", prompt.size(), prompt.c_str());
        return 0;
    }

    std::fprintf(stderr,"Sending the full crash artifact JSON to api.anthropic.com.\n");

    const std::string api_key = read_env("ANTHROPIC_API_KEY");
    if (api_key.empty()) {
        std::fprintf(stderr, "ANTHROPIC_API_KEY not set. Use --dry-run to skip the "
                             "network call.\n");
        return 1;
    }
    const std::string model = read_env("ANTHROPIC_MODEL", "claude-sonnet-5");

    json req = {
        {"model", model},
        {"max_tokens", 2048},
        {"messages", json::array({
            json{{"role", "user"}, {"content", prompt}}
        })}
    };
    std::string body = req.dump();

    auto hr = post_anthropic(api_key, "api.anthropic.com", "/v1/messages", body);
    if (!hr.ok)          { std::fprintf(stderr, "http error: %s\n", hr.error.c_str()); return 1; }
    if (hr.status != 200) {
        std::fprintf(stderr, "HTTP %u\n%s\n", hr.status, hr.body.c_str());
        return 1;
    }

    // Extract the text content from the response.
    std::string writeup;
    try {
        auto resp = json::parse(hr.body);
        if (resp.contains("content") && resp["content"].is_array()) {
            for (const auto& block : resp["content"]) {
                if (block.value("type", "") == "text")
                    writeup += block.value("text", "");
            }
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "response parse: %s\n", e.what());
        std::fprintf(stderr, "raw:\n%s\n", hr.body.c_str());
        return 1;
    }
    if (writeup.empty()) {
        std::fprintf(stderr, "no text content in response\n%s\n", hr.body.c_str());
        return 1;
    }

    if (out_path.empty()) {
        out_path = in_path;
        out_path.replace_extension(".writeup.md");
    }
    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) { std::fprintf(stderr, "cannot write %s\n", out_path.string().c_str()); return 1; }
    out.write(writeup.data(), static_cast<std::streamsize>(writeup.size()));
    std::printf("writeup: %s (%zu bytes)\n", out_path.string().c_str(), writeup.size());
    return 0;
}
