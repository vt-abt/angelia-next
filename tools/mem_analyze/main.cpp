// mem_analyze — Stage 2's headline tool.
//
// Given a PAGEDU64 dump, resolves _EPROCESS offsets from a matching
// kernel PDB (via PdbTypeResolver + KernelStructureCache), walks the
// ActiveProcessLinks list through the dump's page tables, and (if a
// live snapshot is supplied) cross-references to produce a structured
// process inventory with cross-time differences marked for review.
//
//   mem_analyze --dump <PAGEDU64>
//               [--kernel-image C:\Windows\System32\ntoskrnl.exe]
//               [--sym "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"]
//               [--snapshot snapshot.json]
//               [--cache pdb_offsets.json]
//               [--out inventory.json]
//               [--offsets-json '{"apl":472,"upi":1088,"ifn":1512}']  (skip PDB resolution)

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include <fmt/format.h>

#include "memforensics/ActiveProcessWalker.h"
#include "memforensics/KernelStructureCache.h"
#include "memforensics/LiveProcessSnapshot.h"
#include "memforensics/PageTableWalker.h"
#include "memforensics/PdbTypeResolver.h"
#include "memforensics/PhysicalMemoryReader.h"
#include "memforensics/ProcessInventory.h"

using namespace angelia::memforensics;
using json = nlohmann::json;

namespace {

struct Args {
    std::filesystem::path dump;
    std::filesystem::path kernel_image = "C:\\Windows\\System32\\ntoskrnl.exe";
    std::string           sym_path;
    std::filesystem::path snapshot;
    std::optional<std::filesystem::path> cache;
    std::filesystem::path out;
    std::string           offsets_json;
};

Args parse(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string_view k = argv[i];
        auto need = [&]() -> std::string {
            if (i + 1 >= argc) { std::fprintf(stderr, "missing value for %.*s\n",
                                              (int)k.size(), k.data()); std::exit(2); }
            return argv[++i];
        };
        if      (k == "--dump")          a.dump         = need();
        else if (k == "--kernel-image")  a.kernel_image = need();
        else if (k == "--sym")           a.sym_path     = need();
        else if (k == "--snapshot")      a.snapshot     = need();
        else if (k == "--cache")         a.cache        = std::filesystem::path{need()};
        else if (k == "--out")           a.out          = need();
        else if (k == "--offsets-json")  a.offsets_json = need();
        else if (k == "-h" || k == "--help") {
            std::printf("usage: mem_analyze --dump <PAGEDU64> "
                        "[--kernel-image PATH] [--sym SRV] [--snapshot PATH] "
                        "[--cache PATH] [--out PATH] [--offsets-json JSON]\n");
            std::exit(0);
        }
        else { std::fprintf(stderr, "unknown arg: %.*s\n", (int)k.size(), k.data()); std::exit(2); }
    }
    if (a.dump.empty()) { std::fprintf(stderr, "--dump is required\n"); std::exit(2); }
    return a;
}

std::optional<EprocessOffsets> resolve_offsets(const Args& a) {
    // Explicit CLI override — skip PDB entirely.
    if (!a.offsets_json.empty()) {
        try {
            auto j = json::parse(a.offsets_json);
            EprocessOffsets o;
            o.active_process_links = j.value("apl", uint32_t{0});
            o.unique_process_id    = j.value("upi", uint32_t{0});
            o.image_file_name      = j.value("ifn", uint32_t{0});
            o.inherited_from       = j.value("pif", uint32_t{0});
            o.resolved = (o.active_process_links && o.unique_process_id && o.image_file_name);
            if (o.resolved) return o;
            std::fprintf(stderr, "--offsets-json missing apl/upi/ifn\n");
        } catch (const std::exception& e) {
            std::fprintf(stderr, "--offsets-json parse: %s\n", e.what());
        }
        return std::nullopt;
    }

    PdbTypeResolver res;
    auto load = res.load_for_image(a.kernel_image, a.sym_path);
    if (!load.ok) {
        std::fprintf(stderr, "PDB load: %s\n", load.error.c_str());
        return std::nullopt;
    }
    const std::string build_key = load.pdb_guid + "+" + std::to_string(load.pdb_age);
    KernelStructureCache cache = a.cache
        ? KernelStructureCache(*a.cache)
        : KernelStructureCache();

    if (auto cached = cache.get_eprocess(build_key)) {
        std::fprintf(stderr, "offsets: cache hit for %s\n", build_key.c_str());
        return cached;
    }
    EprocessOffsets o;
    auto apl = res.member_offset(L"_EPROCESS", L"ActiveProcessLinks");
    auto upi = res.member_offset(L"_EPROCESS", L"UniqueProcessId");
    auto ifn = res.member_offset(L"_EPROCESS", L"ImageFileName");
    auto pif = res.member_offset(L"_EPROCESS", L"InheritedFromUniqueProcessId");
    if (!apl || !upi || !ifn) {
        std::fprintf(stderr, "PDB missing one or more _EPROCESS offsets "
                             "(apl=%d upi=%d ifn=%d)\n",
                     apl ? int(*apl) : -1, upi ? int(*upi) : -1, ifn ? int(*ifn) : -1);
        return std::nullopt;
    }
    o.active_process_links = *apl;
    o.unique_process_id    = *upi;
    o.image_file_name      = *ifn;
    o.inherited_from       = pif.value_or(0);
    o.resolved             = true;
    cache.put_eprocess(build_key, o);
    cache.save();
    std::fprintf(stderr, "offsets: resolved from %s and cached under %s\n",
                 load.resolved_pdb.c_str(), build_key.c_str());
    return o;
}

}  // namespace

int angelia_cli_run_mem_analyze(int argc, char** argv) {
    Args a = parse(argc, argv);

    PhysicalMemoryReader phys;
    if (!phys.open(a.dump)) {
        std::fprintf(stderr, "dump: %s\n", phys.last_error().c_str());
        return 1;
    }
    std::fprintf(stderr, "dump: DTB=0x%llx PsActiveProcessHead=0x%llx runs=%zu\n",
                 (unsigned long long)phys.header().directory_table_base,
                 (unsigned long long)phys.header().ps_active_process_head,
                 phys.runs().size());

    auto offsets = resolve_offsets(a);
    if (!offsets) return 1;
    std::fprintf(stderr, "_EPROCESS: ActiveProcessLinks=+0x%x UniqueProcessId=+0x%x "
                         "ImageFileName=+0x%x\n",
                 offsets->active_process_links, offsets->unique_process_id,
                 offsets->image_file_name);

    PageTableWalker pw(phys, phys.header().directory_table_base);
    auto walk = walk_active_process_list(pw, phys.header().ps_active_process_head, *offsets);
    if (!walk.ok) {
        std::fprintf(stderr, "walk: %s\n", walk.error.c_str());
        return 1;
    }
    if (!walk.error.empty())
        std::fprintf(stderr, "walk (partial): %s\n", walk.error.c_str());
    std::fprintf(stderr, "walk: %zu processes across %zu iterations\n",
                 walk.processes.size(), walk.iterations);

    LiveSnapshot live;
    bool have_live = false;
    if (!a.snapshot.empty()) {
        std::string err;
        if (!load_snapshot(a.snapshot, live, err)) {
            std::fprintf(stderr, "snapshot: %s\n", err.c_str());
            return 1;
        } else {
            have_live = true;
            std::fprintf(stderr, "snapshot: loaded %zu processes captured %s\n",
                         live.processes.size(), live.captured_iso8601_utc.c_str());
        }
    }

    auto inv = build_inventory(walk.processes, have_live ? &live : nullptr);
    auto result=json::parse(to_json(inv));
    result["dump_path"]=std::filesystem::absolute(a.dump).string();
    result["dump_format"]="PAGEDU64";
    result["dump_type"]=phys.header().dump_type;
    result["dump_time_100ns"]=phys.header().system_time_100ns;
    result["snapshot_time_utc"]=have_live ? live.captured_iso8601_utc : "";
    result["walk_complete"]=walk.error.empty();
    result["walk_warning"]=walk.error;
    result["validated_against_reference"]=false;
    auto js=result.dump(2);

    if (a.out.empty()) {
        std::fwrite(js.data(), 1, js.size(), stdout);
        std::printf("\n");
    } else {
        std::ofstream f(a.out, std::ios::binary | std::ios::trunc);
        f.write(js.data(), static_cast<std::streamsize>(js.size()));
        std::fprintf(stderr, "inventory: %s (%zu entries, %zu dump-only review items)\n",
                     a.out.string().c_str(), inv.entries.size(), inv.raw_only_count());
    }
    return 0;
}
