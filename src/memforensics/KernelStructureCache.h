#pragma once

// Per-kernel-build cache of struct-member offsets. Resolving offsets
// via DIA/dbghelp is slow (symsrv HTTP round trip + PDB parse); doing
// it once per (pdb-guid, pdb-age) pair and persisting to a JSON file
// keeps subsequent runs fast.
//
// Cache lives under %LOCALAPPDATA%\angelia\pdb_offsets.json on Windows,
// or an explicit path via --cache. The file format is:
//   { "<GUID>+<age>": { "_EPROCESS.ActiveProcessLinks": 472, ... }, ... }

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace angelia::memforensics {

struct EprocessOffsets {
    uint32_t active_process_links = 0;
    uint32_t unique_process_id    = 0;
    uint32_t image_file_name      = 0;
    uint32_t inherited_from       = 0;    // parent pid; optional (may be 0)
    // Track whether resolve() has populated us.
    bool     resolved             = false;
};

class KernelStructureCache {
public:
    // Path defaults to %LOCALAPPDATA%\angelia\pdb_offsets.json.
    KernelStructureCache();
    explicit KernelStructureCache(std::filesystem::path path);

    // Cache key = "<GUID>+<age>" (guid in canonical uppercase form).
    std::optional<uint32_t> get(std::string_view build_key,
                                std::string_view field_dotted) const;
    void put(std::string_view build_key,
             std::string_view field_dotted, uint32_t offset);

    // Full-struct helpers for the specific type Stage 2 needs.
    std::optional<EprocessOffsets> get_eprocess(std::string_view build_key) const;
    void put_eprocess(std::string_view build_key, const EprocessOffsets& o);

    // Read/write the on-disk JSON. load() is called by the constructor;
    // save() must be called explicitly (typically once after a batch of
    // put()s completes).
    void load();
    void save();

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
    std::unordered_map<std::string,
        std::unordered_map<std::string, uint32_t>> map_;
    bool dirty_ = false;
};

}  // namespace angelia::memforensics
