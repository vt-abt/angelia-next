#pragma once

// P0.3 — DIA-backed PDB type resolver.
//
// Loads a matched PDB (or a PDB you hand in explicitly), then reads
// resolved struct-member offsets by name. The plan requires proving
// both success on a matched PDB and clean rejection on a mismatched
// PDB — this interface makes that distinction explicit: use
// load_for_image() for the matched path (DIA verifies GUID+age) and
// load_pdb() for a direct load with no cross-check.
//
// Nothing DIA-specific leaks through this header; the implementation
// hides IDiaDataSource / IDiaSession behind Impl.

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

namespace angelia::memforensics {

struct PdbLoadResult {
    bool        ok = false;
    std::string error;            // populated when ok == false
    std::string resolved_pdb;     // the PDB path DIA actually opened
    std::string pdb_guid;         // canonical GUID (upper hex, dashes)
    uint32_t    pdb_age = 0;
};

class PdbTypeResolver {
public:
    PdbTypeResolver();
    ~PdbTypeResolver();

    PdbTypeResolver(const PdbTypeResolver&)            = delete;
    PdbTypeResolver& operator=(const PdbTypeResolver&) = delete;

    // Load the PDB matching `image` from `sym_path`. `sym_path` follows
    // the standard DIA / dbghelp syntax, e.g.:
    //     srv*C:\symbols*https://msdl.microsoft.com/download/symbols
    // Returns ok=false with a human-readable `error` on any failure —
    // including GUID/age mismatch, in which case the message names both
    // the image and the rejected PDB. This is the path the P0.3
    // "matched vs mismatched" test drives.
    PdbLoadResult load_for_image(const std::filesystem::path& image,
                                 const std::string& sym_path);

    // Load a PDB directly. Skips image cross-check by construction.
    PdbLoadResult load_pdb(const std::filesystem::path& pdb);

    // Resolve a data-member offset within a UDT (e.g. udt="_EPROCESS",
    // member="ActiveProcessLinks"). Returns nullopt when the UDT is
    // absent, when the member is absent, or when the type isn't a
    // struct/union.
    std::optional<uint32_t> member_offset(const std::wstring& udt,
                                          const std::wstring& member);

    // True once a PDB is loaded.
    bool is_loaded() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace angelia::memforensics
