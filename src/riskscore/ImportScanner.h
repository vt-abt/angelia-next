#pragma once

// Walks the IMAGE_DIRECTORY_ENTRY_IMPORT table of a PE and returns the
// (DLL, function) pairs it references by name. Ordinal-only imports are
// captured as {dll, "#<ordinal>"}. Bounded by max_entries to keep the
// scanner from spiraling on a hostile file that lies about counts.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace angelia::riskscore {

class PeImage;

struct ImportEntry {
    std::string dll;
    std::string function;      // "#42" when the import was by ordinal
    bool        by_ordinal = false;
};

std::vector<ImportEntry> scan_imports(const PeImage& pe,
                                      std::size_t max_entries = 65536);

}  // namespace angelia::riskscore
