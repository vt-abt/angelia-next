#include "memforensics/KernelStructureCache.h"

#include <windows.h>
#include <shlobj.h>

#include <nlohmann/json.hpp>

#include <fstream>
#include <sstream>

#pragma comment(lib, "shell32.lib")

using json = nlohmann::json;

namespace angelia::memforensics {

namespace {

std::filesystem::path default_path() {
    PWSTR w = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &w)) && w) {
        std::filesystem::path p = w;
        CoTaskMemFree(w);
        return p / "angelia" / "pdb_offsets.json";
    }
    return std::filesystem::current_path() / "pdb_offsets.json";
}

}  // namespace

KernelStructureCache::KernelStructureCache()
    : KernelStructureCache(default_path()) {}

KernelStructureCache::KernelStructureCache(std::filesystem::path path)
    : path_(std::move(path)) {
    load();
}

void KernelStructureCache::load() {
    std::ifstream f(path_);
    if (!f) return;
    try {
        json j; f >> j;
        if (!j.is_object()) return;
        for (auto it = j.begin(); it != j.end(); ++it) {
            if (!it.value().is_object()) continue;
            for (auto vit = it.value().begin(); vit != it.value().end(); ++vit) {
                if (vit.value().is_number_unsigned() || vit.value().is_number_integer())
                    map_[it.key()][vit.key()] = vit.value().get<uint32_t>();
            }
        }
    } catch (...) {
        // Corrupt cache is not fatal — proceed as if empty. Next put()+save()
        // rewrites the file cleanly.
        map_.clear();
    }
}

void KernelStructureCache::save() {
    if (!dirty_) return;
    std::error_code ec;
    std::filesystem::create_directories(path_.parent_path(), ec);
    json j;
    for (const auto& [k, m] : map_) {
        json inner;
        for (const auto& [field, off] : m) inner[field] = off;
        j[k] = inner;
    }
    std::ofstream f(path_, std::ios::binary | std::ios::trunc);
    if (!f) return;
    f << j.dump(2);
    dirty_ = false;
}

std::optional<uint32_t> KernelStructureCache::get(std::string_view build_key,
                                                  std::string_view field) const {
    auto it = map_.find(std::string(build_key));
    if (it == map_.end()) return std::nullopt;
    auto jt = it->second.find(std::string(field));
    if (jt == it->second.end()) return std::nullopt;
    return jt->second;
}

void KernelStructureCache::put(std::string_view build_key,
                                std::string_view field, uint32_t offset) {
    map_[std::string(build_key)][std::string(field)] = offset;
    dirty_ = true;
}

std::optional<EprocessOffsets> KernelStructureCache::get_eprocess(std::string_view k) const {
    EprocessOffsets o;
    auto apl = get(k, "_EPROCESS.ActiveProcessLinks");
    auto upi = get(k, "_EPROCESS.UniqueProcessId");
    auto ifn = get(k, "_EPROCESS.ImageFileName");
    if (!apl || !upi || !ifn) return std::nullopt;
    o.active_process_links = *apl;
    o.unique_process_id    = *upi;
    o.image_file_name      = *ifn;
    o.inherited_from       = get(k, "_EPROCESS.InheritedFromUniqueProcessId").value_or(0);
    o.resolved             = true;
    return o;
}

void KernelStructureCache::put_eprocess(std::string_view k, const EprocessOffsets& o) {
    put(k, "_EPROCESS.ActiveProcessLinks", o.active_process_links);
    put(k, "_EPROCESS.UniqueProcessId",    o.unique_process_id);
    put(k, "_EPROCESS.ImageFileName",      o.image_file_name);
    if (o.inherited_from)
        put(k, "_EPROCESS.InheritedFromUniqueProcessId", o.inherited_from);
}

}  // namespace angelia::memforensics
