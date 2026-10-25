#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>

#include "memforensics/DumpIdentify.h"

using namespace angelia::memforensics;

namespace {

std::filesystem::path tmp_file(const char* name) {
    return std::filesystem::temp_directory_path() / name;
}

void write_bytes(const std::filesystem::path& p, const void* data, std::size_t n) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(n));
}

TEST(DumpIdentify, HeaderBearing64) {
    const auto p = tmp_file("angelia_dump_pageu64.bin");
    const std::string hdr = std::string("PAGEDU64") + std::string(512, '\0');
    write_bytes(p, hdr.data(), hdr.size());
    auto info = identify(p);
    EXPECT_EQ(info.kind, DumpKind::HeaderBearing64);
    EXPECT_TRUE(info.is_header_bearing());
    std::filesystem::remove(p);
}

TEST(DumpIdentify, HeaderBearing32) {
    const auto p = tmp_file("angelia_dump_pageump.bin");
    const std::string hdr = std::string("PAGEDUMP") + std::string(512, '\0');
    write_bytes(p, hdr.data(), hdr.size());
    auto info = identify(p);
    EXPECT_EQ(info.kind, DumpKind::HeaderBearing32);
    std::filesystem::remove(p);
}

TEST(DumpIdentify, RejectsRawPhysical) {
    const auto p = tmp_file("angelia_raw_phys.bin");
    // Something that plausibly is raw memory: nonzero non-magic prefix.
    const std::string body(64, '\xcc');
    write_bytes(p, body.data(), body.size());
    auto info = identify(p);
    EXPECT_EQ(info.kind, DumpKind::Unknown);
    EXPECT_FALSE(info.is_header_bearing());
    EXPECT_NE(info.rejection_reason.find("PAGEDU64"), std::string::npos);
    std::filesystem::remove(p);
}

TEST(DumpIdentify, RejectsTruncated) {
    const auto p = tmp_file("angelia_trunc.bin");
    const char bytes[3] = {'P','A','G'};
    write_bytes(p, bytes, sizeof(bytes));
    auto info = identify(p);
    EXPECT_EQ(info.kind, DumpKind::Truncated);
    std::filesystem::remove(p);
}

TEST(DumpIdentify, RejectsMissingFile) {
    auto info = identify(tmp_file("angelia_definitely_does_not_exist_12345.bin"));
    EXPECT_EQ(info.kind, DumpKind::Unknown);
    EXPECT_FALSE(info.rejection_reason.empty());
}

}  // namespace
