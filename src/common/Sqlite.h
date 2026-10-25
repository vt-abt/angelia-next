#pragma once

// Thin RAII shell over sqlite3. Keeps error handling explicit — every
// method that can fail returns a result, no exceptions across the writer
// thread hot path.

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

struct sqlite3;
struct sqlite3_stmt;

namespace angelia::common {

class Database;

class Statement {
public:
    Statement() = default;
    ~Statement();
    Statement(Statement&&) noexcept;
    Statement& operator=(Statement&&) noexcept;
    Statement(const Statement&)            = delete;
    Statement& operator=(const Statement&) = delete;

    void bind_int64(int idx, int64_t v);
    void bind_int   (int idx, int32_t v);
    void bind_text  (int idx, std::string_view v);
    void bind_blob  (int idx, const void* p, size_t n);
    void bind_null  (int idx);

    // step() returns true if a row is available (SQLITE_ROW), false when
    // done (SQLITE_DONE). Any other rc throws std::runtime_error.
    bool step();
    void reset();

    sqlite3_stmt* raw() noexcept { return stmt_; }

private:
    friend class Database;
    Statement(Database* db, sqlite3_stmt* s) : db_(db), stmt_(s) {}
    Database*     db_   = nullptr;
    sqlite3_stmt* stmt_ = nullptr;
};

class Database {
public:
    Database() = default;
    ~Database();
    Database(Database&&) noexcept;
    Database& operator=(Database&&) noexcept;
    Database(const Database&)            = delete;
    Database& operator=(const Database&) = delete;

    void open(const std::filesystem::path& path);
    void close() noexcept;

    // exec()/prepare() throw std::runtime_error on failure with a message
    // that includes sqlite3_errmsg.
    void      exec(std::string_view sql);
    Statement prepare(std::string_view sql);

    sqlite3* raw() noexcept { return db_; }

private:
    sqlite3* db_ = nullptr;
};

// Applies our standard write-ingest pragmas: WAL, synchronous=NORMAL,
// temp_store=MEMORY, mmap_size 256 MiB, busy_timeout 5 s.
void configure_for_ingest(Database& db);

}  // namespace angelia::common
