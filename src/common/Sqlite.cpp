#include "common/Sqlite.h"

#include <sqlite3.h>

#include <fmt/format.h>

#include <stdexcept>
#include <utility>

namespace angelia::common {

namespace {
[[noreturn]] void raise(sqlite3* db, std::string_view what) {
    throw std::runtime_error(
        fmt::format("sqlite: {} ({})", what, db ? sqlite3_errmsg(db) : "no db"));
}
}  // namespace

Statement::~Statement() {
    if (stmt_) sqlite3_finalize(stmt_);
}

Statement::Statement(Statement&& other) noexcept
    : db_(other.db_), stmt_(other.stmt_) {
    other.db_ = nullptr;
    other.stmt_ = nullptr;
}

Statement& Statement::operator=(Statement&& other) noexcept {
    if (this != &other) {
        if (stmt_) sqlite3_finalize(stmt_);
        db_        = other.db_;
        stmt_      = other.stmt_;
        other.db_  = nullptr;
        other.stmt_ = nullptr;
    }
    return *this;
}

void Statement::bind_int64(int idx, int64_t v) {
    if (sqlite3_bind_int64(stmt_, idx, v) != SQLITE_OK) raise(db_->raw(), "bind_int64");
}
void Statement::bind_int(int idx, int32_t v) {
    if (sqlite3_bind_int(stmt_, idx, v) != SQLITE_OK) raise(db_->raw(), "bind_int");
}
void Statement::bind_text(int idx, std::string_view v) {
    if (sqlite3_bind_text(stmt_, idx, v.data(), static_cast<int>(v.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK) raise(db_->raw(), "bind_text");
}
void Statement::bind_blob(int idx, const void* p, size_t n) {
    if (sqlite3_bind_blob(stmt_, idx, p, static_cast<int>(n), SQLITE_TRANSIENT) != SQLITE_OK)
        raise(db_->raw(), "bind_blob");
}
void Statement::bind_null(int idx) {
    if (sqlite3_bind_null(stmt_, idx) != SQLITE_OK) raise(db_->raw(), "bind_null");
}

bool Statement::step() {
    const int rc = sqlite3_step(stmt_);
    if (rc == SQLITE_ROW)  return true;
    if (rc == SQLITE_DONE) return false;
    raise(db_->raw(), "step");
}

void Statement::reset() {
    if (sqlite3_reset(stmt_) != SQLITE_OK) raise(db_->raw(), "reset");
    sqlite3_clear_bindings(stmt_);
}

Database::~Database() { close(); }

Database::Database(Database&& other) noexcept : db_(other.db_) { other.db_ = nullptr; }
Database& Database::operator=(Database&& other) noexcept {
    if (this != &other) {
        close();
        db_       = other.db_;
        other.db_ = nullptr;
    }
    return *this;
}

void Database::open(const std::filesystem::path& path) {
    close();
    const auto s = path.u8string();
    if (sqlite3_open_v2(reinterpret_cast<const char*>(s.c_str()), &db_,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX,
                        nullptr) != SQLITE_OK) {
        raise(db_, "open");
    }
}

void Database::close() noexcept {
    if (db_) {
        sqlite3_close_v2(db_);
        db_ = nullptr;
    }
}

void Database::exec(std::string_view sql) {
    char* err = nullptr;
    std::string s{sql};
    if (sqlite3_exec(db_, s.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "exec";
        sqlite3_free(err);
        throw std::runtime_error(fmt::format("sqlite: exec failed: {}", msg));
    }
}

Statement Database::prepare(std::string_view sql) {
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v3(db_, sql.data(), static_cast<int>(sql.size()),
                           SQLITE_PREPARE_PERSISTENT, &raw, nullptr) != SQLITE_OK) {
        raise(db_, "prepare");
    }
    return Statement{this, raw};
}

void configure_for_ingest(Database& db) {
    db.exec("PRAGMA journal_mode=WAL;");
    db.exec("PRAGMA synchronous=NORMAL;");
    db.exec("PRAGMA temp_store=MEMORY;");
    db.exec("PRAGMA mmap_size=268435456;");   // 256 MiB
    db.exec("PRAGMA busy_timeout=5000;");
    db.exec("PRAGMA wal_autocheckpoint=2000;");
}

}  // namespace angelia::common
