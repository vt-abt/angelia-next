// Evidence-backed Windows investigation cases. Raw inputs are copied into
// sources/ and identified by SHA-256; normalized rows retain source row IDs.
#include <windows.h>
#include <winevt.h>
#include <bcrypt.h>
#include <sqlite3.h>
#include <pugixml.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "collector/EventRecord.h"
#include "angelia/subcommands.h"
#include "crashtriage/CrashArtifact.h"
#include "memforensics/LiveProcessSnapshot.h"
#include "riskscore/StaticScorer.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

[[noreturn]] void fail(const std::string& s) { throw std::runtime_error(s); }

struct Db {
    sqlite3* h = nullptr;
    explicit Db(const fs::path& path, int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE) {
        const auto u = path.u8string();
        if (sqlite3_open_v2(reinterpret_cast<const char*>(u.c_str()), &h, flags, nullptr) != SQLITE_OK) {
            const std::string e = h ? sqlite3_errmsg(h) : "open failed";
            if (h) sqlite3_close(h);
            h = nullptr;
            fail(path.string() + ": " + e);
        }
        sqlite3_busy_timeout(h, 5000);
    }
    ~Db() { if (h) sqlite3_close(h); }
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;
    void exec(const char* sql) {
        char* error = nullptr;
        if (sqlite3_exec(h, sql, nullptr, nullptr, &error) != SQLITE_OK) {
            std::string e = error ? error : sqlite3_errmsg(h);
            sqlite3_free(error);
            fail("SQLite: " + e);
        }
    }
};

struct Stmt {
    sqlite3* db;
    sqlite3_stmt* h = nullptr;
    Stmt(Db& d, const char* sql) : db(d.h) {
        if (sqlite3_prepare_v2(db, sql, -1, &h, nullptr) != SQLITE_OK)
            fail(std::string("SQLite prepare: ") + sqlite3_errmsg(db));
    }
    ~Stmt() { sqlite3_finalize(h); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;
    void text(int i, const std::string& v) { sqlite3_bind_text(h, i, v.c_str(), -1, SQLITE_TRANSIENT); }
    void number(int i, int64_t v) { sqlite3_bind_int64(h, i, v); }
    void reset() { sqlite3_reset(h); sqlite3_clear_bindings(h); }
    bool row() {
        const int rc = sqlite3_step(h);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        fail(std::string("SQLite step: ") + sqlite3_errmsg(db));
    }
    void done() { if (row()) fail("unexpected SQLite result row"); reset(); }
    std::string str(int i) const {
        const auto* p = sqlite3_column_text(h, i);
        return p ? reinterpret_cast<const char*>(p) : "";
    }
    int64_t integer(int i) const { return sqlite3_column_int64(h, i); }
};

std::string utf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) fail("UTF-16 conversion failed");
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::string sha256(const fs::path& path) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        fail("cannot open SHA-256 provider");
    auto close = [&] { if (hash) BCryptDestroyHash(hash); if (alg) BCryptCloseAlgorithmProvider(alg, 0); };
    try {
        DWORD object_len = 0, size = 0;
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_len), sizeof(object_len), &size, 0) < 0)
            fail("cannot query SHA-256 object size");
        std::vector<UCHAR> object(object_len);
        if (BCryptCreateHash(alg, &hash, object.data(), object_len, nullptr, 0, 0) < 0)
            fail("cannot create SHA-256 hash");
        std::ifstream f(path, std::ios::binary);
        if (!f) fail("cannot read " + path.string());
        std::array<char, 65536> buf{};
        while (f.read(buf.data(), buf.size()) || f.gcount()) {
            if (BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf.data()),
                               static_cast<ULONG>(f.gcount()), 0) < 0) fail("SHA-256 update failed");
        }
        if (f.bad()) fail("read failed: " + path.string());
        std::array<UCHAR, 32> digest{};
        if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
            fail("SHA-256 finish failed");
        std::ostringstream out;
        for (auto b : digest) out << std::hex << std::setfill('0') << std::setw(2) << unsigned(b);
        close();
        return out.str();
    } catch (...) { close(); throw; }
}

constexpr const char* kSchema = R"SQL(
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS sources (
 id INTEGER PRIMARY KEY, type TEXT NOT NULL, original_path TEXT NOT NULL,
 stored_path TEXT NOT NULL, sha256 TEXT NOT NULL, imported_utc TEXT NOT NULL,
 record_count INTEGER NOT NULL DEFAULT 0, notes TEXT NOT NULL DEFAULT '',
 UNIQUE(type,sha256));
CREATE TABLE IF NOT EXISTS processes (
 process_key TEXT PRIMARY KEY, pid INTEGER NOT NULL, guid TEXT NOT NULL DEFAULT '',
 start_100ns INTEGER NOT NULL, end_100ns INTEGER,
 parent_key TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '',
 command_line TEXT NOT NULL DEFAULT '', hashes TEXT NOT NULL DEFAULT '', source_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL REFERENCES sources(id),
 source_record TEXT NOT NULL, timestamp_100ns INTEGER NOT NULL, pid INTEGER NOT NULL,
 kind TEXT NOT NULL, provider TEXT NOT NULL DEFAULT '', event_id INTEGER NOT NULL DEFAULT 0,
 name TEXT NOT NULL DEFAULT '', process_guid TEXT NOT NULL DEFAULT '',
 parent_guid TEXT NOT NULL DEFAULT '', parent_pid INTEGER NOT NULL DEFAULT 0,
 process_key TEXT NOT NULL DEFAULT '', parent_key TEXT NOT NULL DEFAULT '',
 command_line TEXT NOT NULL DEFAULT '', hashes TEXT NOT NULL DEFAULT '',
 src_ip TEXT NOT NULL DEFAULT '', dst_ip TEXT NOT NULL DEFAULT '',
 src_port INTEGER NOT NULL DEFAULT 0, dst_port INTEGER NOT NULL DEFAULT 0,
 protocol TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '', raw_xml TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_case_events_time ON events(timestamp_100ns);
CREATE INDEX IF NOT EXISTS ix_case_events_pid_time ON events(pid,timestamp_100ns);
CREATE INDEX IF NOT EXISTS ix_case_events_key_time ON events(process_key,timestamp_100ns);
CREATE INDEX IF NOT EXISTS ix_case_events_network ON events(kind,src_ip,dst_ip,src_port,dst_port,protocol,timestamp_100ns);
CREATE TABLE IF NOT EXISTS packets (
 id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL REFERENCES sources(id),
 packet_no INTEGER NOT NULL, timestamp_100ns INTEGER NOT NULL,
 src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, src_port INTEGER NOT NULL,
 dst_port INTEGER NOT NULL, protocol TEXT NOT NULL, length INTEGER NOT NULL,
 link_event_id INTEGER, process_key TEXT NOT NULL DEFAULT '',
 link_status TEXT NOT NULL DEFAULT 'unlinked');
CREATE INDEX IF NOT EXISTS ix_case_packets_time ON packets(timestamp_100ns);
CREATE TABLE IF NOT EXISTS findings (
 id INTEGER PRIMARY KEY, origin TEXT NOT NULL, rule_id TEXT NOT NULL,
 subject TEXT NOT NULL, severity TEXT NOT NULL, rationale TEXT NOT NULL,
 limitations TEXT NOT NULL, evidence_json TEXT NOT NULL,
 created_utc TEXT NOT NULL, UNIQUE(origin,rule_id,subject));
CREATE INDEX IF NOT EXISTS ix_case_findings_subject ON findings(subject);
CREATE TABLE IF NOT EXISTS crash_runs (
 id INTEGER PRIMARY KEY, series_key TEXT NOT NULL, run_index INTEGER NOT NULL,
 capture_source_id INTEGER NOT NULL REFERENCES sources(id),
 artifact_source_id INTEGER NOT NULL REFERENCES sources(id),
 dump_source_id INTEGER REFERENCES sources(id),
 binary_source_id INTEGER NOT NULL REFERENCES sources(id),
 input_source_id INTEGER NOT NULL REFERENCES sources(id),
 capture_utc TEXT NOT NULL, exception_code TEXT NOT NULL,
 bucket TEXT NOT NULL, confidence REAL NOT NULL, artifact_json TEXT NOT NULL,
 UNIQUE(series_key,run_index));
CREATE INDEX IF NOT EXISTS ix_case_crash_series ON crash_runs(series_key);
)SQL";

fs::path case_db(const fs::path& dir) { return dir / "case.db"; }
void require_case(const fs::path& dir) {
    if (!fs::is_regular_file(case_db(dir))) fail("case not initialized: " + dir.string());
}
std::string utc_now() {
    SYSTEMTIME st{}; GetSystemTime(&st);
    char s[32]; std::snprintf(s, sizeof(s), "%04u-%02u-%02uT%02u:%02u:%02uZ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return s;
}
std::string lower(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    return s;
}
int64_t parse_utc(std::string_view s) {
    int y=0,mo=0,d=0,h=0,mi=0,se=0;
    if (std::sscanf(std::string(s).c_str(), "%d-%d-%dT%d:%d:%d", &y,&mo,&d,&h,&mi,&se) != 6)
        fail("invalid UTC timestamp: " + std::string(s));
    SYSTEMTIME st{};
    st.wYear=static_cast<WORD>(y); st.wMonth=static_cast<WORD>(mo);
    st.wDay=static_cast<WORD>(d); st.wHour=static_cast<WORD>(h);
    st.wMinute=static_cast<WORD>(mi); st.wSecond=static_cast<WORD>(se);
    FILETIME ft{};
    if (!SystemTimeToFileTime(&st, &ft)) fail("invalid UTC timestamp: " + std::string(s));
    ULARGE_INTEGER u{}; u.LowPart=ft.dwLowDateTime; u.HighPart=ft.dwHighDateTime;
    const size_t dot = s.find('.');
    if (dot != std::string_view::npos) {
        uint64_t frac=0; int digits=0;
        for (size_t i=dot+1; i<s.size() && s[i]>='0' && s[i]<='9' && digits<7; ++i,++digits)
            frac=frac*10+uint64_t(s[i]-'0');
        while (digits++ < 7) frac*=10;
        u.QuadPart += frac;
    }
    return static_cast<int64_t>(u.QuadPart);
}

struct Source { int64_t id; fs::path stored; bool fresh; };
Source register_source(Db& db, const fs::path& dir, const fs::path& input,
                       const std::string& type, bool snapshot_sqlite = false) {
    if (!fs::is_regular_file(input)) fail("source does not exist: " + input.string());
    fs::create_directories(dir / "sources");
    fs::path staged = dir / "sources" / ("incoming-" + std::to_string(GetCurrentProcessId()) + input.extension().string());
    if (snapshot_sqlite) {
        Db from(input, SQLITE_OPEN_READONLY);
        Db to(staged);
        sqlite3_backup* b = sqlite3_backup_init(to.h, "main", from.h, "main");
        if (!b) fail("cannot snapshot source database");
        const int rc = sqlite3_backup_step(b, -1);
        sqlite3_backup_finish(b);
        if (rc != SQLITE_DONE) fail("cannot finish source database snapshot");
    } else {
        fs::copy_file(input, staged, fs::copy_options::overwrite_existing);
    }
    const std::string hash = sha256(staged);
    fs::path stored = dir / "sources" / (hash + input.extension().string());
    if (fs::exists(stored)) fs::remove(staged);
    else fs::rename(staged, stored);
    Stmt existing(db, "SELECT id FROM sources WHERE type=? AND sha256=?");
    existing.text(1,type); existing.text(2,hash);
    if (existing.row()) return {existing.integer(0),stored,false};
    Stmt add(db, "INSERT INTO sources(type,original_path,stored_path,sha256,imported_utc) VALUES(?,?,?,?,?)");
    add.text(1,type); add.text(2,fs::absolute(input).string());
    add.text(3,fs::relative(stored,dir).generic_string()); add.text(4,hash); add.text(5,utc_now());
    add.done();
    return {sqlite3_last_insert_rowid(db.h),stored,true};
}

struct Event {
    int64_t source_id=0, ts=0, pid=0, event_id=0, parent_pid=0, src_port=0, dst_port=0;
    std::string source_record,kind,provider,name,guid,parent_guid,key,parent_key,cmd,hashes;
    std::string src_ip,dst_ip,protocol,details,raw_xml;
};

void insert_event(Stmt& st, const Event& e) {
    st.number(1,e.source_id); st.text(2,e.source_record); st.number(3,e.ts);
    st.number(4,e.pid); st.text(5,e.kind); st.text(6,e.provider);
    st.number(7,e.event_id); st.text(8,e.name); st.text(9,e.guid);
    st.text(10,e.parent_guid); st.number(11,e.parent_pid);
    st.text(12,e.key); st.text(13,e.parent_key); st.text(14,e.cmd);
    st.text(15,e.hashes); st.text(16,e.src_ip); st.text(17,e.dst_ip);
    st.number(18,e.src_port); st.number(19,e.dst_port); st.text(20,e.protocol);
    st.text(21,e.details); st.text(22,e.raw_xml); st.done();
}

constexpr const char* kInsertEvent =
    "INSERT INTO events(source_id,source_record,timestamp_100ns,pid,kind,provider,event_id,name,"
    "process_guid,parent_guid,parent_pid,process_key,parent_key,command_line,hashes,src_ip,dst_ip,"
    "src_port,dst_port,protocol,details,raw_xml) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

void upsert_process(Stmt& st, const Event& e) {
    if (e.key.empty()) return;
    st.text(1,e.key); st.number(2,e.pid); st.text(3,e.guid); st.number(4,e.ts);
    st.text(5,e.parent_key); st.text(6,e.name); st.text(7,e.cmd);
    st.text(8,e.hashes); st.number(9,e.source_id); st.done();
}
constexpr const char* kUpsertProcess =
    "INSERT INTO processes(process_key,pid,guid,start_100ns,parent_key,image,command_line,hashes,source_id) "
    "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(process_key) DO UPDATE SET "
    "image=excluded.image,command_line=excluded.command_line,hashes=excluded.hashes";

void finish_source(Db& db, int64_t id, int64_t count, const std::string& notes = {}) {
    Stmt s(db,"UPDATE sources SET record_count=?, notes=? WHERE id=?");
    s.number(1,count); s.text(2,notes); s.number(3,id); s.done();
}

std::string xml_value(pugi::xml_node node, const char* child) {
    return node.child(child).text().as_string();
}
std::string data_value(const std::map<std::string,std::string>& d, const char* name) {
    const auto it=d.find(name); return it==d.end() ? "" : it->second;
}
int64_t decimal(const std::string& s) {
    if (s.empty()) return 0;
    try { return std::stoll(s); } catch (...) { return 0; }
}
std::string sysmon_kind(int id) {
    switch (id) {
        case 1: return "ProcessStart";
        case 3: return "NetworkConnect";
        case 5: return "ProcessEnd";
        case 7: return "ImageLoad";
        case 11: return "FileCreate";
        case 12: return "RegistryKeyChange";
        case 13: return "RegistrySetValue";
        case 14: return "RegistryRename";
        case 22: return "DnsQuery";
        case 23: return "FileDelete";
        case 26: return "FileDelete";
        default: return "WindowsEvent";
    }
}

void consume_xml_event(pugi::xml_node root, int64_t source_id, int64_t ordinal,
                       Stmt& add, Stmt& process, Stmt& finish_process) {
    const auto sys = root.child("System");
    if (!sys) fail("event XML has no System section");
    Event e;
    e.source_id = source_id;
    e.event_id = decimal(xml_value(sys,"EventID"));
    e.source_record = xml_value(sys,"EventRecordID");
    if (e.source_record.empty()) e.source_record=std::to_string(ordinal);
    e.provider = sys.child("Provider").attribute("Name").as_string();
    const std::string when = sys.child("TimeCreated").attribute("SystemTime").as_string();
    if (when.empty()) fail("event XML has no TimeCreated/SystemTime");
    e.ts = parse_utc(when);
    e.kind = e.provider == "Microsoft-Windows-Sysmon" ? sysmon_kind(static_cast<int>(e.event_id)) : "WindowsEvent";
    std::map<std::string,std::string> fields;
    for (auto n=root.child("EventData").child("Data"); n; n=n.next_sibling("Data")) {
        const std::string key=n.attribute("Name").as_string();
        if (!key.empty()) fields[key]=n.text().as_string();
    }
    e.pid=decimal(data_value(fields,"ProcessId"));
    if (!e.pid) e.pid=decimal(data_value(fields,"ProcessID"));
    if (!e.pid) e.pid=decimal(sys.child("Execution").attribute("ProcessID").as_string());
    e.guid=lower(data_value(fields,"ProcessGuid"));
    e.parent_guid=lower(data_value(fields,"ParentProcessGuid"));
    e.parent_pid=decimal(data_value(fields,"ParentProcessId"));
    if (!e.guid.empty()) e.key="sysmon:"+e.guid;
    if (!e.parent_guid.empty()) e.parent_key="sysmon:"+e.parent_guid;
    e.name=data_value(fields,"Image");
    if (e.kind=="FileCreate" || e.kind=="FileDelete") e.name=data_value(fields,"TargetFilename");
    if (e.kind.rfind("Registry",0)==0) e.name=data_value(fields,"TargetObject");
    if (e.kind=="ImageLoad") e.name=data_value(fields,"ImageLoaded");
    if (e.kind=="DnsQuery") e.name=data_value(fields,"QueryName");
    if (e.name.empty()) e.name=data_value(fields,"Image");
    e.cmd=data_value(fields,"CommandLine");
    e.hashes=data_value(fields,"Hashes");
    if (e.kind=="NetworkConnect") {
        e.src_ip=data_value(fields,"SourceIp"); e.dst_ip=data_value(fields,"DestinationIp");
        e.src_port=decimal(data_value(fields,"SourcePort"));
        e.dst_port=decimal(data_value(fields,"DestinationPort"));
        e.protocol=lower(data_value(fields,"Protocol"));
        e.name=e.dst_ip+":"+std::to_string(e.dst_port);
    }
    e.details=json(fields).dump();
    std::ostringstream raw; root.print(raw,"",pugi::format_raw); e.raw_xml=raw.str();
    insert_event(add,e);
    if (e.kind=="ProcessStart") upsert_process(process,e);
    else if (e.kind=="ProcessEnd" && !e.key.empty()) {
        finish_process.number(1,e.ts); finish_process.text(2,e.key); finish_process.done();
    }
}

int64_t import_xml_file(Db& db, const fs::path& dir, const fs::path& input) {
    db.exec("BEGIN IMMEDIATE");
    try {
        const auto source=register_source(db,dir,input,"event-xml");
        if (!source.fresh) { db.exec("COMMIT"); std::printf("already imported source %lld\n",static_cast<long long>(source.id)); return 0; }
        pugi::xml_document doc;
        const auto result=doc.load_file(source.stored.c_str());
        if (!result) fail(std::string("XML parse: ")+result.description());
        Stmt add(db,kInsertEvent), proc(db,kUpsertProcess);
        Stmt end(db,"UPDATE processes SET end_100ns=? WHERE process_key=?");
        int64_t count=0;
        auto root=doc.child("Event");
        if (root) { consume_xml_event(root,source.id,++count,add,proc,end); }
        else for (auto event=doc.child("Events").child("Event"); event; event=event.next_sibling("Event"))
            consume_xml_event(event,source.id,++count,add,proc,end);
        if (!count) fail("XML contains no Event nodes");
        finish_source(db,source.id,count);
        db.exec("COMMIT");
        std::printf("imported %lld XML events (source %lld)\n",static_cast<long long>(count),static_cast<long long>(source.id));
        return count;
    } catch (...) { db.exec("ROLLBACK"); throw; }
}

int64_t import_evtx_file(Db& db, const fs::path& dir, const fs::path& input) {
    db.exec("BEGIN IMMEDIATE");
    try {
        const auto source=register_source(db,dir,input,"evtx");
        if (!source.fresh) { db.exec("COMMIT"); std::printf("already imported source %lld\n",static_cast<long long>(source.id)); return 0; }
        EVT_HANDLE query=EvtQuery(nullptr,source.stored.c_str(),L"*",EvtQueryFilePath|EvtQueryForwardDirection);
        if (!query) fail("EvtQuery failed (Windows error "+std::to_string(GetLastError())+")");
        Stmt add(db,kInsertEvent), proc(db,kUpsertProcess);
        Stmt end(db,"UPDATE processes SET end_100ns=? WHERE process_key=?");
        int64_t count=0;
        try {
            EVT_HANDLE handles[64]{};
            DWORD returned=0;
            while (EvtNext(query,64,handles,INFINITE,0,&returned)) {
                for (DWORD i=0;i<returned;++i) {
                    try {
                        DWORD bytes=0,props=0;
                        EvtRender(nullptr,handles[i],EvtRenderEventXml,0,nullptr,&bytes,&props);
                        if (GetLastError()!=ERROR_INSUFFICIENT_BUFFER) fail("EvtRender size query failed");
                        std::vector<wchar_t> buffer(bytes/sizeof(wchar_t)+1);
                        if (!EvtRender(nullptr,handles[i],EvtRenderEventXml,static_cast<DWORD>(buffer.size()*sizeof(wchar_t)),buffer.data(),&bytes,&props))
                            fail("EvtRender failed (Windows error "+std::to_string(GetLastError())+")");
                        pugi::xml_document doc;
                        const std::string xml=utf8(buffer.data());
                        if (!doc.load_string(xml.c_str())) fail("invalid event XML from Windows Event Log");
                        consume_xml_event(doc.child("Event"),source.id,++count,add,proc,end);
                    } catch (...) {
                        for (DWORD j=i;j<returned;++j) EvtClose(handles[j]);
                        throw;
                    }
                    EvtClose(handles[i]);
                }
            }
            const DWORD last=GetLastError();
            if (last!=ERROR_NO_MORE_ITEMS) fail("EvtNext failed (Windows error "+std::to_string(last)+")");
        } catch (...) { EvtClose(query); throw; }
        EvtClose(query);
        finish_source(db,source.id,count);
        db.exec("COMMIT");
        std::printf("imported %lld EVTX events (source %lld)\n",static_cast<long long>(count),static_cast<long long>(source.id));
        return count;
    } catch (...) { db.exec("ROLLBACK"); throw; }
}

bool has_column(Db& db,const char* table,const char* name) {
    Stmt q(db,(std::string("PRAGMA table_info(")+table+")").c_str());
    while (q.row()) if (q.str(1)==name) return true;
    return false;
}

int64_t import_snapshot(Db& db,const fs::path& dir,const fs::path& input) {
    db.exec("BEGIN IMMEDIATE");
    try {
        const auto source=register_source(db,dir,input,"process-snapshot");
        if (!source.fresh) { db.exec("COMMIT"); return source.id; }
        angelia::memforensics::LiveSnapshot snapshot;
        std::string error;
        if (!angelia::memforensics::load_snapshot(source.stored,snapshot,error)) fail("process snapshot: "+error);
        Stmt proc(db,kUpsertProcess);
        for (const auto& p:snapshot.processes) {
            Event e;
            e.source_id=source.id; e.pid=p.pid; e.ts=static_cast<int64_t>(p.create_time_100ns);
            e.key="snapshot:"+std::to_string(source.id)+":"+std::to_string(p.pid)+":"+
                  std::to_string(p.create_time_100ns);
            e.name=p.image;
            upsert_process(proc,e);
        }
        finish_source(db,source.id,static_cast<int64_t>(snapshot.processes.size()),
                      "captured="+snapshot.captured_iso8601_utc);
        db.exec("COMMIT");
        std::printf("imported %zu initial process identities (source %lld)\n",
                    snapshot.processes.size(),static_cast<long long>(source.id));
        return source.id;
    } catch (...) { db.exec("ROLLBACK"); throw; }
}

int64_t import_etw_db(Db& db, const fs::path& dir, const fs::path& input,
                      const std::string& notes = {},int64_t snapshot_source_id=0) {
    db.exec("BEGIN IMMEDIATE");
    try {
        const auto source=register_source(db,dir,input,"etw-sqlite",true);
        if (!source.fresh) { db.exec("COMMIT"); std::printf("already imported source %lld\n",static_cast<long long>(source.id)); return 0; }
        Db raw(source.stored,SQLITE_OPEN_READONLY);
        const bool provider=has_column(raw,"events","provider");
        Stmt rows(raw,provider ?
            "SELECT id,timestamp_100ns,pid,kind,event_id,name,attrs,provider FROM events ORDER BY timestamp_100ns,id" :
            "SELECT id,timestamp_100ns,pid,kind,event_id,name,attrs,0 FROM events ORDER BY timestamp_100ns,id");
        Stmt add(db,kInsertEvent), proc(db,kUpsertProcess);
        Stmt end(db,"UPDATE processes SET end_100ns=? WHERE process_key=?");
        std::unordered_map<int64_t,std::string> active;
        if (snapshot_source_id) {
            Stmt seed(db,"SELECT pid,process_key FROM processes WHERE source_id=?");
            seed.number(1,snapshot_source_id);
            while (seed.row()) active[seed.integer(0)]=seed.str(1);
        }
        int64_t count=0;
        while (rows.row()) {
            Event e;
            e.source_id=source.id; e.source_record=std::to_string(rows.integer(0));
            e.ts=rows.integer(1); e.pid=rows.integer(2);
            const auto kind=static_cast<angelia::collector::EventKind>(rows.integer(3));
            e.kind=angelia::collector::to_string(kind);
            e.event_id=rows.integer(4); e.name=rows.str(5); e.details=rows.str(6);
            if (!provider) e.provider="legacy-etw";
            else switch (rows.integer(7)) {
                case 1: e.provider="Microsoft-Windows-Kernel-Process"; break;
                case 2: e.provider="Microsoft-Windows-Kernel-File"; break;
                case 3: e.provider="Microsoft-Windows-Kernel-Registry"; break;
                default: e.provider="other-etw"; break;
            }
            json attrs=json::object();
            if (!e.details.empty()) attrs=json::parse(e.details,nullptr,false);
            if (attrs.is_discarded() || !attrs.is_object()) attrs=json::object();
            if (e.kind=="ProcessStart" || e.kind=="ProcessEnd") {
                e.pid=attrs.value("subject_pid",e.pid);
                e.parent_pid=attrs.value("parent_pid",0);
            }
            if (e.kind=="ProcessStart") {
                e.key="etw:"+std::to_string(source.id)+":"+std::to_string(e.pid)+":"+std::to_string(e.ts);
                if (active.count(e.parent_pid)) e.parent_key=active[e.parent_pid];
                active[e.pid]=e.key;
                upsert_process(proc,e);
            } else {
                if (active.count(e.pid)) e.key=active[e.pid];
                if (e.kind=="ProcessEnd" && !e.key.empty()) {
                    end.number(1,e.ts); end.text(2,e.key); end.done(); active.erase(e.pid);
                }
            }
            insert_event(add,e); ++count;
        }
        finish_source(db,source.id,count,notes);
        db.exec("COMMIT");
        std::printf("imported %lld ETW events (source %lld)\n",static_cast<long long>(count),static_cast<long long>(source.id));
        return count;
    } catch (...) { db.exec("ROLLBACK"); throw; }
}

uint16_t u16(const uint8_t* p,bool little) {
    return little ? uint16_t(p[0]|(p[1]<<8)) : uint16_t((p[0]<<8)|p[1]);
}
uint32_t u32(const uint8_t* p,bool little) {
    return little ? uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24)
                  : (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|uint32_t(p[3]);
}
std::string ipv4(const uint8_t* p) {
    return std::to_string(p[0])+"."+std::to_string(p[1])+"."+
           std::to_string(p[2])+"."+std::to_string(p[3]);
}
struct Packet { int64_t ts=0; std::string src,dst,proto; uint16_t sport=0,dport=0; uint32_t length=0; };
std::optional<Packet> parse_packet(const std::vector<uint8_t>& b,uint32_t linktype) {
    size_t off=0;
    if (linktype==1) {
        if (b.size()<14) return {};
        uint16_t eth=u16(b.data()+12,false); off=14;
        for (int i=0;i<2 && (eth==0x8100 || eth==0x88a8);++i) {
            if (b.size()<off+4) return {};
            eth=u16(b.data()+off+2,false); off+=4;
        }
        if (eth!=0x0800) return {};
    } else if (linktype!=101) return {};
    if (b.size()<off+20 || (b[off]>>4)!=4) return {};
    const size_t ihl=size_t(b[off]&0x0f)*4;
    if (ihl<20 || b.size()<off+ihl+4) return {};
    if ((u16(b.data()+off+6,false)&0x1fff)!=0) return {}; // later fragments have no ports
    const uint8_t proto=b[off+9];
    if (proto!=6 && proto!=17) return {};
    Packet p;
    p.src=ipv4(b.data()+off+12); p.dst=ipv4(b.data()+off+16);
    p.sport=u16(b.data()+off+ihl,false); p.dport=u16(b.data()+off+ihl+2,false);
    p.proto=proto==6 ? "tcp" : "udp";
    p.length=static_cast<uint32_t>(b.size());
    return p;
}

int64_t import_pcap(Db& db,const fs::path& dir,const fs::path& input) {
    db.exec("BEGIN IMMEDIATE");
    try {
        const auto source=register_source(db,dir,input,"pcap");
        if (!source.fresh) { db.exec("COMMIT"); std::printf("already imported source %lld\n",static_cast<long long>(source.id)); return 0; }
        std::ifstream f(source.stored,std::ios::binary);
        std::array<uint8_t,24> header{};
        if (!f.read(reinterpret_cast<char*>(header.data()),header.size())) fail("truncated PCAP header");
        const std::array<uint8_t,4> magic{header[0],header[1],header[2],header[3]};
        bool little=false,nano=false;
        if (magic==std::array<uint8_t,4>{0xd4,0xc3,0xb2,0xa1}) little=true;
        else if (magic==std::array<uint8_t,4>{0xa1,0xb2,0xc3,0xd4}) little=false;
        else if (magic==std::array<uint8_t,4>{0x4d,0x3c,0xb2,0xa1}) {little=true;nano=true;}
        else if (magic==std::array<uint8_t,4>{0xa1,0xb2,0x3c,0x4d}) {little=false;nano=true;}
        else fail("unsupported capture format; import classic .pcap (PCAPNG conversion is required)");
        const uint32_t linktype=u32(header.data()+20,little);
        if (linktype!=1 && linktype!=101) fail("PCAP link type must be Ethernet (1) or raw IP (101)");
        Stmt add(db,"INSERT INTO packets(source_id,packet_no,timestamp_100ns,src_ip,dst_ip,src_port,dst_port,protocol,length) VALUES(?,?,?,?,?,?,?,?,?)");
        int64_t total=0,accepted=0;
        std::array<uint8_t,16> rec{};
        while (f.read(reinterpret_cast<char*>(rec.data()),rec.size())) {
            ++total;
            const uint32_t sec=u32(rec.data(),little), sub=u32(rec.data()+4,little);
            const uint32_t captured=u32(rec.data()+8,little), original=u32(rec.data()+12,little);
            if (captured>16*1024*1024 || captured>original) fail("invalid PCAP packet length at packet "+std::to_string(total));
            std::vector<uint8_t> bytes(captured);
            if (!f.read(reinterpret_cast<char*>(bytes.data()),captured)) fail("truncated PCAP packet "+std::to_string(total));
            auto p=parse_packet(bytes,linktype);
            if (!p) continue;
            p->ts=(int64_t(sec)+11644473600LL)*10000000LL + (nano ? sub/100 : int64_t(sub)*10);
            add.number(1,source.id); add.number(2,total); add.number(3,p->ts);
            add.text(4,p->src); add.text(5,p->dst); add.number(6,p->sport);
            add.number(7,p->dport); add.text(8,p->proto); add.number(9,original); add.done();
            ++accepted;
        }
        if (!f.eof() || f.gcount()!=0) fail("truncated PCAP record header");
        finish_source(db,source.id,accepted,
            "IPv4 TCP/UDP packets indexed: "+std::to_string(accepted)+" of "+std::to_string(total));
        db.exec("COMMIT");
        std::printf("indexed %lld of %lld PCAP packets (source %lld); unsupported protocols remain in raw capture\n",
            static_cast<long long>(accepted),static_cast<long long>(total),static_cast<long long>(source.id));
        return accepted;
    } catch (...) { db.exec("ROLLBACK"); throw; }
}

void correlate(Db& db) {
    // A matching five-tuple and a two-second window support a possible
    // process link. Multiple different process identities remain ambiguous.
    Stmt packets(db,"SELECT id,timestamp_100ns,src_ip,dst_ip,src_port,dst_port,protocol FROM packets");
    Stmt matches(db,R"SQL(SELECT id,process_key FROM events WHERE kind='NetworkConnect'
      AND protocol=? AND timestamp_100ns BETWEEN ? AND ?
      AND ((src_ip=? AND dst_ip=? AND src_port=? AND dst_port=?)
        OR (src_ip=? AND dst_ip=? AND src_port=? AND dst_port=?))
      ORDER BY ABS(timestamp_100ns-?))SQL");
    Stmt update(db,"UPDATE packets SET link_event_id=?, process_key=?, link_status=? WHERE id=?");
    db.exec("BEGIN IMMEDIATE");
    try {
        while (packets.row()) {
            const int64_t id=packets.integer(0),ts=packets.integer(1);
            const std::string src=packets.str(2),dst=packets.str(3),proto=packets.str(6);
            const int64_t sport=packets.integer(4),dport=packets.integer(5);
            matches.text(1,proto); matches.number(2,ts-20000000); matches.number(3,ts+20000000);
            matches.text(4,src); matches.text(5,dst); matches.number(6,sport); matches.number(7,dport);
            matches.text(8,dst); matches.text(9,src); matches.number(10,dport); matches.number(11,sport);
            matches.number(12,ts);
            int64_t match_id=0; std::string key; bool ambiguous=false;
            while (matches.row()) {
                const std::string candidate=matches.str(1);
                if (candidate.empty()) continue;
                if (key.empty()) { key=candidate; match_id=matches.integer(0); }
                else if (candidate!=key) ambiguous=true;
            }
            matches.reset();
            update.number(1,ambiguous ? 0 : match_id);
            update.text(2,ambiguous ? "" : key);
            update.text(3,ambiguous ? "ambiguous" : key.empty() ? "unlinked" : "tuple-time");
            update.number(4,id); update.done();
        }
        db.exec("COMMIT");
    } catch (...) { db.exec("ROLLBACK"); throw; }
}

std::string timestamp_string(int64_t ticks) {
    if (ticks<=0) return "unknown";
    ULARGE_INTEGER u{}; u.QuadPart=static_cast<uint64_t>(ticks);
    FILETIME ft{}; ft.dwLowDateTime=u.LowPart; ft.dwHighDateTime=u.HighPart;
    SYSTEMTIME st{}; if (!FileTimeToSystemTime(&ft,&st)) return "unknown";
    char s[40]; std::snprintf(s,sizeof(s),"%04u-%02u-%02u %02u:%02u:%02u.%03uZ",
        st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond,st.wMilliseconds);
    return s;
}

struct Filter {
    std::optional<int64_t> pid,from,to;
    std::string key,contains;
    int64_t limit=100;
};
std::vector<json> timeline_rows(Db& db,const Filter& f) {
    std::string sql=R"SQL(SELECT 'event' AS type,e.id,e.timestamp_100ns,e.pid,e.process_key,e.kind,e.name,
      e.source_id,e.source_record,'' AS link_status FROM events e WHERE 1=1)SQL";
    if (f.pid) sql+=" AND e.pid=?";
    if (!f.key.empty()) sql+=" AND e.process_key=?";
    if (f.from) sql+=" AND e.timestamp_100ns>=?";
    if (f.to) sql+=" AND e.timestamp_100ns<=?";
    if (!f.contains.empty()) sql+=" AND (e.name LIKE ? OR e.details LIKE ?)";
    sql+=R"SQL( UNION ALL SELECT 'packet',p.id,p.timestamp_100ns,COALESCE(linked.pid,pr.pid,0),
      p.process_key,p.protocol,p.src_ip||':'||p.src_port||' -> '||p.dst_ip||':'||p.dst_port,
      p.source_id,CAST(p.packet_no AS TEXT),p.link_status
      FROM packets p LEFT JOIN processes pr ON pr.process_key=p.process_key
      LEFT JOIN events linked ON linked.id=p.link_event_id WHERE 1=1)SQL";
    if (f.pid) sql+=" AND COALESCE(linked.pid,pr.pid,0)=?";
    if (!f.key.empty()) sql+=" AND p.process_key=?";
    if (f.from) sql+=" AND p.timestamp_100ns>=?";
    if (f.to) sql+=" AND p.timestamp_100ns<=?";
    if (!f.contains.empty()) sql+=" AND (p.src_ip LIKE ? OR p.dst_ip LIKE ?)";
    sql+=" ORDER BY 3,1,2 LIMIT ?";
    Stmt q(db,sql.c_str());
    int idx=1;
    auto bind_filter=[&](bool packet) {
        if (f.pid) q.number(idx++,*f.pid);
        if (!f.key.empty()) q.text(idx++,f.key);
        if (f.from) q.number(idx++,*f.from);
        if (f.to) q.number(idx++,*f.to);
        if (!f.contains.empty()) {
            const std::string pattern="%"+f.contains+"%";
            q.text(idx++,pattern); q.text(idx++,pattern);
        }
        (void)packet;
    };
    bind_filter(false); bind_filter(true); q.number(idx,f.limit);
    std::vector<json> out;
    while (q.row()) out.push_back({
        {"type",q.str(0)},{"id",q.integer(1)},
        {"timestamp_utc",timestamp_string(q.integer(2))},{"timestamp_100ns",q.integer(2)},
        {"pid",q.integer(3)},{"process_key",q.str(4)},
        {"kind",q.str(5)},{"name",q.str(6)},
        {"source_id",q.integer(7)},{"source_record",q.str(8)},
        {"link_status",q.str(9)}});
    return out;
}

std::string html_escape(std::string_view s) {
    std::string out;
    for (const char c:s) {
        switch(c) {
            case '&': out+="&amp;"; break;
            case '<': out+="&lt;"; break;
            case '>': out+="&gt;"; break;
            case '"': out+="&quot;"; break;
            case '\'': out+="&#39;"; break;
            default: out+=c;
        }
    }
    return out;
}

void status(Db& db) {
    Stmt s(db,"SELECT id,type,original_path,stored_path,sha256,record_count,notes FROM sources ORDER BY id");
    std::puts("Sources:");
    while(s.row()) std::printf("  #%lld %-12s %lld records\n    original=%s\n    retained=%s\n    sha256=%s%s%s\n",
        static_cast<long long>(s.integer(0)),s.str(1).c_str(),
        static_cast<long long>(s.integer(5)),s.str(2).c_str(),s.str(3).c_str(),s.str(4).c_str(),
        s.str(6).empty()?"":" | ",s.str(6).c_str());
    Stmt counts(db,"SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM processes),"
        "(SELECT COUNT(*) FROM packets),(SELECT COUNT(*) FROM packets WHERE link_status='tuple-time'),"
        "(SELECT COUNT(*) FROM packets WHERE link_status='ambiguous'),(SELECT COUNT(*) FROM crash_runs)");
    if(counts.row()) std::printf("events=%lld processes=%lld packets=%lld linked_packets=%lld ambiguous_packets=%lld crash_runs=%lld\n",
        static_cast<long long>(counts.integer(0)),static_cast<long long>(counts.integer(1)),
        static_cast<long long>(counts.integer(2)),static_cast<long long>(counts.integer(3)),
        static_cast<long long>(counts.integer(4)),static_cast<long long>(counts.integer(5)));
    Stmt unknown(db,"SELECT provider,event_id,COUNT(*) FROM events WHERE kind='Unknown' "
        "GROUP BY provider,event_id ORDER BY COUNT(*) DESC LIMIT 20");
    bool heading=false;
    while (unknown.row()) {
        if (!heading) { std::puts("Unmapped event IDs:"); heading=true; }
        std::printf("  %s id=%lld count=%lld\n",unknown.str(0).c_str(),
            static_cast<long long>(unknown.integer(1)),static_cast<long long>(unknown.integer(2)));
    }
}

void processes(Db& db) {
    Stmt s(db,"SELECT process_key,pid,image,parent_key,start_100ns,end_100ns FROM processes ORDER BY start_100ns");
    while (s.row()) std::printf("pid=%lld start=%s image=%s\n  key=%s\n  parent=%s end=%s\n",
        static_cast<long long>(s.integer(1)),timestamp_string(s.integer(4)).c_str(),
        s.str(2).c_str(),s.str(0).c_str(),s.str(3).empty()?"unknown":s.str(3).c_str(),
        sqlite3_column_type(s.h,5)==SQLITE_NULL?"unknown":timestamp_string(s.integer(5)).c_str());
}

void save_finding(Stmt& add, const std::string& origin, const std::string& rule,
                  const std::string& subject, const std::string& severity,
                  const std::string& rationale, const std::string& limitations,
                  const json& evidence) {
    add.text(1,origin); add.text(2,rule); add.text(3,subject);
    add.text(4,severity); add.text(5,rationale); add.text(6,limitations);
    add.text(7,evidence.dump()); add.text(8,utc_now()); add.done();
}

constexpr const char* kInsertFinding =
    "INSERT INTO findings(origin,rule_id,subject,severity,rationale,limitations,evidence_json,created_utc) "
    "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(origin,rule_id,subject) DO UPDATE SET "
    "severity=excluded.severity,rationale=excluded.rationale,limitations=excluded.limitations,"
    "evidence_json=excluded.evidence_json,created_utc=excluded.created_utc";

json evidence_event(Stmt& row) {
    return {{"event_id",row.integer(0)},{"source_id",row.integer(2)},
            {"source_record",row.str(3)},{"timestamp_utc",timestamp_string(row.integer(4))},
            {"kind",row.str(5)},{"name",row.str(6)}};
}

json matching_processes_for_hash(Db& db,const std::string& hash) {
    json out=json::array();
    Stmt matches(db,"SELECT process_key,pid,image FROM processes WHERE LOWER(hashes) LIKE ?");
    matches.text(1,"%"+hash+"%");
    while (matches.row()) out.push_back({
        {"process_key",matches.str(0)},{"pid",matches.integer(1)},{"image",matches.str(2)}});
    return out;
}

std::string static_limitations(bool matched) {
    return std::string("Static features are indicators, not proof of execution or malicious behavior.")+
        (matched?" A process hash matches, but behavior still requires separate review.":
         " No case process has a matching SHA-256 hash.");
}

void refresh_static_links(Db& db) {
    Stmt rows(db,"SELECT id,evidence_json FROM findings WHERE origin='static'");
    std::vector<std::pair<int64_t,json>> pending;
    while (rows.row()) {
        json evidence=json::parse(rows.str(1),nullptr,false);
        if (!evidence.is_object() || !evidence.contains("sha256")) continue;
        pending.emplace_back(rows.integer(0),std::move(evidence));
    }
    Stmt update(db,"UPDATE findings SET evidence_json=?,limitations=? WHERE id=?");
    for (auto& [id,evidence]:pending) {
        const auto matches=matching_processes_for_hash(db,evidence["sha256"].get<std::string>());
        evidence["matching_processes_by_sha256"]=matches;
        update.text(1,evidence.dump()); update.text(2,static_limitations(!matches.empty()));
        update.number(3,id); update.done();
    }
}

int analyze_behavior(Db& db) {
    db.exec("BEGIN IMMEDIATE");
    try {
        db.exec("DELETE FROM findings WHERE origin='behavior'");
        Stmt add(db,kInsertFinding);
        int made=0;
        struct Rule { const char* id; const char* where; const char* severity;
                      const char* rationale; const char* limitations; };
        const Rule rules[] = {
            {"run-key-write", "kind='RegistrySetValue' AND (LOWER(name) LIKE '%\\microsoft\\windows\\currentversion\\run\\%' OR LOWER(name) LIKE '%\\microsoft\\windows\\currentversion\\runonce\\%')",
             "medium", "A process set a Windows auto-start Run value.",
             "Installers and legitimate software also use Run keys. The value data and execution outcome are not established by this event."},
            {"user-writable-image-load", "kind='ImageLoad' AND (LOWER(name) LIKE '%\\appdata\\%' OR LOWER(name) LIKE '%\\temp\\%' OR LOWER(name) LIKE '%\\downloads\\%' OR LOWER(name) LIKE '%\\users\\public\\%')",
             "medium", "A process loaded an image from a commonly user-writable location.",
             "Location alone does not establish maliciousness. File ACLs and signatures have not been checked."}
        };
        for (const auto& rule:rules) {
            const std::string sql=std::string("SELECT id,process_key,source_id,source_record,timestamp_100ns,kind,name ")+
                "FROM events WHERE process_key<>'' AND " + rule.where + " ORDER BY process_key,timestamp_100ns,id";
            Stmt rows(db,sql.c_str());
            std::string subject; json samples=json::array(); int64_t count=0;
            auto emit=[&] {
                if (subject.empty()) return;
                const std::string limits=std::string(rule.limitations)+
                    (subject.rfind("snapshot:",0)==0
                     ? " Process identity was inferred from a pre-collection snapshot; verify PID reuse."
                     : "");
                save_finding(add,"behavior",rule.id,subject,rule.severity,rule.rationale,
                             limits,{{"matching_events",count},{"events",samples}});
                ++made;
            };
            while (rows.row()) {
                const std::string key=rows.str(1);
                if (key!=subject) { emit(); subject=key; samples=json::array(); count=0; }
                ++count;
                if (samples.size()<20) samples.push_back(evidence_event(rows));
            }
            emit();
        }
        Stmt groups(db,"SELECT process_key,COUNT(DISTINCT name) FROM events "
            "WHERE process_key<>'' AND kind='FileWrite' AND name<>'' "
            "GROUP BY process_key HAVING COUNT(DISTINCT name)>=50");
        Stmt examples(db,"SELECT id,process_key,source_id,source_record,timestamp_100ns,kind,name "
            "FROM events WHERE process_key=? AND kind='FileWrite' AND name<>'' "
            "GROUP BY name ORDER BY MIN(timestamp_100ns) LIMIT 20");
        while (groups.row()) {
            const std::string key=groups.str(0);
            examples.text(1,key);
            json events=json::array();
            while (examples.row()) events.push_back(evidence_event(examples));
            examples.reset();
            save_finding(add,"behavior","many-files-written",key,"medium",
                "One process wrote to at least 50 distinct file paths during this case.",
                std::string("Backups, builds, and installers can also write many files. File contents and intent have not been checked.")+
                (key.rfind("snapshot:",0)==0
                 ? " Process identity was inferred from a pre-collection snapshot; verify PID reuse."
                 : ""),
                {{"distinct_paths",groups.integer(1)},{"events",events}});
            ++made;
        }
        refresh_static_links(db);
        db.exec("COMMIT");
        return made;
    } catch (...) { db.exec("ROLLBACK"); throw; }
}

void add_pe(Db& db,const fs::path& dir,const fs::path& input) {
    db.exec("BEGIN IMMEDIATE");
    try {
        const auto source=register_source(db,dir,input,"pe");
        if (!source.fresh) { db.exec("COMMIT"); std::printf("already analyzed PE source %lld\n",static_cast<long long>(source.id)); return; }
        const auto result=angelia::riskscore::score_pe(source.stored);
        if (!result.ok) fail("PE analysis: "+result.error);
        const std::string file_hash=sha256(source.stored);
        const auto matching_processes=matching_processes_for_hash(db,file_hash);
        finish_source(db,source.id,1,"static score="+std::to_string(result.score));
        Stmt add(db,kInsertFinding);
        for (const auto& feature:result.features) {
            json ev={{"source_id",source.id},{"sha256",file_hash},
                     {"feature",feature.name},{"feature_evidence",feature.evidence},
                     {"score_contribution",feature.weight},
                     {"imports",result.imports_flat},
                     {"matching_processes_by_sha256",matching_processes}};
            json sections=json::array();
            for (const auto& s:result.sections)
                sections.push_back({{"name",s.name},{"entropy",s.entropy},
                                    {"executable",s.executable},{"writable",s.writable}});
            ev["sections"]=sections;
            save_finding(add,"static",feature.name,"source:"+std::to_string(source.id),
                feature.weight>=0.5?"medium":"low",feature.evidence,
                static_limitations(!matching_processes.empty()),ev);
        }
        db.exec("COMMIT");
        std::printf("analyzed PE source %lld: score=%.3f, %zu named findings\n",
            static_cast<long long>(source.id),result.score,result.features.size());
    } catch (...) { db.exec("ROLLBACK"); throw; }
}

int run_crash_stage(int (*fn)(int,char**),std::vector<std::string> args) {
    std::vector<char*> argv;
    for (auto& arg:args) argv.push_back(arg.data());
    return fn(static_cast<int>(argv.size()),argv.data());
}

void capture_crashes(Db& db,const fs::path& dir,const fs::path& binary,
                     const fs::path& input,int pattern_size,int repeats) {
    if (!fs::is_regular_file(binary)) fail("crash binary does not exist: "+binary.string());
    if (!pattern_size && !fs::is_regular_file(input)) fail("crash input does not exist: "+input.string());
    if (repeats<1 || repeats>20) fail("repeat count must be 1..20");
    if (pattern_size<0 || pattern_size>1048576) fail("pattern size must be 1..1048576");
    auto binary_source=register_source(db,dir,binary,"crash-binary");
    finish_source(db,binary_source.id,1);
    const std::string binary_hash=sha256(binary_source.stored);
    for (int run=1;run<=repeats;++run) {
        const fs::path run_dir=dir/"incoming"/("crash-"+std::to_string(GetTickCount64())+"-"+std::to_string(run));
        if (!fs::create_directories(run_dir)) fail("crash run directory already exists");
        std::vector<std::string> capture={"capture","--binary",fs::absolute(binary).string(),"--out",fs::absolute(run_dir).string()};
        if (pattern_size) { capture.push_back("--gen-pattern"); capture.push_back(std::to_string(pattern_size)); }
        else { capture.push_back("--input"); capture.push_back(fs::absolute(input).string()); }
        if (run_crash_stage(angelia_cli_run_capture,capture)!=0) fail("crash capture failed in "+run_dir.string());
        fs::path artifact;
        for (const auto& file:fs::directory_iterator(run_dir)) {
            if (file.path().extension()==".json") {
                if (!artifact.empty()) fail("multiple crash artifacts in "+run_dir.string());
                artifact=file.path();
            }
        }
        if (artifact.empty()) fail("capture produced no crash artifact");
        auto capture_source=register_source(db,dir,artifact,"crash-capture");
        finish_source(db,capture_source.id,1);
        if (run_crash_stage(angelia_cli_run_analyze,{"analyze",artifact.string()})!=0 ||
            run_crash_stage(angelia_cli_run_classify,{"classify",artifact.string()})!=0)
            fail("crash analysis or classification failed: "+artifact.string());
        std::ifstream f(artifact,std::ios::binary);
        json result=json::parse(f,nullptr,false);
        if (!result.is_object() || !result.contains("analysis") || !result.contains("verdict"))
            fail("classified crash artifact is incomplete");
        const fs::path actual_input=result.value("input_path",std::string{});
        if (!fs::is_regular_file(actual_input)) fail("captured input is missing: "+actual_input.string());
        auto input_source=register_source(db,dir,actual_input,"crash-input");
        auto final_source=register_source(db,dir,artifact,"crash-classified");
        finish_source(db,input_source.id,1);
        finish_source(db,final_source.id,1);
        int64_t dump_id=0;
        const fs::path dump=result.value("minidump_path",std::string{});
        if (!dump.empty() && fs::is_regular_file(dump)) {
            auto dump_source=register_source(db,dir,dump,"crash-minidump");
            finish_source(db,dump_source.id,1);
            dump_id=dump_source.id;
        }
        const std::string series=binary_hash+":"+sha256(input_source.stored);
        Stmt next(db,"SELECT COALESCE(MAX(run_index),0)+1 FROM crash_runs WHERE series_key=?");
        next.text(1,series); next.row();
        const int64_t index=next.integer(0);
        Stmt add(db,"INSERT INTO crash_runs(series_key,run_index,capture_source_id,artifact_source_id,"
            "dump_source_id,binary_source_id,input_source_id,capture_utc,exception_code,bucket,confidence,artifact_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)");
        add.text(1,series); add.number(2,index); add.number(3,capture_source.id);
        add.number(4,final_source.id);
        if (dump_id) add.number(5,dump_id);
        add.number(6,binary_source.id); add.number(7,input_source.id);
        add.text(8,result.value("capture_iso8601_utc",std::string{}));
        add.text(9,result.value("exception_code",std::string{}));
        add.text(10,result["verdict"].value("bucket",std::string{"Unknown"}));
        sqlite3_bind_double(add.h,11,result["verdict"].value("confidence",0.0));
        add.text(12,result.dump()); add.done();
        std::printf("case crash run %lld: %s (artifact source #%lld, dump source #%lld)\n",
            static_cast<long long>(index),result["verdict"].value("bucket",std::string{"Unknown"}).c_str(),
            static_cast<long long>(final_source.id),static_cast<long long>(dump_id));
    }
}

json coverage(Db& db) {
    Stmt q(db,"SELECT COUNT(*),SUM(CASE WHEN process_key='' THEN 1 ELSE 0 END),"
              "SUM(CASE WHEN process_key LIKE 'snapshot:%' THEN 1 ELSE 0 END) FROM events");
    q.row();
    const int64_t total=q.integer(0),unattributed=q.integer(1),snapshot=q.integer(2);
    json out={{"events",total},{"unattributed_events",unattributed},
              {"snapshot_associated_events",snapshot},
              {"assessment",total==0?"no_events":unattributed>0?"limited":
               snapshot>0?"snapshot_association":"no_known_identity_gap"}};
    Stmt sources(db,"SELECT id,notes FROM sources WHERE type='etw-sqlite'");
    out["etw_sources"]=json::array();
    while(sources.row()) {
        json stats=json::parse(sources.str(1),nullptr,false);
        if (stats.is_discarded() || !stats.is_object())
            stats={{"collection_stats","unavailable"}};
        stats["source_id"]=sources.integer(0);
        out["etw_sources"].push_back(stats);
    }
    return out;
}

json finding_rows(Db& db) {
    json out=json::array();
    Stmt q(db,"SELECT id,origin,rule_id,subject,severity,rationale,limitations,evidence_json FROM findings ORDER BY id");
    while(q.row()) {
        json evidence=json::parse(q.str(7),nullptr,false);
        if (evidence.is_discarded()) evidence=json::object();
        out.push_back({{"id",q.integer(0)},{"origin",q.str(1)},
            {"rule_id",q.str(2)},{"subject",q.str(3)},
            {"severity",q.str(4)},{"rationale",q.str(5)},
            {"limitations",q.str(6)},{"evidence",evidence}});
    }
    return out;
}

json crash_rows(Db& db) {
    json out=json::array();
    Stmt q(db,"SELECT id,series_key,run_index,capture_source_id,artifact_source_id,"
        "COALESCE(dump_source_id,0),binary_source_id,input_source_id,capture_utc,"
        "exception_code,bucket,confidence,artifact_json FROM crash_runs ORDER BY series_key,run_index");
    while(q.row()) {
        json artifact=json::parse(q.str(12),nullptr,false);
        if (!artifact.is_object()) artifact=json::object();
        out.push_back({{"id",q.integer(0)},{"series_key",q.str(1)},
            {"run_index",q.integer(2)},{"capture_source_id",q.integer(3)},
            {"artifact_source_id",q.integer(4)},{"dump_source_id",q.integer(5)},
            {"binary_source_id",q.integer(6)},{"input_source_id",q.integer(7)},
            {"capture_utc",q.str(8)},{"exception_code",q.str(9)},
            {"bucket",q.str(10)},{"confidence",sqlite3_column_double(q.h,11)},
            {"artifact",artifact}});
    }
    return out;
}

json crash_series_summary(const json& rows) {
    json out=json::array();
    for (const auto& row:rows) {
        if (out.empty() || out.back()["series_key"]!=row["series_key"])
            out.push_back({{"series_key",row["series_key"]},{"runs",0},
                           {"binary_name",fs::path(row["artifact"].value("binary_path",std::string{})).filename().string()},
                           {"input_name",fs::path(row["artifact"].value("input_path",std::string{})).filename().string()},
                           {"buckets",json::array()},{"disagreement",false}});
        auto& group=out.back();
        group["runs"]=group["runs"].get<int>()+1;
        const auto& buckets=group["buckets"];
        if (std::find(buckets.begin(),buckets.end(),row["bucket"])==buckets.end())
            group["buckets"].push_back(row["bucket"]);
        group["disagreement"]=group["buckets"].size()>1;
    }
    return out;
}

void print_crashes(Db& db,bool as_json) {
    const auto rows=crash_rows(db),series=crash_series_summary(rows);
    if (as_json) { std::puts(json({{"runs",rows},{"series",series}}).dump(2).c_str()); return; }
    if (rows.empty()) { std::puts("No crash runs in this case."); return; }
    for (const auto& group:series)
        std::printf("series %s + %s (%s): %d runs; buckets=%s%s\n",
            group["binary_name"].get<std::string>().c_str(),
            group["input_name"].get<std::string>().c_str(),
            group["series_key"].get<std::string>().c_str(),group["runs"].get<int>(),
            group["buckets"].dump().c_str(),group["disagreement"].get<bool>()?"; VERDICTS DISAGREE":"");
    for (const auto& row:rows)
        std::printf("  run %lld %s confidence=%.2f exception=%s capture=#%lld classified=#%lld dump=#%lld\n",
            static_cast<long long>(row["run_index"].get<int64_t>()),
            row["bucket"].get<std::string>().c_str(),row["confidence"].get<double>(),
            row["exception_code"].get<std::string>().c_str(),
            static_cast<long long>(row["capture_source_id"].get<int64_t>()),
            static_cast<long long>(row["artifact_source_id"].get<int64_t>()),
            static_cast<long long>(row["dump_source_id"].get<int64_t>()));
}

json verify_sources(Db& db,const fs::path& dir) {
    json entries=json::array();
    const std::string root=lower(fs::weakly_canonical(dir).string());
    const std::string prefix=root+std::string(1,fs::path::preferred_separator);
    Stmt q(db,"SELECT id,stored_path,sha256 FROM sources ORDER BY id");
    int64_t ok=0,missing=0,mismatch=0,unsafe=0;
    while(q.row()) {
        const fs::path stored=q.str(1);
        const fs::path path=fs::weakly_canonical(dir/stored);
        std::string status;
        if (lower(path.string()).rfind(prefix,0)!=0) { status="unsafe_path"; ++unsafe; }
        else if (!fs::is_regular_file(path)) { status="missing"; ++missing; }
        else if (sha256(path)!=q.str(2)) { status="hash_mismatch"; ++mismatch; }
        else { status="ok"; ++ok; }
        entries.push_back({{"source_id",q.integer(0)},{"stored_path",stored.generic_string()},
                           {"status",status}});
    }
    return {{"valid",missing==0 && mismatch==0 && unsafe==0},
            {"ok",ok},{"missing",missing},{"hash_mismatch",mismatch},
            {"unsafe_path",unsafe},{"sources",entries}};
}

void print_findings(Db& db,bool as_json) {
    const auto c=coverage(db),rows=finding_rows(db);
    if (as_json) { std::puts(json({{"coverage",c},{"findings",rows}}).dump(2).c_str()); return; }
    std::printf("coverage: %lld events; %lld without process identity; %lld snapshot-associated (%s)\n",
        static_cast<long long>(c["events"].get<int64_t>()),
        static_cast<long long>(c["unattributed_events"].get<int64_t>()),
        static_cast<long long>(c["snapshot_associated_events"].get<int64_t>()),
        c["assessment"].get<std::string>().c_str());
    std::printf("findings: %zu\n",rows.size());
    for(const auto& r:rows)
        std::printf("  #%lld [%s] %s %s: %s\n    %s\n",
            static_cast<long long>(r["id"].get<int64_t>()),
            r["severity"].get<std::string>().c_str(),r["rule_id"].get<std::string>().c_str(),
            r["subject"].get<std::string>().c_str(),r["rationale"].get<std::string>().c_str(),
            r["limitations"].get<std::string>().c_str());
}

void write_report(Db& db,const fs::path& dir,const fs::path& out) {
    Filter f; f.limit=5000;
    auto rows=timeline_rows(db,f);
    const auto integrity=verify_sources(db,dir);
    std::ofstream html(out,std::ios::binary);
    if (!html) fail("cannot write report: "+out.string());
    html << R"HTML(<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Angelia investigation case</title>
<style>:root{color-scheme:light}*,*::before,*::after{box-sizing:border-box}body{font:15px/1.5 system-ui;margin:0;color:#182432;background:#f5f7fa}main{max-width:1400px;margin:auto;padding:2rem;overflow-wrap:anywhere;min-width:0}
h1{font-size:2rem;margin:.25rem 0}h2{border-top:1px solid #c9d4e2;padding-top:1.5rem;margin-top:2rem}nav{display:flex;gap:1rem;flex-wrap:wrap;margin:1.25rem 0}a{color:#145a82}
.lede{color:#43566c}.notice{padding:1rem;background:#e9f2fa;border-left:4px solid #2871a3}.bad{background:#fff0ec;border-color:#a93624}
.cards{display:flex;flex-wrap:wrap;gap:1rem}.card{background:#fff;border:1px solid #dbe3ec;padding:1rem;min-width:180px;border-radius:8px}.card strong{display:block;font-size:1.35rem}
input{padding:.7rem;width:min(100%,34rem);border:1px solid #9eafc2;border-radius:6px}table{border-collapse:collapse;width:100%;background:white;margin-top:1rem}
th,td{padding:.55rem;border-bottom:1px solid #d8e0e8;text-align:left;vertical-align:top}th{background:#e8eff7;position:sticky;top:0}
td{overflow-wrap:anywhere}small,.muted{color:#536274}details{background:white;border:1px solid #dbe3ec;border-radius:8px;padding:.7rem;margin:.6rem 0}summary{cursor:pointer;font-weight:600}
pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:420px;overflow:auto;background:#f3f5f8;padding:1rem}li{margin:.5rem 0}
@media(max-width:700px){main{padding:1rem}table{display:block;overflow:auto}th{position:static}}@media print{body{background:white}main{max-width:none}nav,input{display:none}details{break-inside:avoid}pre{max-height:none}}</style><main>
<h1>Angelia investigation case</h1><p class="lede">Evidence, coverage, findings, crash triage, and a searchable activity timeline.</p>
<nav><a href="#sources">Sources</a><a href="#coverage">Coverage</a><a href="#findings">Findings</a><a href="#crashes">Crashes</a><a href="#timeline">Timeline</a></nav>
<p class="notice">This report can contain paths, command lines, and crash data from the investigated system. Keep the case and exported report private. Every conclusion is a lead for review; inspect its source evidence.</p>
<h2 id="sources">Sources and integrity</h2>)HTML";
    html << "<p class=\"notice" << (integrity["valid"].get<bool>()?"\"":" bad\"") << ">"
         << (integrity["valid"].get<bool>()?"All ":"Integrity problem: ")
         << integrity["ok"] << " sources match their SHA-256 hashes; "
         << integrity["missing"] << " missing; " << integrity["hash_mismatch"]
         << " changed; " << integrity["unsafe_path"] << " unsafe paths.</p><ul>";
    Stmt sources(db,"SELECT id,type,original_path,stored_path,sha256 FROM sources ORDER BY id");
    while (sources.row())
        html << "<li>#" << sources.integer(0) << " " << html_escape(sources.str(1))
             << " — original " << html_escape(sources.str(2)) << "; retained "
             << html_escape(sources.str(3)) << "<br><small>SHA-256 "
             << html_escape(sources.str(4)) << "</small></li>";
    html << R"HTML(</ul>)HTML";
    const auto c=coverage(db),findings=finding_rows(db);
    html << "<h2 id=\"coverage\">Evidence coverage</h2><div class=\"cards\"><div class=\"card\"><strong>" << c["events"] << "</strong>Events</div><div class=\"card\"><strong>"
         << c["unattributed_events"] << "</strong>Without process identity</div><div class=\"card\"><strong>"
         << c["snapshot_associated_events"] << "</strong>Snapshot associated</div></div><p>" << c["events"] << " events; "
         << c["unattributed_events"] << " without a process identity; "
         << c["snapshot_associated_events"] << " linked from a preceding process snapshot. Assessment: "
         << html_escape(c["assessment"].get<std::string>()) << "</p>";
    for (const auto& stats:c["etw_sources"]) {
        html << "<p>ETW source #" << stats["source_id"] << ": ";
        if (stats.value("etw_stats_available",false))
            html << "lost events " << stats.value("etw_events_lost",uint64_t{0})
                 << ", lost buffers " << stats.value("etw_log_buffers_lost",uint64_t{0})
                 << ", pool drops " << stats.value("pool_drops",uint64_t{0})
                 << ", queue drops " << stats.value("queue_drops",uint64_t{0});
        else html << "collection loss counters unavailable";
        html << "</p>";
    }
    html << "<h2 id=\"findings\">Findings</h2>";
    if (findings.empty()) html << "<p>No named findings have been generated. Run <code>angelia case analyze DIR</code>.</p>";
    else {
        html << "<ol>";
        for(const auto& finding:findings) {
            html << "<li><strong>" << html_escape(finding["rule_id"].get<std::string>())
                 << " [" << html_escape(finding["severity"].get<std::string>()) << "]</strong> "
                 << html_escape(finding["subject"].get<std::string>()) << ": "
                 << html_escape(finding["rationale"].get<std::string>())
                 << "<br><small>Limit: " << html_escape(finding["limitations"].get<std::string>())
                 << "</small><details><summary>Evidence</summary><pre>"
                 << html_escape(finding["evidence"].dump(2)) << "</pre></details></li>";
        }
        html << "</ol>";
    }
    const auto crashes=crash_rows(db),series=crash_series_summary(crashes);
    html << "<h2 id=\"crashes\">Crash triage</h2>";
    if (crashes.empty()) html << "<p>No crash runs are attached to this case.</p>";
    for (const auto& group:series)
        html << "<p><strong>" << group["runs"] << " runs</strong> for "
             << html_escape(group["binary_name"].get<std::string>()) << " + "
             << html_escape(group["input_name"].get<std::string>()) << "; SHA-256 pair "
             << html_escape(group["series_key"].get<std::string>())
             << ". Verdicts: " << html_escape(group["buckets"].dump())
             << (group["disagreement"].get<bool>()?". <strong>Runs disagree; inspect each artifact.</strong>":
                 ". Runs agree; this does not establish exploitability by itself.") << "</p>";
    for (const auto& run:crashes) {
        const auto& artifact=run["artifact"];
        const auto analysis=artifact.value("analysis",json::object());
        const auto verdict=artifact.value("verdict",json::object());
        html << "<details><summary>Run " << run["run_index"] << " — "
             << html_escape(run["bucket"].get<std::string>()) << " (confidence "
             << run["confidence"] << ")</summary><p>Captured "
             << html_escape(run["capture_utc"].get<std::string>()) << "; exception "
             << html_escape(run["exception_code"].get<std::string>()) << ". Sources: binary #"
             << run["binary_source_id"] << ", input #" << run["input_source_id"]
             << ", initial capture #" << run["capture_source_id"]
             << ", classified artifact #" << run["artifact_source_id"]
             << ", minidump #" << run["dump_source_id"] << ".</p>"
             << "<p>Instruction: " << html_escape(analysis.value("zydis_disasm",std::string{"unavailable"}))
             << ". Rationale: " << html_escape(verdict.value("rationale",std::string{})) << "</p>"
             << "<p>Classification is an automated triage lead. Missing or varying dump, register, and pattern evidence limits the verdict.</p>"
             << "<pre>" << html_escape(artifact.dump(2)) << "</pre></details>";
    }
    html << R"HTML(
<h2 id="timeline">Activity timeline</h2><p>Showing at most 5,000 rows. Use <code>angelia case timeline</code> for the full database. Packet links use a matching network tuple within two seconds; ambiguous links remain unassigned.</p>
<label>Filter visible rows <input id="find" placeholder="Search time, process, kind, path or address"></label><p id="shown" aria-live="polite"></p>
<table><thead><tr><th>UTC</th><th>Type</th><th>PID / process</th><th>Kind</th><th>Object</th><th>Evidence</th><th>Link</th></tr></thead><tbody>)HTML";
    for (const auto& r:rows) {
        const std::string key=r.at("process_key").get<std::string>();
        html << "<tr><td>" << html_escape(r.at("timestamp_utc").get<std::string>())
             << "</td><td>" << html_escape(r.at("type").get<std::string>())
             << "</td><td>" << r.at("pid") << "<br><small>" << html_escape(key)
             << "</small></td><td>" << html_escape(r.at("kind").get<std::string>())
             << "</td><td>" << html_escape(r.at("name").get<std::string>())
             << "</td><td>#" << r.at("source_id") << ":" << html_escape(r.at("source_record").get<std::string>())
             << "</td><td>" << html_escape(r.at("link_status").get<std::string>()) << "</td></tr>\n";
    }
    html << R"HTML(</tbody></table><script>const f=document.querySelector('#find'),rows=[...document.querySelectorAll('tbody tr')],shown=document.querySelector('#shown');function filter(){const q=f.value.toLowerCase();let n=0;for(const row of rows){row.hidden=!row.textContent.toLowerCase().includes(q);if(!row.hidden)n++}shown.textContent=n+' of '+rows.length+' displayed rows'}f.addEventListener('input',filter);filter()</script></main></html>)HTML";
    std::printf("wrote %s (%zu timeline rows)\n",out.string().c_str(),rows.size());
}

void print_usage() {
    std::puts("angelia case init DIR\n"
      "angelia case collect DIR [--duration SECONDS]  (elevated live ETW)\n"
      "angelia case import-etw DIR DB [--snapshot-source ID]\n"
      "angelia case import-snapshot DIR processes.json\n"
      "angelia case import-evtx DIR LOG.evtx\n"
      "angelia case import-xml DIR events.xml\n"
      "angelia case import-pcap DIR traffic.pcap\n"
      "angelia case add-pe DIR program.exe\n"
      "angelia case crash DIR --binary program.exe (--input file | --gen-pattern N) [--repeat N]\n"
      "angelia case crashes DIR [--json]\n"
      "angelia case analyze DIR\n"
      "angelia case findings DIR [--json]\n"
      "angelia case verify DIR [--json]\n"
      "angelia case status DIR\n"
      "angelia case processes DIR\n"
      "angelia case timeline DIR [--pid N] [--process KEY] [--contains TEXT] [--from UTC] [--to UTC] [--limit N] [--json]\n"
      "angelia case report DIR --out report.html");
}

} // namespace

int angelia_cli_run_case(int argc,char** argv) {
    try {
        if (argc<2 || std::string_view(argv[1])=="--help" || std::string_view(argv[1])=="-h") { print_usage(); return 0; }
        if (argc<3) fail("case directory is required");
        const std::string action=argv[1];
        const fs::path dir=argv[2];
        if (action=="init") {
            fs::create_directories(dir/"sources");
            Db db(case_db(dir)); db.exec(kSchema);
            std::printf("case ready: %s\n",fs::absolute(dir).string().c_str());
            return 0;
        }
        require_case(dir);
        Db db(case_db(dir)); db.exec(kSchema);
        if (action=="status") { status(db); return 0; }
        if (action=="verify") {
            if(argc>4 || (argc==4 && std::string_view(argv[3])!="--json")) fail("verify accepts only --json");
            const auto result=verify_sources(db,dir);
            if(argc==4) std::puts(result.dump(2).c_str());
            else std::printf("%lld sources match SHA-256; %lld missing; %lld changed; %lld unsafe paths\n",
                static_cast<long long>(result["ok"].get<int64_t>()),
                static_cast<long long>(result["missing"].get<int64_t>()),
                static_cast<long long>(result["hash_mismatch"].get<int64_t>()),
                static_cast<long long>(result["unsafe_path"].get<int64_t>()));
            return result["valid"].get<bool>()?0:1;
        }
        if (action=="processes") { processes(db); return 0; }
        if (action=="analyze") { if(argc!=3) fail("analyze takes only DIR");
            std::printf("generated %d behavior findings\n",analyze_behavior(db)); return 0; }
        if (action=="findings") {
            if(argc>4 || (argc==4 && std::string_view(argv[3])!="--json")) fail("findings accepts only --json");
            print_findings(db,argc==4); return 0;
        }
        if (action=="add-pe") { if(argc!=4) fail("PE path is required"); add_pe(db,dir,argv[3]); return 0; }
        if (action=="crashes") {
            if(argc>4 || (argc==4 && std::string_view(argv[3])!="--json")) fail("crashes accepts only --json");
            print_crashes(db,argc==4); return 0;
        }
        if (action=="crash") {
            fs::path binary,input; int pattern=0,repeats=1;
            for (int i=3;i<argc;++i) {
                const std::string opt=argv[i];
                if (i+1>=argc) fail("missing value for "+opt);
                const std::string val=argv[++i];
                if (opt=="--binary") binary=val;
                else if (opt=="--input") input=val;
                else if (opt=="--gen-pattern") pattern=std::stoi(val);
                else if (opt=="--repeat") repeats=std::stoi(val);
                else fail("unknown crash option: "+opt);
            }
            if (binary.empty() || (input.empty()==(pattern==0)))
                fail("crash requires --binary and exactly one of --input or --gen-pattern");
            capture_crashes(db,dir,binary,input,pattern,repeats); return 0;
        }
        if (action=="import-etw" || action=="import-evtx" || action=="import-xml" ||
            action=="import-pcap" || action=="import-snapshot") {
            if (argc<4) fail("input path is required");
            const fs::path input=argv[3];
            int64_t snapshot_id=0;
            if (action=="import-etw" && argc==6 && std::string_view(argv[4])=="--snapshot-source")
                snapshot_id=std::stoll(argv[5]);
            else if (argc!=4) fail("unexpected import option");
            if (snapshot_id) {
                Stmt valid(db,"SELECT id FROM sources WHERE id=? AND type='process-snapshot'");
                valid.number(1,snapshot_id);
                if (!valid.row()) fail("snapshot source ID does not exist");
            }
            if (action=="import-etw") import_etw_db(db,dir,input,"",snapshot_id);
            if (action=="import-evtx") import_evtx_file(db,dir,input);
            if (action=="import-xml") import_xml_file(db,dir,input);
            if (action=="import-pcap") import_pcap(db,dir,input);
            if (action=="import-snapshot") import_snapshot(db,dir,input);
            correlate(db);
            return 0;
        }
        if (action=="collect") {
            int duration=10;
            for (int i=3;i<argc;++i) {
                if (std::string_view(argv[i])=="--duration" && i+1<argc) duration=std::stoi(argv[++i]);
                else fail("unknown collect option");
            }
            if (duration<1 || duration>86400) fail("duration must be 1..86400 seconds");
            fs::create_directories(dir/"incoming");
            const fs::path capture=dir/"incoming"/("live-"+std::to_string(GetTickCount64())+".db");
            fs::path snapshot_path=capture; snapshot_path.replace_extension(".snapshot.json");
            angelia::memforensics::LiveSnapshot initial;
            std::string snapshot_error;
            if (!angelia::memforensics::capture_live(initial,snapshot_error) ||
                !angelia::memforensics::save_snapshot(initial,snapshot_path,snapshot_error))
                fail("initial process snapshot: "+snapshot_error);
            const int64_t snapshot_source_id=import_snapshot(db,dir,snapshot_path);
            fs::path stats_path=capture; stats_path.replace_extension(".stats.json");
            std::string duration_s=std::to_string(duration),path_s=capture.string(),stats_s=stats_path.string();
            std::vector<char*> args{const_cast<char*>("collect"),const_cast<char*>("--duration"),duration_s.data(),
                const_cast<char*>("--db"),path_s.data(),const_cast<char*>("--keep-db"),
                const_cast<char*>("--stats-json"),stats_s.data()};
            const int rc=angelia_cli_run_collect(static_cast<int>(args.size()),args.data());
            if (rc!=0) return rc;
            std::ifstream stats_file(stats_path);
            std::string notes((std::istreambuf_iterator<char>(stats_file)),std::istreambuf_iterator<char>());
            json quality=json::parse(notes,nullptr,false);
            if (quality.is_discarded() || !quality.is_object()) quality=json::object();
            quality["initial_snapshot_source_id"]=snapshot_source_id;
            import_etw_db(db,dir,capture,quality.dump(),snapshot_source_id);
            std::error_code ec; fs::remove(capture,ec);
            fs::remove(stats_path,ec);
            fs::remove(snapshot_path,ec);
            return 0;
        }
        if (action=="timeline") {
            Filter f; bool as_json=false;
            for (int i=3;i<argc;++i) {
                const std::string k=argv[i];
                if (k=="--json") { as_json=true; continue; }
                if (i+1>=argc) fail("missing value for "+k);
                const std::string v=argv[++i];
                if (k=="--pid") f.pid=std::stoll(v);
                else if (k=="--process") f.key=v;
                else if (k=="--contains") f.contains=v;
                else if (k=="--from") f.from=parse_utc(v);
                else if (k=="--to") f.to=parse_utc(v);
                else if (k=="--limit") f.limit=std::stoll(v);
                else fail("unknown timeline option: "+k);
            }
            if (f.limit<1 || f.limit>1000000) fail("limit must be 1..1000000");
            const auto rows=timeline_rows(db,f);
            if (as_json) std::puts(json(rows).dump(2).c_str());
            else for (const auto& r:rows) std::printf("%s %-7s pid=%-6lld %-18s %-45s source=%lld:%s %s\n",
                r.at("timestamp_utc").get<std::string>().c_str(),r.at("type").get<std::string>().c_str(),
                static_cast<long long>(r.at("pid").get<int64_t>()),r.at("kind").get<std::string>().c_str(),
                r.at("name").get<std::string>().c_str(),static_cast<long long>(r.at("source_id").get<int64_t>()),
                r.at("source_record").get<std::string>().c_str(),r.at("process_key").get<std::string>().c_str());
            return 0;
        }
        if (action=="report") {
            if (argc!=5 || std::string_view(argv[3])!="--out") fail("usage: angelia case report DIR --out PATH");
            write_report(db,dir,argv[4]); return 0;
        }
        fail("unknown case action: "+action);
    } catch (const std::exception& e) {
        std::fprintf(stderr,"angelia case: %s\n",e.what()); return 2;
    }
}
