#include "AutoSnapshot.h"
#include "DatabaseEnv.h"
#include "Log.h"
#include <chrono>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace
{
// {table, guid-column-for-WHERE}
struct SnapTbl { const char* name; const char* guidCol; };
static const SnapTbl k_Tables[] = {
    {"characters",                    "guid"},
    {"character_stats",               "guid"},
    {"character_homebind",            "guid"},
    {"character_skills",              "guid"},
    {"character_spells",              "guid"},
    {"character_talent",              "guid"},
    {"character_glyphs",              "guid"},
    {"character_queststatus",         "guid"},
    {"character_queststatus_rewarded","guid"},
    {"character_queststatus_seasonal","guid"},
    {"character_reputation",          "guid"},
    {"character_achievement",         "guid"},
    {"character_achievement_progress","guid"},
    {"character_aura",                "guid"},
    {"character_aura_effect",         "guid"},
    {"character_pet",                 "owner"},
    {"character_currency",            "CharacterGuid"},
    {"character_action",              "guid"},
    {"character_inventory",           "guid"},
};

// Column name cache built once on startup
static std::map<std::string, std::vector<std::string>> s_ColCache;

static std::string SqlEsc(std::string const& s)
{
    std::string r; r.reserve(s.size() * 2);
    for (unsigned char c : s) {
        switch (c) {
            case '\'': r += "\\'";  break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n";  break;
            case '\r': r += "\\r";  break;
            case '\0': r += "\\0";  break;
            default:   r += char(c); break;
        }
    }
    return r;
}

static std::string JsonStr(std::string const& s)
{
    std::string r = "\"";
    for (unsigned char c : s) {
        if      (c == '"')  r += "\\\"";
        else if (c == '\\') r += "\\\\";
        else if (c == '\n') r += "\\n";
        else if (c == '\r') r += "\\r";
        else if (c < 0x20)  { char buf[8]; snprintf(buf, 8, "\\u%04x", c); r += buf; }
        else                r += c;
    }
    r += '"';
    return r;
}

static void BuildColCache()
{
    s_ColCache.clear();
    for (auto& t : k_Tables) {
        std::string sql = std::string(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS"
            " WHERE TABLE_SCHEMA='characters' AND TABLE_NAME='") + t.name +
            "' ORDER BY ORDINAL_POSITION";
        if (auto res = CharacterDatabase.Query(sql.c_str()))
            do { s_ColCache[t.name].push_back(res->Fetch()[0].GetString()); } while (res->NextRow());
    }
    // item_instance for inventory items
    if (auto res = CharacterDatabase.Query(
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS"
        " WHERE TABLE_SCHEMA='characters' AND TABLE_NAME='item_instance'"
        " ORDER BY ORDINAL_POSITION"))
        do { s_ColCache["item_instance"].push_back(res->Fetch()[0].GetString()); } while (res->NextRow());
}

static std::string SerializeTbl(const char* tbl, const char* guidCol, uint32 guid)
{
    auto it = s_ColCache.find(tbl);
    if (it == s_ColCache.end() || it->second.empty()) return "";

    auto dataRes = CharacterDatabase.Query(
        (std::string("SELECT * FROM `") + tbl + "` WHERE `" + guidCol + "`=" + std::to_string(guid)).c_str());

    std::ostringstream o;
    o << "{\"cols\":[";
    for (size_t i = 0; i < it->second.size(); ++i) { if (i) o << ','; o << '"' << it->second[i] << '"'; }
    o << "],\"rows\":[";
    bool fr = true;
    if (dataRes) do {
        auto f = dataRes->Fetch();
        if (!fr) o << ','; fr = false;
        o << '[';
        for (uint32 i = 0; i < dataRes->GetFieldCount(); ++i) {
            if (i) o << ',';
            if (f[i].IsNull()) o << "null"; else o << JsonStr(f[i].GetString());
        }
        o << ']';
    } while (dataRes->NextRow());
    o << "]}";
    return o.str();
}

static void SnapshotChar(uint32 charGuid, uint32 accountId)
{
    std::ostringstream data;
    data << "{\"version\":2,\"guid\":" << charGuid << ",\"tables\":{";
    bool firstTbl = true;

    for (auto& t : k_Tables) {
        std::string j = SerializeTbl(t.name, t.guidCol, charGuid);
        if (j.empty()) continue;
        if (!firstTbl) data << ','; firstTbl = false;
        data << '"' << t.name << "\":" << j;
    }

    // item_instance — items currently in this character's inventory
    auto invRes = CharacterDatabase.Query(
        ("SELECT item FROM character_inventory WHERE guid=" + std::to_string(charGuid)).c_str());
    if (invRes) {
        std::string guids;
        do {
            if (!guids.empty()) guids += ',';
            guids += invRes->Fetch()[0].GetString();
        } while (invRes->NextRow());

        if (!guids.empty()) {
            auto colIt = s_ColCache.find("item_instance");
            if (colIt != s_ColCache.end() && !colIt->second.empty()) {
                auto itemRes = CharacterDatabase.Query(
                    ("SELECT * FROM item_instance WHERE guid IN (" + guids + ")").c_str());
                if (!firstTbl) data << ','; firstTbl = false;
                data << "\"item_instance\":{\"cols\":[";
                for (size_t i = 0; i < colIt->second.size(); ++i) { if (i) data << ','; data << '"' << colIt->second[i] << '"'; }
                data << "],\"rows\":[";
                bool fr = true;
                if (itemRes) do {
                    auto f = itemRes->Fetch();
                    if (!fr) data << ','; fr = false;
                    data << '[';
                    for (uint32 i = 0; i < itemRes->GetFieldCount(); ++i) {
                        if (i) data << ',';
                        if (f[i].IsNull()) data << "null"; else data << JsonStr(f[i].GetString());
                    }
                    data << ']';
                } while (itemRes->NextRow());
                data << "]}";
            }
        }
    }
    data << "}}";

    // Get character name
    std::string charName;
    if (auto r = CharacterDatabase.Query(("SELECT name FROM characters WHERE guid=" + std::to_string(charGuid)).c_str()))
        charName = r->Fetch()[0].GetString();

    // Insert into admin snapshot table
    std::string sql =
        "INSERT INTO auth.admin_char_snapshots"
        " (bnet_account_id, game_account_id, char_guid, char_name, snapshot_time, label, snap_type, data_json)"
        " VALUES (0," + std::to_string(accountId) + "," + std::to_string(charGuid) +
        ",'" + SqlEsc(charName) + "',NOW(),'Auto-snapshot',2,'" + SqlEsc(data.str()) + "')";
    LoginDatabase.DirectExecute(sql.c_str());
}

static void PruneAutoSnapshots(uint32 charGuid, uint32 keepCount)
{
    // MySQL requires the double-subquery trick when deleting from a table you select from
    std::string sql =
        "DELETE FROM auth.admin_char_snapshots"
        " WHERE char_guid=" + std::to_string(charGuid) +
        " AND snap_type=2"
        " AND id NOT IN ("
        "   SELECT id FROM ("
        "     SELECT id FROM auth.admin_char_snapshots"
        "     WHERE char_guid=" + std::to_string(charGuid) +
        "     AND snap_type=2"
        "     ORDER BY snapshot_time DESC LIMIT " + std::to_string(keepCount) +
        "   ) AS _t"
        ")";
    LoginDatabase.DirectExecute(sql.c_str());
}

} // anon namespace

// ─────────────────────────────────────────────────────────────────────────────

AutoSnapshot& AutoSnapshot::Instance()
{
    static AutoSnapshot inst;
    return inst;
}

void AutoSnapshot::Start(uint32 intervalSeconds, uint32 keepCount)
{
    if (intervalSeconds < 60) intervalSeconds = 60;  // floor at 1 minute
    _interval  = intervalSeconds;
    _keepCount = keepCount > 0 ? keepCount : 1;
    _running   = true;
    _thread    = std::thread(&AutoSnapshot::Run, this);
    TC_LOG_INFO("server.worldserver",
        "AutoSnapshot: started — interval {}s, keep {} snapshots per character",
        intervalSeconds, _keepCount);
}

void AutoSnapshot::Stop()
{
    _running = false;
    if (_thread.joinable())
        _thread.join();
}

void AutoSnapshot::Run()
{
    BuildColCache();

    uint32 elapsed = 0;
    while (_running)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!_running) break;

        if (++elapsed < _interval)
            continue;
        elapsed = 0;

        auto res = CharacterDatabase.Query("SELECT guid, account FROM characters WHERE online=1");
        if (!res) continue;

        uint32 count = 0;
        do {
            if (!_running) break;
            auto f    = res->Fetch();
            uint32 cg = f[0].GetUInt32();
            uint32 ac = f[1].GetUInt32();
            SnapshotChar(cg, ac);
            PruneAutoSnapshots(cg, _keepCount);
            ++count;
        } while (res->NextRow());

        if (count)
            TC_LOG_INFO("server.worldserver",
                "AutoSnapshot: {} snapshot(s) created", count);
    }
}
