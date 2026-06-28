#pragma once
#include "LogCommon.h"
#include <atomic>
#include <ctime>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

struct AdminLogEntry
{
    uint64_t    seq;
    std::string level;
    std::string text;
    std::string time;
};

class AdminLogBuffer
{
public:
    static AdminLogBuffer& Instance();

    void PushLog(LogLevel level, std::string const& text);
    std::vector<AdminLogEntry> GetSince(uint64_t seq) const;
    uint64_t GetLatestSeq() const;

    std::atomic<bool>  Running  { true  };
    std::atomic<int>   Sessions { 0     };
    time_t             StartTime{ 0     };
    int                BnetPort { 1119  };
    int                HttpPort { 8081  };
    int                TactPort { 8082  };
    std::string        Version;
    std::function<void()> ShutdownCallback;

private:
    static constexpr size_t MAX_ENTRIES = 500;
    mutable std::mutex         _mutex;
    std::deque<AdminLogEntry>  _entries;
    uint64_t                   _nextSeq { 0 };

    static char const* LevelStr(LogLevel level);
    static std::string TimeNow();
};

#define sAdminBuf AdminLogBuffer::Instance()
