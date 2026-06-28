#include "AdminLogBuffer.h"
#include <ctime>

AdminLogBuffer& AdminLogBuffer::Instance()
{
    static AdminLogBuffer inst;
    return inst;
}

char const* AdminLogBuffer::LevelStr(LogLevel level)
{
    switch (level)
    {
        case LOG_LEVEL_TRACE: return "TRACE";
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_FATAL: return "FATAL";
        default:              return "INFO";
    }
}

std::string AdminLogBuffer::TimeNow()
{
    time_t t = time(nullptr);
    struct tm tm;
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[16];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

void AdminLogBuffer::PushLog(LogLevel level, std::string const& text)
{
    AdminLogEntry e;
    e.level = LevelStr(level);
    e.text  = text;
    e.time  = TimeNow();

    std::lock_guard<std::mutex> lk(_mutex);
    e.seq = _nextSeq++;
    _entries.push_back(std::move(e));
    if (_entries.size() > MAX_ENTRIES)
        _entries.pop_front();
}

std::vector<AdminLogEntry> AdminLogBuffer::GetSince(uint64_t seq) const
{
    std::lock_guard<std::mutex> lk(_mutex);
    std::vector<AdminLogEntry> out;
    for (auto const& e : _entries)
        if (e.seq > seq)
            out.push_back(e);
    return out;
}

uint64_t AdminLogBuffer::GetLatestSeq() const
{
    std::lock_guard<std::mutex> lk(_mutex);
    return _nextSeq > 0 ? _nextSeq - 1 : 0;
}
