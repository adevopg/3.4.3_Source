#pragma once
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <string>
#include <functional>
#include "LogCommon.h"

namespace BnetServerWindow
{
    bool Initialize(HINSTANCE hInstance);
    void Run();
    void AppendLog(LogLevel level, std::string const& text);
    void SetShutdownCallback(std::function<void()> cb);
    void UpdateTitle(char const* status);
    void SetPorts(int bnet, int http, int tact);
    void SetConnectionCount(int active);
    void SetLogsDir(std::string const& dir);
}
#endif
