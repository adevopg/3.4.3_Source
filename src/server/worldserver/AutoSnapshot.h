#pragma once
#include "Define.h"
#include <atomic>
#include <thread>

class AutoSnapshot
{
public:
    static AutoSnapshot& Instance();

    void Start(uint32 intervalSeconds, uint32 keepCount);
    void Stop();

private:
    void Run();

    std::thread       _thread;
    std::atomic<bool> _running{false};
    uint32            _interval{1800};
    uint32            _keepCount{10};
};

#define sAutoSnapshot AutoSnapshot::Instance()
