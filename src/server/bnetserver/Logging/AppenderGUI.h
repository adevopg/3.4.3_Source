#pragma once
#ifdef _WIN32
#include "Appender.h"

class AppenderGUI : public Appender
{
public:
    static constexpr AppenderType type = AppenderType(4);

    AppenderGUI(uint8 id, std::string const& name, LogLevel level, AppenderFlags flags,
                std::vector<std::string_view> const& /*args*/);

    AppenderType getType() const override { return type; }

private:
    void _write(LogMessage const* message) override;
};
#endif
