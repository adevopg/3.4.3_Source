#ifdef _WIN32
#include "AppenderGUI.h"
#include "AdminLogBuffer.h"
#include "BnetServerWindow.h"
#include "LogMessage.h"

AppenderGUI::AppenderGUI(uint8 id, std::string const& name, LogLevel level,
                         AppenderFlags flags, std::vector<std::string_view> const& /*args*/)
    : Appender(id, name, level, flags)
{
}

void AppenderGUI::_write(LogMessage const* message)
{
    std::string text = message->prefix + message->text;
    sAdminBuf.PushLog(message->level, text);
    BnetServerWindow::AppendLog(message->level, text);
}
#endif
