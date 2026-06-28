#pragma once
#include "HttpService.h"
#include "AdminHttpSession.h"

namespace Battlenet
{
class AdminService : public Trinity::Net::Http::HttpService<AdminHttpSession>
{
public:
    AdminService() : HttpService("admin") { }

    static AdminService& Instance();

    bool StartNetwork(Trinity::Asio::IoContext& ioContext, std::string const& bindIp,
                      uint16 port, int32 threadCount = 1) override;

    std::shared_ptr<Trinity::Net::Http::SessionState>
        CreateNewSessionState(boost::asio::ip::address const& address) override;

    void NotifyShutdown();

private:
    static void OnSocketAccept(boost::asio::ip::tcp::socket&& sock, uint32 threadIndex);
};
}

#define sAdminService Battlenet::AdminService::Instance()
