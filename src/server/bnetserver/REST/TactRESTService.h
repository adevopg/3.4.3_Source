#ifndef TactRESTService_h__
#define TactRESTService_h__

#include "HttpService.h"
#include "TactHttpSession.h"

namespace Battlenet
{
// Minimal plain-HTTP service that answers TACT CDN queries from the WoW client.
// The client reaches here via the proto_url returned in the ResourcesService
// GetContentHandle RPC response.  An empty 200 reply tells the client that
// there is no content to stream, clearing the "0 Mbps / 0%" indicator.
class TactRESTService : public Trinity::Net::Http::HttpService<TactHttpSession>
{
public:
    TactRESTService() : HttpService("tact") { }

    static TactRESTService& Instance();

    bool StartNetwork(Trinity::Asio::IoContext& ioContext, std::string const& bindIp, uint16 port, int32 threadCount = 1) override;

    std::shared_ptr<Trinity::Net::Http::SessionState> CreateNewSessionState(boost::asio::ip::address const& address) override;

private:
    static void OnSocketAccept(boost::asio::ip::tcp::socket&& sock, uint32 threadIndex);
};
}

#define sTactService Battlenet::TactRESTService::Instance()

#endif // TactRESTService_h__
