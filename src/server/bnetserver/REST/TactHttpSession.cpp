#include "TactHttpSession.h"
#include "TactRESTService.h"

namespace Battlenet
{
TactHttpSession::TactHttpSession(boost::asio::ip::tcp::socket&& socket)
    : Socket(std::move(socket)) { }

Trinity::Net::Http::RequestHandlerResult TactHttpSession::RequestHandler(Trinity::Net::Http::RequestContext& context)
{
    return sTactService.HandleRequest(shared_from_this(), context);
}

std::shared_ptr<Trinity::Net::Http::SessionState> TactHttpSession::ObtainSessionState(Trinity::Net::Http::RequestContext& /*context*/) const
{
    return sTactService.CreateNewSessionState(GetRemoteIpAddress());
}
}
