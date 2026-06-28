#include "AdminHttpSession.h"
#include "AdminService.h"

namespace Battlenet
{
AdminHttpSession::AdminHttpSession(boost::asio::ip::tcp::socket&& socket)
    : Socket(std::move(socket)) { }

Trinity::Net::Http::RequestHandlerResult AdminHttpSession::RequestHandler(Trinity::Net::Http::RequestContext& context)
{
    return sAdminService.HandleRequest(shared_from_this(), context);
}

std::shared_ptr<Trinity::Net::Http::SessionState> AdminHttpSession::ObtainSessionState(Trinity::Net::Http::RequestContext& /*context*/) const
{
    return sAdminService.CreateNewSessionState(GetRemoteIpAddress());
}
}
