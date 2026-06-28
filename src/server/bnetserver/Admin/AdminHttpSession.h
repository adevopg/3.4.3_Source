#pragma once
#include "HttpSocket.h"

namespace Battlenet
{
class AdminHttpSession : public Trinity::Net::Http::Socket<AdminHttpSession>
{
public:
    explicit AdminHttpSession(boost::asio::ip::tcp::socket&& socket);

    Trinity::Net::Http::RequestHandlerResult RequestHandler(Trinity::Net::Http::RequestContext& context) override;

protected:
    std::shared_ptr<Trinity::Net::Http::SessionState> ObtainSessionState(Trinity::Net::Http::RequestContext& context) const override;
};
}
