#ifndef TactHttpSession_h__
#define TactHttpSession_h__

#include "HttpSocket.h"

namespace Battlenet
{
// Plain (non-SSL) HTTP session used exclusively for the TACT CDN stub.
class TactHttpSession : public Trinity::Net::Http::Socket<TactHttpSession>
{
public:
    explicit TactHttpSession(boost::asio::ip::tcp::socket&& socket);

    Trinity::Net::Http::RequestHandlerResult RequestHandler(Trinity::Net::Http::RequestContext& context) override;

protected:
    std::shared_ptr<Trinity::Net::Http::SessionState> ObtainSessionState(Trinity::Net::Http::RequestContext& context) const override;
};
}

#endif // TactHttpSession_h__
