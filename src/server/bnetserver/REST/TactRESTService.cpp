#include "TactRESTService.h"
#include "Config.h"
#include "HttpCommon.h"
#include "Log.h"
#include "StringFormat.h"
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>

namespace
{
// Fetches urlPath from Blizzard's public CDN and writes it to cachePath.
// Returns file bytes on success, empty optional if all CDN hosts fail.
std::optional<std::string> ProxyFromBlizzardCDN(std::string_view urlPath, std::filesystem::path const& cachePath)
{
    namespace beast = boost::beast;
    namespace http  = beast::http;
    namespace net   = boost::asio;
    using tcp = net::ip::tcp;

    static constexpr const char* CDN_HOSTS[] = {
        "blzddist1-a.akamaihd.net",
        "level3.blizzard.com",
        "us.cdn.blizzard.com"
    };

    for (const char* host : CDN_HOSTS)
    {
        try
        {
            net::io_context ioc;
            tcp::resolver resolver(ioc);
            beast::tcp_stream stream(ioc);
            stream.expires_after(std::chrono::seconds(20));

            stream.connect(resolver.resolve(host, "80"));

            http::request<http::empty_body> req{http::verb::get, std::string(urlPath), 11};
            req.set(http::field::host, host);
            req.set(http::field::user_agent, "Blizzard Download Agent");
            req.prepare_payload();
            http::write(stream, req);

            beast::flat_buffer buf;
            http::response<http::string_body> res;
            http::read(stream, buf, res);

            beast::error_code ec;
            stream.socket().shutdown(tcp::socket::shutdown_both, ec);

            if (res.result() != http::status::ok)
                continue;

            std::string body = std::move(res.body());

            // Cache to disk atomically via temp file
            std::error_code fsec;
            std::filesystem::create_directories(cachePath.parent_path(), fsec);
            if (!fsec)
            {
                auto tmp = cachePath; tmp += ".tmp";
                std::ofstream out(tmp, std::ios::binary);
                if (out)
                {
                    out.write(body.data(), static_cast<std::streamsize>(body.size()));
                    out.close();
                    std::filesystem::rename(tmp, cachePath, fsec);
                }
            }

            return body;
        }
        catch (std::exception const&) { /* try next CDN host */ }
    }
    return std::nullopt;
}
} // anonymous namespace

namespace Battlenet
{
TactRESTService& TactRESTService::Instance()
{
    static TactRESTService instance;
    return instance;
}

bool TactRESTService::StartNetwork(Trinity::Asio::IoContext& ioContext, std::string const& bindIp, uint16 port, int32 threadCount)
{
    if (!HttpService::StartNetwork(ioContext, bindIp, port, threadCount))
        return false;

    // /tact* and /wow* — TACT PSV endpoints (versions, cdns, bgdl).
    auto tactHandler = [](std::shared_ptr<TactHttpSession> session, Trinity::Net::Http::RequestContext& context)
        -> Trinity::Net::Http::RequestHandlerResult
    {
        using Trinity::Net::Http::ToStdStringView;
        std::string_view target = ToStdStringView(context.request.target());

        std::string body;
        if (target.find("/versions") != std::string_view::npos)
        {
            std::string buildConfig = sConfigMgr->GetStringDefault("LoginREST.TactBuildConfig", "");
            std::string cdnConfig   = sConfigMgr->GetStringDefault("LoginREST.TactCDNConfig",   "");
            std::string buildId     = sConfigMgr->GetStringDefault("LoginREST.TactBuildId",     "");
            std::string version     = sConfigMgr->GetStringDefault("LoginREST.TactVersion",     "");
            std::string extAddr     = sConfigMgr->GetStringDefault("LoginREST.ExternalAddress", "127.0.0.1");

            body = "Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16|KeyRing!HEX:16|BuildId!DEC:4|VersionsName!String:0|ProductConfig!HEX:16\n";
            if (!buildConfig.empty())
            {
                for (std::string_view region : { std::string_view("eu"), std::string_view("us") })
                    body += Trinity::StringFormat("{}|{}|{}||{}|{}|\n", region, buildConfig, cdnConfig, buildId, version);
            }
        }
        else if (target.find("/cdns") != std::string_view::npos)
        {
            std::string extAddr = sConfigMgr->GetStringDefault("LoginREST.ExternalAddress", "127.0.0.1");
            int32 tactPort      = sConfigMgr->GetIntDefault   ("LoginREST.TactPort",         1120);
            std::string cdnUrl  = Trinity::StringFormat("http://{}:{}", extAddr, tactPort);

            body = "Name!STRING:0|Path!STRING:0|Hosts!STRING:0|Servers!STRING:0|ConfigPath!STRING:0\n";
            body += Trinity::StringFormat("eu|tpr/wow|{}|{}|tpr/configs/data\n", extAddr, cdnUrl);
            body += Trinity::StringFormat("us|tpr/wow|{}|{}|tpr/configs/data\n", extAddr, cdnUrl);
        }
        else if (target.find("/bgdl") != std::string_view::npos)
        {
            // Empty BGDL = nothing queued for background download.
            body = "Product!STRING:0|Region!STRING:0|status!STRING:0|encrypted!DEC:1|tags!SPACE-DELIMITED-STRING:0\n";
        }

        TC_LOG_INFO("server.http.tact", "[TACT] PSV {} from {}", target, session->GetClientInfo());
        context.response.result(boost::beast::http::status::ok);
        context.response.set(boost::beast::http::field::content_type, "text/plain; charset=utf-8");
        context.response.body() = std::move(body);
        return Trinity::Net::Http::RequestHandlerResult::Handled;
    };

    RegisterHandler(boost::beast::http::verb::get, "/tact*", tactHandler);
    RegisterHandler(boost::beast::http::verb::get, "/wow*",  tactHandler);

    // /tpr* — Static CASC file server (BuildConfig, CDNConfig, data archives, etc.).
    // Files are served from LoginREST.TactDataDir; URL /tpr/... maps to {dataDir}/tpr/...
    RegisterHandler(boost::beast::http::verb::get, "/tpr*", [](std::shared_ptr<TactHttpSession> /*session*/, Trinity::Net::Http::RequestContext& context)
        -> Trinity::Net::Http::RequestHandlerResult
    {
        using Trinity::Net::Http::ToStdStringView;
        std::string_view target = ToStdStringView(context.request.target());

        // Strip query string (e.g. ?maxhosts=4)
        std::string_view urlPath = target.substr(0, target.find('?'));

        std::string dataDir = sConfigMgr->GetStringDefault("LoginREST.TactDataDir", "./data");

        std::filesystem::path fsPath;
        try
        {
            // urlPath = "/tpr/wow/config/c9/16/..." — strip leading slash
            std::string rel(urlPath.size() > 1 ? urlPath.substr(1) : "");
            fsPath = std::filesystem::weakly_canonical(
                std::filesystem::path(dataDir) / std::filesystem::path(rel));

            // Directory-traversal guard: resolved path must start with resolved dataDir
            std::filesystem::path base = std::filesystem::weakly_canonical(std::filesystem::path(dataDir));
            std::string fsStr   = fsPath.generic_string();
            std::string baseStr = base.generic_string();
            if (baseStr.back() != '/') baseStr += '/';
            if (fsStr.rfind(baseStr, 0) != 0)
            {
                context.response.result(boost::beast::http::status::forbidden);
                context.response.body() = "";
                return Trinity::Net::Http::RequestHandlerResult::Handled;
            }
        }
        catch (std::exception const& ex)
        {
            TC_LOG_ERROR("server.http.tact", "[TACT] CDN path error for {}: {}", urlPath, ex.what());
            context.response.result(boost::beast::http::status::bad_request);
            context.response.body() = "";
            return Trinity::Net::Http::RequestHandlerResult::Handled;
        }

        std::string body;
        std::ifstream file(fsPath, std::ios::binary);
        if (file)
        {
            body.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>{});
            TC_LOG_INFO("server.http.tact", "[TACT] CDN local {} -> {} bytes", urlPath, body.size());
        }
        else
        {
            // File not in local cache — proxy from Blizzard CDN and cache for next time
            TC_LOG_INFO("server.http.tact", "[TACT] CDN proxy {} (not cached)", urlPath);
            auto result = ProxyFromBlizzardCDN(urlPath, fsPath);
            if (!result)
            {
                TC_LOG_WARN("server.http.tact", "[TACT] CDN 404 {} (all CDN hosts failed)", urlPath);
                context.response.result(boost::beast::http::status::not_found);
                context.response.body() = "";
                return Trinity::Net::Http::RequestHandlerResult::Handled;
            }
            body = std::move(*result);
            TC_LOG_INFO("server.http.tact", "[TACT] CDN proxy {} -> {} bytes (cached)", urlPath, body.size());
        }

        context.response.result(boost::beast::http::status::ok);
        context.response.set(boost::beast::http::field::content_type, "application/octet-stream");
        context.response.body() = std::move(body);
        return Trinity::Net::Http::RequestHandlerResult::Handled;
    });

    _acceptor->AsyncAcceptWithCallback<&TactRESTService::OnSocketAccept>();
    return true;
}

std::shared_ptr<Trinity::Net::Http::SessionState> TactRESTService::CreateNewSessionState(boost::asio::ip::address const& address)
{
    std::shared_ptr<Trinity::Net::Http::SessionState> state = std::make_shared<Trinity::Net::Http::SessionState>();
    InitAndStoreSessionState(state, address);
    return state;
}

void TactRESTService::OnSocketAccept(boost::asio::ip::tcp::socket&& sock, uint32 threadIndex)
{
    sTactService.OnSocketOpen(std::move(sock), threadIndex);
}
}
