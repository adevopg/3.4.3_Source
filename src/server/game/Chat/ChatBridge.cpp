#include "ChatBridge.h"
#include "Log.h"
#include <cstdlib>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <thread>
#if defined(USE_HIREDIS)
#pragma warning(push)
#pragma warning(disable: 4200)
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libevent.h>
#pragma warning(pop)
#endif
#include "World.h"
#include "ChatPackets.h"
#include "ObjectAccessor.h"
#include "Player.h"
#include "ChannelMgr.h"
#include "Channel.h"
#include "Guild.h"
#include "GuildMgr.h"
#include "Language.h"
#include "Log.h"
#include <string>
#include <cstdint>
#include <charconv>
#include <rapidjson/document.h>

static std::string extractJsonValue(const std::string& json, const std::string& key)
{
	std::string needle = "\"" + key + "\":\"";
	auto p = json.find(needle);
	if (p == std::string::npos) return {};
	p += needle.size();
	auto q = json.find('"', p);
	if (q == std::string::npos) return {};
	return json.substr(p, q - p);
}

static uint64_t parseGuidString(const std::string& s)
{
	if (s.empty()) return 0;
	// assume decimal guid as string
	uint64_t v = 0;
	for (char c : s)
	{
		if (c < '0' || c > '9') return 0;
		v = v * 10 + (c - '0');
	}
	return v;
}

ChatBridge& ChatBridge::Instance()
{
	static ChatBridge instance;
	return instance;
}

void ChatBridge::PushIncoming(IncomingWebChat&& msg)
{
	std::lock_guard<std::mutex> lk(m_incomingMutex);
	m_incoming.push(std::move(msg));
	m_incomingCond.notify_one();
}

void ChatBridge::ProcessIncoming()
{
	std::queue<IncomingWebChat> q;
	{
		std::lock_guard<std::mutex> lk(m_incomingMutex);
		q.swap(m_incoming);
	}

	while (!q.empty())
	{
		IncomingWebChat msg = std::move(q.front());
		q.pop();
		// Robust dispatch: parse raw JSON with rapidjson
		rapidjson::Document d;
		if (d.Parse(msg.rawJson.c_str()).HasParseError())
		{
			TC_LOG_ERROR("network", "ChatBridge: JSON parse error: %s", msg.rawJson.c_str());
			continue;
		}

		auto getString = [&](const char* k)->std::string {
			if (!d.HasMember(k)) return {};
			const rapidjson::Value& v = d[k];
			if (v.IsString()) return std::string(v.GetString(), v.GetStringLength());
			if (v.IsUint64()) return std::to_string(v.GetUint64());
			if (v.IsUint()) return std::to_string(v.GetUint());
			return {};
		};

		auto getUInt32 = [&](const char* k)->uint32_t {
			if (!d.HasMember(k)) return 0;
			const rapidjson::Value& v = d[k];
			if (v.IsUint()) return v.GetUint();
			if (v.IsUint64()) return uint32_t(v.GetUint64());
			if (v.IsString()) { try { return uint32_t(std::stoul(std::string(v.GetString(), v.GetStringLength()))); } catch(...) { return 0; } }
			return 0u;
		};

		std::string type = getString("type");
		std::string messageStr = getString("message");
		std::string charGuidStr = getString("charGuid");
		uint32_t fromAcc = getUInt32("fromAccount");
		std::string target = getString("target");
		std::string channelName = getString("channel");
		(void)getUInt32("guildId");

		if (messageStr.empty())
		{
			TC_LOG_ERROR("network", "ChatBridge: empty message ignored");
			continue;
		}

		// find player by GUID if provided
		Player* player = nullptr;
		uint64_t guidVal = parseGuidString(charGuidStr);
		if (guidVal)
			player = ObjectAccessor::FindPlayer(ObjectGuid::Create<HighGuid::Player>(guidVal));

		// If player not connected, try find session by account (fromAccount)
		if (!player && fromAcc != 0)
		{
			if (WorldSession* sess = sWorld->FindSession(fromAcc))
				player = sess->GetPlayer();
		}

		if (!player)
		{
			TC_LOG_INFO("network", "ChatBridge: player for charGuid %s not found, broadcasting system message", charGuidStr.c_str());
			WorldPackets::Chat::Chat packet;
			std::string out = "[WEB] " + messageStr;
			packet.Initialize(CHAT_MSG_SYSTEM, LANG_UNIVERSAL, nullptr, nullptr, out);
			sWorld->SendGlobalMessage(packet.Write());
			continue;
		}

		// Validate ownership
		if (fromAcc != 0 && player->GetSession() && player->GetSession()->GetAccountId() != fromAcc)
		{
			TC_LOG_ERROR("network", "ChatBridge: ownership mismatch for player %s (%u) vs fromAccount %u", player->GetName(), player->GetSession()->GetAccountId(), fromAcc);
			continue;
		}

		// Dispatch
		if (type == "say")
			player->Say(messageStr, LANG_UNIVERSAL, player);
		else if (type == "yell")
			player->Yell(messageStr, LANG_UNIVERSAL, player);
		else if (type == "emote")
			player->TextEmote(messageStr, player, false);
		else if (type == "whisper")
		{
			if (!target.empty())
			{
				if (Player* recv = ObjectAccessor::FindPlayerByName(target))
					player->Whisper(messageStr, LANG_UNIVERSAL, recv, false);
				else
					TC_LOG_ERROR("network", "ChatBridge: whisper target %s not found", target.c_str());
			}
		}
		else if (type == "guild" || type == "officer")
		{
			if (Guild* g = sGuildMgr->GetGuildById(player->GetGuildId()))
			{
				bool officerOnly = (type == "officer");
				g->BroadcastToGuild(player->GetSession(), officerOnly, messageStr, LANG_UNIVERSAL);
			}
			else TC_LOG_ERROR("network", "ChatBridge: player %s has no guild for guild chat", player->GetName());
		}
		else if (type == "channel")
		{
			if (!channelName.empty())
			{
				Channel* chan = ChannelMgr::GetChannelForPlayerByNamePart(channelName, player);
				if (chan)
					chan->Say(player->GetGUID(), messageStr, LANG_UNIVERSAL);
				else
					TC_LOG_ERROR("network", "ChatBridge: channel %s not found for player %s", channelName.c_str(), player->GetName());
			}
		}
		else
			TC_LOG_ERROR("network", "ChatBridge: unknown chat type %s", type.c_str());
	}
}

void ChatBridge::Publish(const std::string& channel, const std::string& message)
{
	// If compiled with hiredis, publish directly
#if defined(USE_HIREDIS)
	redisContext* c = redisConnect("127.0.0.1", 6379);
	if (!c || c->err)
	{
		TC_LOG_ERROR("network", "ChatBridge: hiredis connect failed: %s", c ? c->errstr : "unknown");
		if (c) redisFree(c);
		return;
	}

	redisReply* reply = (redisReply*)redisCommand(c, "PUBLISH %s %s", channel.c_str(), message.c_str());
	if (!reply)
	{
		TC_LOG_ERROR("network", "ChatBridge: publish failed (no reply)");
		redisFree(c);
		return;
	}
	freeReplyObject(reply);
	redisFree(c);
#else
	const char* cmd = std::getenv("REDIS_PUBLISH_CMD");
	if (!cmd)
	{
		TC_LOG_INFO("network", "ChatBridge: publish %s -> %s", channel.c_str(), message.c_str());
		return;
	}

	// Build system command: cmd + " '" + message + "'"
	std::string full = std::string(cmd) + " " + channel + " '" + message + "'";
	int r = std::system(full.c_str());
	if (r != 0)
		TC_LOG_ERROR("network", "ChatBridge: publish command failed (%d) for channel %s", r, channel.c_str());
#endif
}

#if !defined(USE_HIREDIS)
void ChatBridge::StartSubscriber() {}
#else
void ChatBridge::StartSubscriber()
{
	m_subRunning = true;
	m_subThread = std::thread([this]() {
		while (m_subRunning)
		{
			redisContext* c = redisConnect("127.0.0.1", 6379);
			if (!c || c->err)
			{
				TC_LOG_ERROR("network", "ChatBridge subscriber: connect failed: %s", c ? c->errstr : "null");
				if (c) redisFree(c);
				std::this_thread::sleep_for(std::chrono::seconds(1));
				continue;
			}

			redisReply* reply = (redisReply*)redisCommand(c, "SUBSCRIBE %s", "chat:in");
			if (reply) freeReplyObject(reply);
			TC_LOG_INFO("network", "ChatBridge subscriber: subscribed to chat:in");
			while (m_subRunning)
			{
				void* r = nullptr;
				if (redisGetReply(c, &r) != REDIS_OK) break;
				redisReply* rr = (redisReply*)r;
				if (rr && rr->type == REDIS_REPLY_ARRAY && rr->elements >= 3)
				{
					if (rr->element[2] && rr->element[2]->str)
					{
						std::string msg = rr->element[2]->str;
						TC_LOG_INFO("network", "ChatBridge received: %s", msg.c_str());
						// push raw JSON to queue for main-thread parsing
						IncomingWebChat iw;
						iw.rawJson = msg;
						{ // push to queue for main thread to process
							PushIncoming(std::move(iw));
						}
					}
				}
				if (rr) freeReplyObject(rr);
			}

			if (c) redisFree(c);
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
		}
	});
}
#endif
