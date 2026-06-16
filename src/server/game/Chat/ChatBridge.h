// Simple outbound bridge helper to publish chat JSON to an external command (e.g. redis-cli)
#pragma once

#ifdef USE_HIREDIS
#pragma warning(push)
#pragma warning(disable: 4200)
#include <hiredis/hiredis.h>
#pragma warning(pop)
#endif
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>

struct ChatMessage
{
	std::string channel;
	std::string message;
};

struct IncomingWebChat
{
	std::string type;
	std::string charGuid;
	std::string message;
	std::string target;
	std::string channel;
	uint32_t guildId = 0;
	uint32_t fromAccount = 0;
	std::string fromName;
	std::string rawJson;
};

class ChatBridge
{
public:
	static ChatBridge& Instance();
	void Publish(const std::string& channel, const std::string& message);
	void PushIncoming(IncomingWebChat&& msg);
	void ProcessIncoming();
	void StartSubscriber();

private:
#ifdef USE_HIREDIS
	redisContext* m_redis = nullptr;
#endif
	std::thread m_thread;
	std::thread m_subThread;
	bool m_subRunning{false};
	std::queue<IncomingWebChat> m_incoming;
	std::mutex m_incomingMutex;
	std::condition_variable m_incomingCond;
	ChatBridge() = default;
	~ChatBridge() = default;
	ChatBridge(const ChatBridge&) = delete;
	ChatBridge& operator=(const ChatBridge&) = delete;
};
