#ifndef WorldserverBnetStubServices_h__
#define WorldserverBnetStubServices_h__

#include "WorldserverService.h"
#include "BattlenetRpcErrorCodes.h"
#include "presence_service.pb.h"
#include "club_membership_service.pb.h"
#include "club_service.pb.h"
#include "user_manager_service.pb.h"

// Minimal stub services — override Subscribe (and Unsubscribe) to return ERROR_OK
// so the client activates the Battle.net social panel.

namespace Battlenet
{
    namespace Services
    {
        // PresenceService: client subscribes to get real-time friend presence updates
        class PresenceService : public WorldserverService<bgs::protocol::presence::v1::PresenceService>
        {
        public:
            PresenceService(WorldSession* session)
                : WorldserverService<bgs::protocol::presence::v1::PresenceService>(session) {}

            uint32 HandleSubscribe(
                bgs::protocol::presence::v1::SubscribeRequest const*,
                bgs::protocol::NoData*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleUnsubscribe(
                bgs::protocol::presence::v1::UnsubscribeRequest const*,
                bgs::protocol::NoData*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleUpdate(
                bgs::protocol::presence::v1::UpdateRequest const*,
                bgs::protocol::NoData*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleQuery(
                bgs::protocol::presence::v1::QueryRequest const*,
                bgs::protocol::presence::v1::QueryResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleBatchSubscribe(
                bgs::protocol::presence::v1::BatchSubscribeRequest const*,
                bgs::protocol::presence::v1::BatchSubscribeResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleBatchUnsubscribe(
                bgs::protocol::presence::v1::BatchUnsubscribeRequest const*,
                bgs::protocol::NoData*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }
        };

        // ClubMembershipService: client subscribes to get club membership data
        class ClubMembershipService : public WorldserverService<bgs::protocol::club::v1::membership::ClubMembershipService>
        {
        public:
            ClubMembershipService(WorldSession* session)
                : WorldserverService<bgs::protocol::club::v1::membership::ClubMembershipService>(session) {}

            uint32 HandleSubscribe(
                bgs::protocol::club::v1::membership::SubscribeRequest const*,
                bgs::protocol::club::v1::membership::SubscribeResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleUnsubscribe(
                bgs::protocol::club::v1::membership::UnsubscribeRequest const*,
                bgs::protocol::NoData*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetState(
                bgs::protocol::club::v1::membership::GetStateRequest const*,
                bgs::protocol::club::v1::membership::GetStateResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }
        };

        // UserManagerService: client subscribes to get blocked player and recent player data
        class UserManagerService : public WorldserverService<bgs::protocol::user_manager::v1::UserManagerService>
        {
        public:
            UserManagerService(WorldSession* session)
                : WorldserverService<bgs::protocol::user_manager::v1::UserManagerService>(session) {}

            uint32 HandleSubscribe(
                bgs::protocol::user_manager::v1::SubscribeRequest const*,
                bgs::protocol::user_manager::v1::SubscribeResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleUnsubscribe(
                bgs::protocol::user_manager::v1::UnsubscribeRequest const*,
                bgs::protocol::NoData*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }
        };
    }
}

#endif // WorldserverBnetStubServices_h__
