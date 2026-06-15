#ifndef WorldserverBnetStubServices_h__
#define WorldserverBnetStubServices_h__

#include "WorldserverService.h"
#include "BattlenetRpcErrorCodes.h"
#include "Log.h"
#include "account_service.pb.h"
#include "account_types.pb.h"
#include "club_core.pb.h"
#include "club_member_id.pb.h"
#include "club_membership_service.pb.h"
#include "club_membership_types.pb.h"
#include "club_service.pb.h"
#include "club_type.pb.h"
#include "content_handle_types.pb.h"
#include "presence_service.pb.h"
#include "resource_service.pb.h"
#include "user_manager_service.pb.h"

// Minimal stub services — override Subscribe (and other common methods) to return ERROR_OK
// so the client activates the Battle.net social panel.

namespace Battlenet
{
    namespace Services
    {
        // AccountService: client subscribes and queries account state info
        class AccountService : public WorldserverService<bgs::protocol::account::v1::AccountService>
        {
        public:
            AccountService(WorldSession* session)
                : WorldserverService<bgs::protocol::account::v1::AccountService>(session) {}

            uint32 HandleSubscribe(
                bgs::protocol::account::v1::SubscriptionUpdateRequest const*,
                bgs::protocol::account::v1::SubscriptionUpdateResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleUnsubscribe(
                bgs::protocol::account::v1::SubscriptionUpdateRequest const*,
                bgs::protocol::NoData*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetAccountState(
                bgs::protocol::account::v1::GetAccountStateRequest const*,
                bgs::protocol::account::v1::GetAccountStateResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetGameAccountState(
                bgs::protocol::account::v1::GetGameAccountStateRequest const*,
                bgs::protocol::account::v1::GetGameAccountStateResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleResolveAccount(
                bgs::protocol::account::v1::ResolveAccountRequest const*,
                bgs::protocol::account::v1::ResolveAccountResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetLicenses(
                bgs::protocol::account::v1::GetLicensesRequest const*,
                bgs::protocol::account::v1::GetLicensesResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetGameSessionInfo(
                bgs::protocol::account::v1::GetGameSessionInfoRequest const*,
                bgs::protocol::account::v1::GetGameSessionInfoResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetGameTimeRemainingInfo(
                bgs::protocol::account::v1::GetGameTimeRemainingInfoRequest const*,
                bgs::protocol::account::v1::GetGameTimeRemainingInfoResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetCAISInfo(
                bgs::protocol::account::v1::GetCAISInfoRequest const*,
                bgs::protocol::account::v1::GetCAISInfoResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetAccountInfo(
                bgs::protocol::account::v1::GetAccountInfoRequest const*,
                bgs::protocol::account::v1::GetAccountInfoResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }
        };

        // ClubService: client subscribes to club (community/guild) events
        class ClubService : public WorldserverService<bgs::protocol::club::v1::ClubService>
        {
        public:
            ClubService(WorldSession* session)
                : WorldserverService<bgs::protocol::club::v1::ClubService>(session) {}

            uint32 HandleSubscribe(
                bgs::protocol::club::v1::SubscribeRequest const*,
                bgs::protocol::NoData*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleUnsubscribe(
                bgs::protocol::club::v1::UnsubscribeRequest const*,
                bgs::protocol::NoData*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetClubType(
                bgs::protocol::club::v1::GetClubTypeRequest const*,
                bgs::protocol::club::v1::GetClubTypeResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetDescription(
                bgs::protocol::club::v1::GetDescriptionRequest const*,
                bgs::protocol::club::v1::GetDescriptionResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetMembers(
                bgs::protocol::club::v1::GetMembersRequest const*,
                bgs::protocol::club::v1::GetMembersResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetMember(
                bgs::protocol::club::v1::GetMemberRequest const*,
                bgs::protocol::club::v1::GetMemberResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetInvitations(
                bgs::protocol::club::v1::GetInvitationsRequest const*,
                bgs::protocol::club::v1::GetInvitationsResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }

            uint32 HandleGetSuggestions(
                bgs::protocol::club::v1::GetSuggestionsRequest const*,
                bgs::protocol::club::v1::GetSuggestionsResponse*,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            { return ERROR_OK; }
        };

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

        // ClubMembershipService: returns the synthetic BNet "group" club so the client shows
        // the Battle.net friends section in the Social frame (O key).
        class ClubMembershipService : public WorldserverService<bgs::protocol::club::v1::membership::ClubMembershipService>
        {
        public:
            ClubMembershipService(WorldSession* session)
                : WorldserverService<bgs::protocol::club::v1::membership::ClubMembershipService>(session) {}

            uint32 HandleSubscribe(
                bgs::protocol::club::v1::membership::SubscribeRequest const*,
                bgs::protocol::club::v1::membership::SubscribeResponse* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            {
                uint32 bnetAccountId = _session->GetBattlenetAccountId();
                TC_LOG_INFO("network", "ClubMembershipService::HandleSubscribe called for %s bnetId=%u",
                    _session->GetPlayerInfo().c_str(), bnetAccountId);

                if (!bnetAccountId)
                    return ERROR_OK;

                // Add the synthetic BNet friends "group" club so the client activates
                // the Battle.net section in the Social frame.
                auto* desc = response->mutable_state()->add_description();

                desc->mutable_member_id()->mutable_account_id()->set_id(bnetAccountId);

                auto* club = desc->mutable_club();
                club->set_id(static_cast<uint64>(bnetAccountId));
                club->mutable_type()->set_program(16974); // 0x424E = "BN"
                club->mutable_type()->set_name("group");
                club->set_name("Battle.net");

                TC_LOG_INFO("network", "ClubMembershipService::HandleSubscribe returning BNet group club id=%u", bnetAccountId);
                return ERROR_OK;
            }

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

        // ResourcesService: returns a ContentHandle pointing to our local TACT stub server so the
        // client has a CDN URL to query. Without proto_url the streaming indicator stays at 0%/0 Mbps.
        class ResourcesService : public WorldserverService<bgs::protocol::resources::v1::ResourcesService>
        {
        public:
            ResourcesService(WorldSession* session)
                : WorldserverService<bgs::protocol::resources::v1::ResourcesService>(session) {}

            uint32 HandleGetContentHandle(
                bgs::protocol::resources::v1::ContentHandleRequest const* request,
                bgs::protocol::ContentHandle* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>&) override
            {
                TC_LOG_DEBUG("network", "ResourcesService::HandleGetContentHandle: program={} stream={} version={}",
                    request->program(), request->stream(), request->version());

                // Point the client at our local TACT stub (chat_bridge /tact/).
                // The stub returns an empty versions list so the client considers
                // the content up-to-date and shows 100% / N/A instead of 0%.
                response->set_region(0x75730000u); // "us\0\0"
                response->set_usage(0u);
                response->set_hash(std::string(16, '\0'));
                response->set_proto_url("http://212.227.187.160:3000/tact/");
                return ERROR_OK;
            }
        };
    }
}

#endif // WorldserverBnetStubServices_h__
