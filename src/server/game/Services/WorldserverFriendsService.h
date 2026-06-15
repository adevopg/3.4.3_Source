#ifndef WorldserverFriendsService_h__
#define WorldserverFriendsService_h__

#include "WorldserverService.h"
#include "friends_service.pb.h"

namespace Battlenet
{
    namespace Services
    {
        class FriendsService : public WorldserverService<bgs::protocol::friends::v1::FriendsService>
        {
            typedef WorldserverService<bgs::protocol::friends::v1::FriendsService> BaseService;

        public:
            FriendsService(WorldSession* session);

            uint32 HandleSubscribe(
                bgs::protocol::friends::v1::SubscribeRequest const* request,
                bgs::protocol::friends::v1::SubscribeResponse* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleSendInvitation(
                bgs::protocol::friends::v1::SendInvitationRequest const* request,
                bgs::protocol::NoData* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleAcceptInvitation(
                bgs::protocol::friends::v1::AcceptInvitationRequest const* request,
                bgs::protocol::NoData* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleDeclineInvitation(
                bgs::protocol::friends::v1::DeclineInvitationRequest const* request,
                bgs::protocol::NoData* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleRevokeInvitation(
                bgs::protocol::friends::v1::RevokeInvitationRequest const* request,
                bgs::protocol::NoData* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleRemoveFriend(
                bgs::protocol::friends::v1::RemoveFriendRequest const* request,
                bgs::protocol::NoData* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleGetFriendList(
                bgs::protocol::friends::v1::GetFriendListRequest const* request,
                bgs::protocol::friends::v1::GetFriendListResponse* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

        private:
            std::string GetOrCreateBattleTag(uint32 bnetAccountId);
            uint32 GetBnetAccountIdByBattleTag(std::string const& battleTag);

            void NotifyFriendAdded(WorldSession* target, uint32 friendBnetId, std::string const& friendBattleTag, uint32 creationTime);
            void NotifyFriendRemoved(WorldSession* target, uint32 friendBnetId);
            void NotifyReceivedInvitationAdded(WorldSession* target, uint64 invId, uint32 inviterBnetId,
                std::string const& inviterBattleTag, std::string const& inviteeBattleTag, uint32 creationTime);
            void NotifyReceivedInvitationRemoved(WorldSession* target, uint64 invId, uint32 reason);
            void NotifySentInvitationAdded(WorldSession* target, uint64 invId,
                std::string const& inviteeBattleTag, uint32 creationTime);
            void NotifySentInvitationRemoved(WorldSession* target, uint64 invId, uint32 reason);

            WorldSession* FindSessionByBnetId(uint32 bnetAccountId);
        };
    }
}

#endif // WorldserverFriendsService_h__
