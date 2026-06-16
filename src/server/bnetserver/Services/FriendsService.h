/*
 * This file is part of the TrinityCore Project. See AUTHORS file for Copyright information
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY, to the extent permitted by law; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef FriendsService_h__
#define FriendsService_h__

#include "Service.h"
#include "friends_service.pb.h"

namespace Battlenet
{
    class Session;

    namespace Services
    {
        class Friends : public Service<friends::v1::FriendsService>
        {
            typedef Service<friends::v1::FriendsService> FriendsServiceBase;

        public:
            Friends(Session* session);

            uint32 HandleSubscribe(friends::v1::SubscribeRequest const* request,
                friends::v1::SubscribeResponse* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleGetFriendList(friends::v1::GetFriendListRequest const* request,
                friends::v1::GetFriendListResponse* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleSendInvitation(friends::v1::SendInvitationRequest const* request,
                NoData* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleAcceptInvitation(friends::v1::AcceptInvitationRequest const* request,
                NoData* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleRevokeInvitation(friends::v1::RevokeInvitationRequest const* request,
                NoData* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleDeclineInvitation(friends::v1::DeclineInvitationRequest const* request,
                NoData* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleRemoveFriend(friends::v1::RemoveFriendRequest const* request,
                NoData* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleUnsubscribe(friends::v1::UnsubscribeRequest const* request,
                NoData* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

            uint32 HandleRevokeAllInvitations(friends::v1::RevokeAllInvitationsRequest const* request,
                NoData* response,
                std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& continuation) override;

        private:
            void PopulateFriend(friends::v1::Friend* proto, uint32 friendId, uint32 creationTime);
        };
    }
}

#endif // FriendsService_h__
