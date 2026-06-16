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

#include "FriendsService.h"
#include "DatabaseEnv.h"
#include "LoginDatabase.h"
#include "Session.h"
#include "friends_types.pb.h"
#include "BattlenetRpcErrorCodes.h"

static constexpr uint64 BNET_ACCOUNT_ENTITY_HIGH = UI64LIT(0x100000000000000);

Battlenet::Services::Friends::Friends(Session* session) : FriendsServiceBase(session)
{
}

void Battlenet::Services::Friends::PopulateFriend(friends::v1::Friend* proto, uint32 friendId, uint32 creationTime)
{
    proto->mutable_account_id()->set_low(friendId);
    proto->mutable_account_id()->set_high(BNET_ACCOUNT_ENTITY_HIGH);
    if (creationTime)
        proto->set_creation_time(creationTime);

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_BATTLETAG);
    stmt->setUInt32(0, friendId);
    if (PreparedQueryResult result = LoginDatabase.Query(stmt))
    {
        std::string battletag = (*result)[0].GetString();
        if (!battletag.empty())
        {
            Attribute* attr = proto->add_attribute();
            attr->set_name("BattleTag");
            attr->mutable_value()->set_string_value(battletag);
        }
    }
}

uint32 Battlenet::Services::Friends::HandleSubscribe(friends::v1::SubscribeRequest const* /*request*/,
    friends::v1::SubscribeResponse* response,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    uint32 accountId = _session->GetAccountId();
    if (!accountId)
        return ERROR_DENIED;

    // Friends list
    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_FRIENDS);
    stmt->setUInt32(0, accountId);
    stmt->setUInt32(1, accountId);
    stmt->setUInt32(2, accountId);
    if (PreparedQueryResult result = LoginDatabase.Query(stmt))
    {
        do
        {
            Field* fields = result->Fetch();
            uint32 friendId      = fields[0].GetUInt32();
            uint32 creationTime  = fields[1].GetUInt32();
            PopulateFriend(response->add_friends(), friendId, creationTime);
        } while (result->NextRow());
    }

    // Received invitations (pending friend requests sent TO us)
    stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_INVITATIONS_RECEIVED);
    stmt->setUInt32(0, accountId);
    if (PreparedQueryResult result = LoginDatabase.Query(stmt))
    {
        do
        {
            Field* fields = result->Fetch();
            uint64 invId             = fields[0].GetUInt32();
            uint32 inviterId         = fields[1].GetUInt32();
            std::string inviterTag   = fields[2].GetString();
            uint32 created           = fields[4].GetUInt32();

            friends::v1::ReceivedInvitation* inv = response->add_received_invitations();
            inv->set_id(invId);
            inv->mutable_inviter_identity()->mutable_account_id()->set_low(inviterId);
            inv->mutable_inviter_identity()->mutable_account_id()->set_high(BNET_ACCOUNT_ENTITY_HIGH);
            inv->mutable_invitee_identity()->mutable_account_id()->set_low(accountId);
            inv->mutable_invitee_identity()->mutable_account_id()->set_high(BNET_ACCOUNT_ENTITY_HIGH);
            inv->set_inviter_name(inviterTag);
            inv->set_creation_time(created);
        } while (result->NextRow());
    }

    // Sent invitations (pending friend requests sent BY us)
    stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_INVITATIONS_SENT);
    stmt->setUInt32(0, accountId);
    if (PreparedQueryResult result = LoginDatabase.Query(stmt))
    {
        do
        {
            Field* fields = result->Fetch();
            uint64 invId            = fields[0].GetUInt32();
            std::string inviteeTag  = fields[3].GetString();
            uint32 created          = fields[4].GetUInt32();

            friends::v1::SentInvitation* inv = response->add_sent_invitations();
            inv->set_id(invId);
            inv->set_target_name(inviteeTag);
            inv->set_creation_time(created);
        } while (result->NextRow());
    }

    return ERROR_OK;
}

uint32 Battlenet::Services::Friends::HandleGetFriendList(friends::v1::GetFriendListRequest const* /*request*/,
    friends::v1::GetFriendListResponse* response,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    uint32 accountId = _session->GetAccountId();
    if (!accountId)
        return ERROR_DENIED;

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_FRIENDS);
    stmt->setUInt32(0, accountId);
    stmt->setUInt32(1, accountId);
    stmt->setUInt32(2, accountId);
    if (PreparedQueryResult result = LoginDatabase.Query(stmt))
    {
        do
        {
            Field* fields = result->Fetch();
            uint32 friendId     = fields[0].GetUInt32();
            uint32 creationTime = fields[1].GetUInt32();
            PopulateFriend(response->add_friends(), friendId, creationTime);
        } while (result->NextRow());
    }

    return ERROR_OK;
}

uint32 Battlenet::Services::Friends::HandleSendInvitation(friends::v1::SendInvitationRequest const* request,
    NoData* /*response*/,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    uint32 accountId = _session->GetAccountId();
    if (!accountId)
        return ERROR_DENIED;

    // Determine target account ID
    uint32 targetId = 0;

    // Try direct account EntityId first
    if (request->has_target_id() && request->target_id().low() != 0)
        targetId = uint32(request->target_id().low());

    // Fall back to battletag lookup
    if (!targetId && request->has_params() &&
        request->params().HasExtension(friends::v1::FriendInvitationParams::friend_params))
    {
        auto const& fp = request->params().GetExtension(friends::v1::FriendInvitationParams::friend_params);
        if (fp.has_target_battle_tag())
        {
            LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_ACCOUNT_ID_BY_BATTLETAG);
            stmt->setString(0, fp.target_battle_tag());
            if (PreparedQueryResult result = LoginDatabase.Query(stmt))
                targetId = (*result)[0].GetUInt32();
        }
    }

    if (!targetId || targetId == accountId)
        return ERROR_INVALID_ARGS;

    // Read sender's battletag
    std::string senderTag;
    {
        LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_BATTLETAG);
        stmt->setUInt32(0, accountId);
        if (PreparedQueryResult result = LoginDatabase.Query(stmt))
            senderTag = (*result)[0].GetString();
    }

    std::string targetTag;
    {
        LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_BATTLETAG);
        stmt->setUInt32(0, targetId);
        if (PreparedQueryResult result = LoginDatabase.Query(stmt))
            targetTag = (*result)[0].GetString();
    }

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_BNET_INVITATION);
    stmt->setUInt32(0, accountId);
    stmt->setUInt32(1, targetId);
    stmt->setString(2, senderTag);
    stmt->setString(3, targetTag);
    LoginDatabase.Execute(stmt);

    return ERROR_OK;
}

uint32 Battlenet::Services::Friends::HandleAcceptInvitation(friends::v1::AcceptInvitationRequest const* request,
    NoData* /*response*/,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    uint32 accountId = _session->GetAccountId();
    if (!accountId)
        return ERROR_DENIED;

    if (!request->has_invitation_id())
        return ERROR_INVALID_ARGS;

    uint64 invId = request->invitation_id();

    // Look up invitation
    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_INVITATION_BY_ID);
    stmt->setUInt32(0, uint32(invId));
    PreparedQueryResult result = LoginDatabase.Query(stmt);
    if (!result)
        return ERROR_INVALID_ARGS;

    Field* fields = result->Fetch();
    uint32 inviterId = fields[1].GetUInt32();
    uint32 inviteeId = fields[2].GetUInt32();

    // Only the invitee can accept
    if (inviteeId != accountId)
        return ERROR_DENIED;

    // Create friendship (normalized pair)
    LoginDatabasePreparedStatement* insStmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_BNET_FRIEND);
    insStmt->setUInt32(0, inviterId);
    insStmt->setUInt32(1, inviteeId);
    insStmt->setUInt32(2, inviterId);
    insStmt->setUInt32(3, inviteeId);
    LoginDatabase.Execute(insStmt);

    // Remove invitation
    LoginDatabasePreparedStatement* delStmt = LoginDatabase.GetPreparedStatement(LOGIN_DEL_BNET_INVITATION);
    delStmt->setUInt32(0, uint32(invId));
    LoginDatabase.Execute(delStmt);

    return ERROR_OK;
}

uint32 Battlenet::Services::Friends::HandleRevokeInvitation(friends::v1::RevokeInvitationRequest const* request,
    NoData* /*response*/,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    if (!request->has_invitation_id())
        return ERROR_INVALID_ARGS;

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_DEL_BNET_INVITATION);
    stmt->setUInt32(0, uint32(request->invitation_id()));
    LoginDatabase.Execute(stmt);

    return ERROR_OK;
}

uint32 Battlenet::Services::Friends::HandleDeclineInvitation(friends::v1::DeclineInvitationRequest const* request,
    NoData* /*response*/,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    if (!request->has_invitation_id())
        return ERROR_INVALID_ARGS;

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_DEL_BNET_INVITATION);
    stmt->setUInt32(0, uint32(request->invitation_id()));
    LoginDatabase.Execute(stmt);

    return ERROR_OK;
}

uint32 Battlenet::Services::Friends::HandleRemoveFriend(friends::v1::RemoveFriendRequest const* request,
    NoData* /*response*/,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    uint32 accountId = _session->GetAccountId();
    if (!accountId)
        return ERROR_DENIED;

    if (!request->has_target_id())
        return ERROR_INVALID_ARGS;

    uint32 targetId = uint32(request->target_id().low());
    if (!targetId)
        return ERROR_INVALID_ARGS;

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_DEL_BNET_FRIEND);
    stmt->setUInt32(0, accountId);
    stmt->setUInt32(1, targetId);
    stmt->setUInt32(2, targetId);
    stmt->setUInt32(3, accountId);
    LoginDatabase.Execute(stmt);

    return ERROR_OK;
}

uint32 Battlenet::Services::Friends::HandleUnsubscribe(friends::v1::UnsubscribeRequest const* /*request*/,
    NoData* /*response*/,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    return ERROR_OK;
}

uint32 Battlenet::Services::Friends::HandleRevokeAllInvitations(friends::v1::RevokeAllInvitationsRequest const* /*request*/,
    NoData* /*response*/,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    uint32 accountId = _session->GetAccountId();
    if (!accountId)
        return ERROR_DENIED;

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_INVITATIONS_SENT);
    stmt->setUInt32(0, accountId);
    if (PreparedQueryResult result = LoginDatabase.Query(stmt))
    {
        do
        {
            uint32 invId = result->Fetch()[0].GetUInt32();
            LoginDatabasePreparedStatement* delStmt = LoginDatabase.GetPreparedStatement(LOGIN_DEL_BNET_INVITATION);
            delStmt->setUInt32(0, invId);
            LoginDatabase.Execute(delStmt);
        } while (result->NextRow());
    }

    return ERROR_OK;
}
