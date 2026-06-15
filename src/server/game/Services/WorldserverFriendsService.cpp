#include "WorldserverFriendsService.h"
#include "BattlenetRpcErrorCodes.h"
#include "DatabaseEnv.h"
#include "LoginDatabase.h"
#include "Log.h"
#include "World.h"
#include "WorldSession.h"
#include "GameTime.h"
#include "friends_types.pb.h"

using namespace Battlenet::Services;
namespace proto = bgs::protocol;

namespace
{
    // FriendsListener method IDs (client-side notification receiver)
    constexpr uint32 METHOD_ON_FRIEND_ADDED                = 1;
    constexpr uint32 METHOD_ON_FRIEND_REMOVED              = 2;
    constexpr uint32 METHOD_ON_RECEIVED_INVITATION_ADDED   = 3;
    constexpr uint32 METHOD_ON_RECEIVED_INVITATION_REMOVED = 4;
    constexpr uint32 METHOD_ON_SENT_INVITATION_ADDED       = 5;
    constexpr uint32 METHOD_ON_SENT_INVITATION_REMOVED     = 6;
}

FriendsService::FriendsService(WorldSession* session) : BaseService(session)
{
}

WorldSession* FriendsService::FindSessionByBnetId(uint32 bnetAccountId)
{
    for (auto const& pair : sWorld->GetAllSessions())
        if (pair.second->GetBattlenetAccountId() == bnetAccountId)
            return pair.second;
    return nullptr;
}

std::string FriendsService::GetOrCreateBattleTag(uint32 bnetAccountId)
{
    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_BATTLETAG);
    stmt->setUInt32(0, bnetAccountId);
    PreparedQueryResult result = LoginDatabase.Query(stmt);

    if (result)
    {
        std::string tag = (*result)[0].GetString();
        if (!tag.empty())
            return tag;
    }

    // Auto-generate BattleTag from email prefix + account ID
    LoginDatabasePreparedStatement* emailStmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_ACCOUNT_EMAIL_BY_ID);
    emailStmt->setUInt32(0, bnetAccountId);
    PreparedQueryResult emailResult = LoginDatabase.Query(emailStmt);

    std::string prefix = "Player";
    if (emailResult)
    {
        std::string email = (*emailResult)[0].GetString();
        auto atPos = email.find('@');
        prefix = (atPos != std::string::npos) ? email.substr(0, atPos) : email;
        if (prefix.size() > 12)
            prefix = prefix.substr(0, 12);
    }

    char suffix[8];
    snprintf(suffix, sizeof(suffix), "%04u", bnetAccountId % 10000);
    std::string tag = prefix + "#" + suffix;

    LoginDatabasePreparedStatement* updStmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_BNET_BATTLETAG);
    updStmt->setString(0, tag);
    updStmt->setUInt32(1, bnetAccountId);
    LoginDatabase.Execute(updStmt);

    return tag;
}

uint32 FriendsService::GetBnetAccountIdByBattleTag(std::string const& battleTag)
{
    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_ACCOUNT_ID_BY_BATTLETAG);
    stmt->setString(0, battleTag);
    PreparedQueryResult result = LoginDatabase.Query(stmt);
    if (result)
        return (*result)[0].GetUInt32();
    return 0;
}

void FriendsService::NotifyFriendAdded(WorldSession* target, uint32 friendBnetId, std::string const& /*friendBattleTag*/, uint32 creationTime)
{
    proto::friends::v1::FriendNotification notif;
    proto::friends::v1::Friend* f = notif.mutable_target();
    f->mutable_account_id()->set_high(0);
    f->mutable_account_id()->set_low(friendBnetId);
    f->set_creation_time(creationTime);
    target->SendBattlenetRequest(proto::friends::v1::FriendsListener::OriginalHash::value, METHOD_ON_FRIEND_ADDED, &notif);
}

void FriendsService::NotifyFriendRemoved(WorldSession* target, uint32 friendBnetId)
{
    proto::friends::v1::FriendNotification notif;
    notif.mutable_target()->mutable_account_id()->set_high(0);
    notif.mutable_target()->mutable_account_id()->set_low(friendBnetId);
    target->SendBattlenetRequest(proto::friends::v1::FriendsListener::OriginalHash::value, METHOD_ON_FRIEND_REMOVED, &notif);
}

void FriendsService::NotifyReceivedInvitationAdded(WorldSession* target, uint64 invId, uint32 inviterBnetId,
    std::string const& inviterBattleTag, std::string const& inviteeBattleTag, uint32 creationTime)
{
    proto::friends::v1::InvitationNotification notif;
    proto::friends::v1::ReceivedInvitation* inv = notif.mutable_invitation();
    inv->set_id(invId);
    inv->mutable_inviter_identity()->mutable_account_id()->set_high(0);
    inv->mutable_inviter_identity()->mutable_account_id()->set_low(inviterBnetId);
    inv->set_inviter_name(inviterBattleTag);
    inv->set_invitee_name(inviteeBattleTag);
    inv->set_creation_time(creationTime);
    target->SendBattlenetRequest(proto::friends::v1::FriendsListener::OriginalHash::value, METHOD_ON_RECEIVED_INVITATION_ADDED, &notif);
}

void FriendsService::NotifyReceivedInvitationRemoved(WorldSession* target, uint64 invId, uint32 reason)
{
    proto::friends::v1::InvitationNotification notif;
    notif.mutable_invitation()->set_id(invId);
    notif.set_reason(reason);
    target->SendBattlenetRequest(proto::friends::v1::FriendsListener::OriginalHash::value, METHOD_ON_RECEIVED_INVITATION_REMOVED, &notif);
}

void FriendsService::NotifySentInvitationAdded(WorldSession* target, uint64 invId,
    std::string const& inviteeBattleTag, uint32 creationTime)
{
    proto::friends::v1::SentInvitationAddedNotification notif;
    notif.mutable_account_id()->set_high(0);
    notif.mutable_account_id()->set_low(target->GetBattlenetAccountId());
    proto::friends::v1::SentInvitation* inv = notif.mutable_invitation();
    inv->set_id(invId);
    inv->set_target_name(inviteeBattleTag);
    inv->set_creation_time(creationTime);
    target->SendBattlenetRequest(proto::friends::v1::FriendsListener::OriginalHash::value, METHOD_ON_SENT_INVITATION_ADDED, &notif);
}

void FriendsService::NotifySentInvitationRemoved(WorldSession* target, uint64 invId, uint32 reason)
{
    proto::friends::v1::SentInvitationRemovedNotification notif;
    notif.mutable_account_id()->set_high(0);
    notif.mutable_account_id()->set_low(target->GetBattlenetAccountId());
    notif.set_invitation_id(invId);
    notif.set_reason(reason);
    target->SendBattlenetRequest(proto::friends::v1::FriendsListener::OriginalHash::value, METHOD_ON_SENT_INVITATION_REMOVED, &notif);
}

uint32 FriendsService::HandleSubscribe(
    proto::friends::v1::SubscribeRequest const* /*request*/,
    proto::friends::v1::SubscribeResponse* response,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    uint32 myBnetId = _session->GetBattlenetAccountId();
    TC_LOG_INFO("network", "FriendsService::HandleSubscribe called for session %s bnetId=%u", _session->GetPlayerInfo().c_str(), myBnetId);
    if (!myBnetId)
        return ERROR_OK;

    // Friends
    {
        LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_FRIENDS);
        stmt->setUInt32(0, myBnetId);
        stmt->setUInt32(1, myBnetId);
        stmt->setUInt32(2, myBnetId);
        PreparedQueryResult result = LoginDatabase.Query(stmt);
        if (result)
        {
            do
            {
                Field* fields = result->Fetch();
                uint32 friendBnetId = fields[0].GetUInt32();
                proto::friends::v1::Friend* f = response->add_friends();
                f->mutable_account_id()->set_high(0);
                f->mutable_account_id()->set_low(friendBnetId);
            } while (result->NextRow());
        }
    }

    // Received invitations
    {
        LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_INVITATIONS_RECEIVED);
        stmt->setUInt32(0, myBnetId);
        PreparedQueryResult result = LoginDatabase.Query(stmt);
        if (result)
        {
            do
            {
                Field* fields = result->Fetch();
                uint64 invId           = fields[0].GetUInt64();
                uint32 inviterBnetId   = fields[1].GetUInt32();
                std::string inviterTag = fields[2].GetString();
                std::string inviteeTag = fields[3].GetString();
                uint32 createdTime     = fields[4].GetUInt32();

                proto::friends::v1::ReceivedInvitation* inv = response->add_received_invitations();
                inv->set_id(invId);
                inv->mutable_inviter_identity()->mutable_account_id()->set_high(0);
                inv->mutable_inviter_identity()->mutable_account_id()->set_low(inviterBnetId);
                inv->set_inviter_name(inviterTag);
                inv->set_invitee_name(inviteeTag);
                inv->set_creation_time(createdTime);
            } while (result->NextRow());
        }
    }

    // Sent invitations
    {
        LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_INVITATIONS_SENT);
        stmt->setUInt32(0, myBnetId);
        PreparedQueryResult result = LoginDatabase.Query(stmt);
        if (result)
        {
            do
            {
                Field* fields = result->Fetch();
                uint64 invId           = fields[0].GetUInt64();
                std::string inviteeName = fields[3].GetString(); // invitee_battletag
                uint32 createdTime     = fields[4].GetUInt32();

                proto::friends::v1::SentInvitation* inv = response->add_sent_invitations();
                inv->set_id(invId);
                inv->set_target_name(inviteeName);
                inv->set_creation_time(createdTime);
            } while (result->NextRow());
        }
    }

    return ERROR_OK;
}

uint32 FriendsService::HandleSendInvitation(
    proto::friends::v1::SendInvitationRequest const* request,
    proto::NoData* /*response*/,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    uint32 myBnetId = _session->GetBattlenetAccountId();
    if (!myBnetId)
        return ERROR_DENIED;

    if (!request->has_params())
        return ERROR_INVALID_ARGS;

    const proto::InvitationParams& params = request->params();
    if (!params.HasExtension(proto::friends::v1::FriendInvitationParams::friend_params))
        return ERROR_INVALID_ARGS;

    const proto::friends::v1::FriendInvitationParams& friendParams =
        params.GetExtension(proto::friends::v1::FriendInvitationParams::friend_params);

    std::string targetBattleTag = friendParams.target_battle_tag();
    if (targetBattleTag.empty())
        return ERROR_INVALID_ARGS;

    uint32 targetBnetId = GetBnetAccountIdByBattleTag(targetBattleTag);
    if (!targetBnetId || targetBnetId == myBnetId)
        return ERROR_INVALID_ARGS;

    std::string myBattleTag = GetOrCreateBattleTag(myBnetId);
    uint32 now = GameTime::GetGameTime();

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_BNET_INVITATION);
    stmt->setUInt32(0, myBnetId);
    stmt->setUInt32(1, targetBnetId);
    stmt->setString(2, myBattleTag);
    stmt->setString(3, targetBattleTag);
    LoginDatabase.Execute(stmt);

    // Fetch the new invitation ID with a sync query
    LoginDatabasePreparedStatement* selStmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_INVITATIONS_SENT);
    selStmt->setUInt32(0, myBnetId);
    PreparedQueryResult result = LoginDatabase.Query(selStmt);
    if (!result)
        return ERROR_OK;

    uint64 newInvId = 0;
    do
    {
        Field* fields = result->Fetch();
        uint32 inviteeId = fields[1].GetUInt32();
        if (inviteeId == targetBnetId)
        {
            newInvId = fields[0].GetUInt64();
            break;
        }
    } while (result->NextRow());

    if (!newInvId)
        return ERROR_OK;

    NotifySentInvitationAdded(_session, newInvId, targetBattleTag, now);

    if (WorldSession* targetSession = FindSessionByBnetId(targetBnetId))
        NotifyReceivedInvitationAdded(targetSession, newInvId, myBnetId, myBattleTag, targetBattleTag, now);

    return ERROR_OK;
}

uint32 FriendsService::HandleAcceptInvitation(
    proto::friends::v1::AcceptInvitationRequest const* request,
    proto::NoData* /*response*/,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    uint64 invId = request->invitation_id();

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_INVITATION_BY_ID);
    stmt->setUInt64(0, invId);
    PreparedQueryResult result = LoginDatabase.Query(stmt);
    if (!result)
        return ERROR_INVALID_ARGS;

    Field* fields = result->Fetch();
    uint32 inviterBnetId   = fields[1].GetUInt32();
    uint32 inviteeBnetId   = fields[2].GetUInt32();
    std::string inviterTag = fields[3].GetString();
    std::string inviteeTag = fields[4].GetString();

    if (inviteeBnetId != _session->GetBattlenetAccountId())
        return ERROR_DENIED;

    LoginDatabasePreparedStatement* insStmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_BNET_FRIEND);
    insStmt->setUInt32(0, inviterBnetId);
    insStmt->setUInt32(1, inviteeBnetId);
    insStmt->setUInt32(2, inviterBnetId);
    insStmt->setUInt32(3, inviteeBnetId);
    LoginDatabase.Execute(insStmt);

    LoginDatabasePreparedStatement* delStmt = LoginDatabase.GetPreparedStatement(LOGIN_DEL_BNET_INVITATION);
    delStmt->setUInt64(0, invId);
    LoginDatabase.Execute(delStmt);

    uint32 now = GameTime::GetGameTime();

    NotifyFriendAdded(_session, inviterBnetId, inviterTag, now);
    NotifyReceivedInvitationRemoved(_session, invId, 0);

    if (WorldSession* inviterSession = FindSessionByBnetId(inviterBnetId))
    {
        NotifyFriendAdded(inviterSession, inviteeBnetId, inviteeTag, now);
        NotifySentInvitationRemoved(inviterSession, invId, 0);
    }

    return ERROR_OK;
}

uint32 FriendsService::HandleDeclineInvitation(
    proto::friends::v1::DeclineInvitationRequest const* request,
    proto::NoData* /*response*/,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    uint64 invId = request->invitation_id();

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_INVITATION_BY_ID);
    stmt->setUInt64(0, invId);
    PreparedQueryResult result = LoginDatabase.Query(stmt);
    if (!result)
        return ERROR_INVALID_ARGS;

    Field* fields = result->Fetch();
    uint32 inviterBnetId = fields[1].GetUInt32();
    uint32 inviteeBnetId = fields[2].GetUInt32();

    if (inviteeBnetId != _session->GetBattlenetAccountId())
        return ERROR_DENIED;

    LoginDatabasePreparedStatement* delStmt = LoginDatabase.GetPreparedStatement(LOGIN_DEL_BNET_INVITATION);
    delStmt->setUInt64(0, invId);
    LoginDatabase.Execute(delStmt);

    NotifyReceivedInvitationRemoved(_session, invId, 1);

    if (WorldSession* inviterSession = FindSessionByBnetId(inviterBnetId))
        NotifySentInvitationRemoved(inviterSession, invId, 1);

    return ERROR_OK;
}

uint32 FriendsService::HandleRevokeInvitation(
    proto::friends::v1::RevokeInvitationRequest const* request,
    proto::NoData* /*response*/,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    uint64 invId = request->invitation_id();

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_INVITATION_BY_ID);
    stmt->setUInt64(0, invId);
    PreparedQueryResult result = LoginDatabase.Query(stmt);
    if (!result)
        return ERROR_INVALID_ARGS;

    Field* fields = result->Fetch();
    uint32 inviterBnetId = fields[1].GetUInt32();
    uint32 inviteeBnetId = fields[2].GetUInt32();

    if (inviterBnetId != _session->GetBattlenetAccountId())
        return ERROR_DENIED;

    LoginDatabasePreparedStatement* delStmt = LoginDatabase.GetPreparedStatement(LOGIN_DEL_BNET_INVITATION);
    delStmt->setUInt64(0, invId);
    LoginDatabase.Execute(delStmt);

    NotifySentInvitationRemoved(_session, invId, 0);

    if (WorldSession* inviteeSession = FindSessionByBnetId(inviteeBnetId))
        NotifyReceivedInvitationRemoved(inviteeSession, invId, 2);

    return ERROR_OK;
}

uint32 FriendsService::HandleRemoveFriend(
    proto::friends::v1::RemoveFriendRequest const* request,
    proto::NoData* /*response*/,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    uint32 myBnetId     = _session->GetBattlenetAccountId();
    uint32 friendBnetId = static_cast<uint32>(request->target_id().low());

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_DEL_BNET_FRIEND);
    stmt->setUInt32(0, myBnetId);
    stmt->setUInt32(1, friendBnetId);
    stmt->setUInt32(2, friendBnetId);
    stmt->setUInt32(3, myBnetId);
    LoginDatabase.Execute(stmt);

    NotifyFriendRemoved(_session, friendBnetId);

    if (WorldSession* friendSession = FindSessionByBnetId(friendBnetId))
        NotifyFriendRemoved(friendSession, myBnetId);

    return ERROR_OK;
}

uint32 FriendsService::HandleGetFriendList(
    proto::friends::v1::GetFriendListRequest const* /*request*/,
    proto::friends::v1::GetFriendListResponse* response,
    std::function<void(ServiceBase*, uint32, ::google::protobuf::Message const*)>& /*continuation*/)
{
    uint32 myBnetId = _session->GetBattlenetAccountId();
    if (!myBnetId)
        return ERROR_OK;

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_FRIENDS);
    stmt->setUInt32(0, myBnetId);
    stmt->setUInt32(1, myBnetId);
    stmt->setUInt32(2, myBnetId);
    PreparedQueryResult result = LoginDatabase.Query(stmt);
    if (result)
    {
        do
        {
            Field* fields = result->Fetch();
            uint32 friendBnetId = fields[0].GetUInt32();
            proto::friends::v1::Friend* f = response->add_friends();
            f->mutable_account_id()->set_high(0);
            f->mutable_account_id()->set_low(friendBnetId);
        } while (result->NextRow());
    }

    return ERROR_OK;
}
