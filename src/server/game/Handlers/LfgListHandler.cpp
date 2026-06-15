#include "WorldSession.h"
#include "LFGListMgr.h"
#include "LFGList.h"
#include "LfgListPackets.h"
#include "Chat.h"
#include "Group.h"

void WorldSession::HandleLfgListJoin(WorldPackets::LfgList::LfgListJoin& packet)
{
    auto list = new LFGListEntry;
    list->GroupFinderActivityData = sGroupFinderActivityStore.LookupEntry(packet.Request.ActivityID);
    list->ItemLevel = packet.Request.ItemLevel;
    list->AutoAccept = packet.Request.AutoAccept;
    list->GroupName = packet.Request.GroupName;
    list->Comment = packet.Request.Comment;
    list->VoiceChat = packet.Request.VoiceChat;
    list->HonorLevel = packet.Request.HonorLevel;
    if (packet.Request.QuestID.has_value())
        list->QuestID = *packet.Request.QuestID;
    list->ApplicationGroup = nullptr;
    list->PrivateGroup = packet.Request.PrivateGroup;
    sLFGListMgr->Insert(list, GetPlayer());
}

void WorldSession::HandleLfgListLeave(WorldPackets::LfgList::LfgListLeave& packet)
{
    auto entry = sLFGListMgr->GetEntrybyGuidLow(packet.ApplicationTicket.Id);
    if (!entry || !entry->ApplicationGroup || !entry->ApplicationGroup->IsLeader(GetPlayer()->GetGUID()))
        return;

    sLFGListMgr->Remove(packet.ApplicationTicket.Id, GetPlayer());
}

void WorldSession::HandleRequestLfgListBlackList(WorldPackets::LfgList::RequestLfgListBlacklist& /*request*/)
{
    SendPacket(WorldPackets::LfgList::LFGListUpdateBlacklist().Write());
}

void WorldSession::HandleLfgListUpdateRequest(WorldPackets::LfgList::LfgListUpdateRequest& packet)
{
    auto entry = sLFGListMgr->GetEntrybyGuidLow(packet.Ticket.Id);
    if (!entry || !entry->ApplicationGroup || !entry->ApplicationGroup->IsLeader(_player->GetGUID()))
        return;

    entry->AutoAccept = packet.UpdateRequest.AutoAccept;
    entry->GroupName = packet.UpdateRequest.GroupName;
    entry->Comment = packet.UpdateRequest.Comment;
    entry->VoiceChat = packet.UpdateRequest.VoiceChat;
    entry->HonorLevel = packet.UpdateRequest.HonorLevel;
    if (packet.UpdateRequest.QuestID.has_value())
        entry->QuestID = *packet.UpdateRequest.QuestID;

    if (packet.UpdateRequest.ItemLevel < sLFGListMgr->GetPlayerItemLevelForActivity(entry->GroupFinderActivityData, _player))
        entry->ItemLevel = packet.UpdateRequest.ItemLevel;
    entry->PrivateGroup = packet.UpdateRequest.PrivateGroup;

    sLFGListMgr->AutoInviteApplicantsIfPossible(entry);
    sLFGListMgr->SendLFGListStatusUpdate(entry);
}

void WorldSession::HandleLfgListGetStatus(WorldPackets::LfgList::LfgListGetStatus& /*packet*/)
{}

void WorldSession::HandleLfgListApplyToGroup(WorldPackets::LfgList::LfgListApplyToGroup& packet)
{
    if (GetPlayer()->GetGroup())
        ChatHandler(GetPlayer()->GetSession()).PSendSysMessage("You can't join it while you in group!");
    else
        sLFGListMgr->OnPlayerApplyForGroup(GetPlayer(), &packet.application.ApplicationTicket, packet.application.ActivityID, packet.application.Comment, packet.application.Role);
}

void WorldSession::HandleLfgListCancelApplication(WorldPackets::LfgList::LfgListCancelApplication& packet)
{
    if (auto entry = sLFGListMgr->GetEntryByApplicant(packet.ApplicantTicket))
        sLFGListMgr->ChangeApplicantStatus(entry->GetApplicant(packet.ApplicantTicket.Id), LFGListApplicationStatus::Cancelled);
}

void WorldSession::HandleLfgListDeclineApplicant(WorldPackets::LfgList::LfgListDeclineApplicant& packet)
{
    if (!_player->GetGroup() || (!_player->GetGroup()->IsAssistant(_player->GetGUID()) && !_player->GetGroup()->IsLeader(_player->GetGUID())))
        return;

    if (auto entry = sLFGListMgr->GetEntrybyGuidLow(packet.ApplicantTicket.Id))
        sLFGListMgr->ChangeApplicantStatus(entry->GetApplicant(packet.ApplicationTicket.Id), LFGListApplicationStatus::Declined);
}

void WorldSession::HandleLfgListSearch(WorldPackets::LfgList::LfgListSearch& request)
{
    WorldPackets::LfgList::LfgListSearchResults results;

    // TODO:

    const auto& list = sLFGListMgr->GetFilteredList(request.GroupFinderCategoryId, request.SearchFilterNum, "", GetPlayer());
    //results.AppicationsCount = list.size();

    for (const auto& lfgEntry : list)
    {
        WorldPackets::LfgList::LFGTEMP entry;

        auto group = lfgEntry->ApplicationGroup;
        if (!group)
            continue;

        entry.Ticket.Id = group->GetGUID().GetCounter();
        entry.Ticket.RequesterGuid = group->GetGUID();
        entry.Ticket.Type = WorldPackets::LFG::RideType::LfgListApplication;
        entry.Ticket.Time = lfgEntry->CreationTime;

        entry.SequenceNum = 14;
        entry.Unk = 5;

        entry.Leader               = group->GetLeaderGUID();
        entry.LastTouchedAny       = group->GetLeaderGUID();
        entry.LastTouchedName      = group->GetLeaderGUID();
        entry.LastTouchedComment   = group->GetLeaderGUID();
        entry.LastTouchedVoiceChat = group->GetLeaderGUID();

        entry.VirtualRealmAddress = GetVirtualRealmAddress();

        entry.Unk2 = 4395;

        entry.BnetFriends = 0;
        entry.CharFriends = 0;
        entry.GuildMates = 0;
        entry.Unk3 = 0;

        entry.CompletedEncountersMask = 0;

        entry.CreationTime = lfgEntry->CreationTime;

        entry.MemberCount = group->GetMemberSlots().size();

        entry.Unk4 = 0;
        entry.Unk5 = 0;

        entry.PartyGUID = group->GetGUID();

        entry.GroupFinderActivityId = lfgEntry->GroupFinderActivityData->ID;

        entry.RequiredItemLevel = lfgEntry->ItemLevel;
        entry.RequiredHonorLevel = lfgEntry->HonorLevel;

        entry.Unk15 = 0;

        entry.AutoAccept = lfgEntry->AutoAccept;
        entry.IsPrivate = lfgEntry->PrivateGroup;

        if (lfgEntry->QuestID)
            *entry.QuestID = lfgEntry->QuestID;

        entry.Unk16 = 2;

        entry.Name = lfgEntry->GroupName;
        entry.Comment = lfgEntry->Comment;
        entry.Voice = lfgEntry->VoiceChat;

        entry.Unk8 = 0;
        entry.Unk9 = 0;
        entry.Unk10 = 0;
        entry.Unk11 = 0;
        entry.Unk12 = 0;

        for (auto const& member : group->GetMemberSlots())
        {
            uint8 role = member.roles >= 2 ? std::log2(member.roles) - 1 : member.roles;

            WorldPackets::LfgList::LFGMemberResult memberResult;
            memberResult.Member = member.guid;
            memberResult.Level = member.level;
            memberResult.Class = member._class;
            memberResult.Role = 1;
            memberResult.Unk13 = 0;
            memberResult.Unk14 = 32768;
            entry.Members.push_back(memberResult);
        }

        results.Entries.emplace_back(entry); // TODO: move contstructor
        break;
    }

    SendPacket(results.Write());
}