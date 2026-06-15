#include "LfgListPackets.h"
#include "LFGMgr.h"
#include "GameTime.h"

ByteBuffer& operator<<(ByteBuffer& data, WorldPackets::LfgList::LFGListBlacklist const& blackList)
{
    data << blackList.ActivityID;
    data << blackList.Reason;

    return data;
}

ByteBuffer& operator>>(ByteBuffer& data, WorldPackets::LfgList::ListRequest& join)
{
    data >> join.ActivityID;

    data >> join.ItemLevel;
    data >> join.HonorLevel;

    //data.ResetBitPos();
    uint32 NameLen = data.ReadBits(10);
    uint32 CommenteLen = data.ReadBits(11);
    uint32 VoiceChatLen = data.ReadBits(8);
    join.AutoAccept = data.ReadBit();
    join.PrivateGroup = data.ReadBit();
    bool isForQuest = data.ReadBit();

    data.ReadBit();

    join.GroupName = data.ReadString(NameLen);
    join.Comment = data.ReadString(CommenteLen);
    join.VoiceChat = data.ReadString(VoiceChatLen);

    if (isForQuest)
        data >> *join.QuestID;

    return data;
}

ByteBuffer& operator<<(ByteBuffer& data, WorldPackets::LfgList::ListRequest const& join)
{
    data << join.ActivityID;

    data << join.ItemLevel;
    data << join.HonorLevel;

    data.WriteBits(join.GroupName.length(), 10);
    data.WriteBits(join.Comment.length(), 11);
    data.WriteBits(join.VoiceChat.length(), 8);

    data.WriteBit(1);

    data.WriteBit(join.AutoAccept);
    data.WriteBit(join.PrivateGroup);
    data.WriteBit(join.QuestID.has_value() && *join.QuestID != 0);

    data.FlushBits();

    data.WriteString(join.GroupName);
    data.WriteString(join.Comment);
    data.WriteString(join.VoiceChat);

    if (join.QuestID.has_value() && *join.QuestID != 0)
        data << *join.QuestID;

    return data;
}

ByteBuffer& operator<<(ByteBuffer& data, WorldPackets::LfgList::MemberInfo const& memberInfo)
{
    data << memberInfo.Member;
    data << memberInfo.Level;
    data << memberInfo.Class;
    data << memberInfo.Role;
    data << memberInfo.Unk13;
    data << memberInfo.Unk14;

    return data;
}

ByteBuffer& operator<<(ByteBuffer& data, WorldPackets::LfgList::ListSearchResult const& listSearch)
{
    data << listSearch.ApplicationTicket;
    data << listSearch.ResultID;
    data << listSearch.UnkGuid1;
    data << listSearch.UnkGuid2;
    data << listSearch.UnkGuid3;
    data << listSearch.UnkGuid4;
    data << listSearch.UnkGuid5;
    data << listSearch.VirtualRealmAddress;
    data << static_cast<uint32>(listSearch.BNetFriendsGuids.size());
    data << static_cast<uint32>(listSearch.NumCharFriendsGuids.size());
    data << static_cast<uint32>(listSearch.NumGuildMateGuids.size());
    data << static_cast<uint32>(listSearch.Members.size());
    data << listSearch.CompletedEncounters;
    data << listSearch.Age;
    data << listSearch.ApplicationStatus;

    data << listSearch.UnkGuid5;

    for (ObjectGuid const& v : listSearch.BNetFriendsGuids)
        data << v;

    for (ObjectGuid const& v : listSearch.NumCharFriendsGuids)
        data << v;

    for (ObjectGuid const& v : listSearch.NumGuildMateGuids)
        data << v;

    for (auto const& v : listSearch.Members)
        data << v;

    data << listSearch.JoinRequest;

    return data;
}

void WorldPackets::LfgList::LfgListJoin::Read()
{
    _worldPacket >> Request;
}

void WorldPackets::LfgList::LfgListLeave::Read()
{
    _worldPacket >> ApplicationTicket;
}

WorldPacket const* WorldPackets::LfgList::LFGListUpdateBlacklist::Write()
{
    std::sort(Blacklist.begin(), Blacklist.end(), [](LFGListBlacklist const& a, LFGListBlacklist const& b) -> bool
    {
        return a.ActivityID < b.ActivityID;
    });

    _worldPacket << static_cast<uint32>(Blacklist.size());
    for (auto const& map : Blacklist)
        _worldPacket << map;

    return &_worldPacket;
}

WorldPacket const* WorldPackets::LfgList::LfgListUpdateStatus::Write()
{
    _worldPacket << ApplicationTicket;
    _worldPacket << ExpirationTime;
    _worldPacket << int32(0); // unknown
    _worldPacket << Status;
    _worldPacket << Request;
    _worldPacket.WriteBit(Listed);
    _worldPacket.FlushBits();

    return &_worldPacket;
}

WorldPacket const* WorldPackets::LfgList::LfgListApplyToGroupResponce::Write()
{
    _worldPacket << ApplicantTicket;

    _worldPacket << InviteExpireTimer;

    _worldPacket << int32(0);
    _worldPacket << int16(6);

    _worldPacket << ApplicationTicket;

    _worldPacket << uint8(16); // dunno

    _worldPacket << SearchResult.ApplicationTicket;

    _worldPacket << int32(14);
    _worldPacket << int8(0);

    _worldPacket << SearchResult.UnkGuid1;
    _worldPacket << SearchResult.UnkGuid2;
    _worldPacket << SearchResult.UnkGuid3;
    _worldPacket << SearchResult.UnkGuid4;
    _worldPacket << SearchResult.UnkGuid4; // Voice

    _worldPacket << SearchResult.VirtualRealmAddress;

    _worldPacket << int32(1637);

   _worldPacket << uint32(0);
    _worldPacket << uint32(0);
    _worldPacket << uint32(0);
   _worldPacket << uint32(0); // Unk3

    _worldPacket << uint32(SearchResult.Members.size());

    _worldPacket << uint32(SearchResult.CompletedEncounters);
    _worldPacket << uint32(ApplicationTicket.Time); // CreationTime
    _worldPacket << uint32(0);
    _worldPacket << uint8(0);

    _worldPacket << ApplicationTicket.RequesterGuid;

    for (int i = 0; i < 7; ++i)
    {
        _worldPacket << uint32(0);
        _worldPacket << uint8(255);
    }

    _worldPacket << int32(0); // Type

    _worldPacket << SearchResult.JoinRequest;

    _worldPacket << uint8(8);
    _worldPacket << int32(0);
    _worldPacket << int32(0);
    _worldPacket << int32(0);
    _worldPacket << int8(0);

    for (auto const& v : SearchResult.Members)
        _worldPacket << v;

    /*
     packet.ReadByte("Unk8");
                packet.ReadInt32("Unk9");
                packet.ReadInt32("Unk10");
                packet.ReadInt32("Unk11");
                packet.ReadByte("Unk12");


                for (int i = 0; i < memberCount; i++)
                    ReadLfgListSearchResultMemberInfo(packet, "Members", i);
    */


   // _worldPacket << SearchResult;

    //_worldPacket << Status;
    //_worldPacket << Role;
    //_worldPacket.WriteBits(ApplicationStatus, 4);
    //_worldPacket.FlushBits();

    return &_worldPacket;
}

WorldPacket const* WorldPackets::LfgList::LfgListGroupInviteResponce::Write()
{
    _worldPacket << ApplicantTicket;
    _worldPacket << uint8(0);
    _worldPacket << uint8(0);
    //_worldPacket << ApplicationTicket;
    //_worldPacket << InviteExpireTimer;
    //_worldPacket << Status;
    //_worldPacket << Role;
    //_worldPacket.WriteBits(ApplicationStatus, 4);
    //_worldPacket.FlushBits();

    return &_worldPacket;
}

void WorldPackets::LfgList::LfgListSearch::Read()
{
    SearchFilterNum = _worldPacket.ReadBits(6);
    _worldPacket >> GroupFinderCategoryId;
    _worldPacket >> SubActivityGroupID;
    _worldPacket >> LFGListFilter;
    _worldPacket >> LanguageFilter;
}

WorldPacket const* WorldPackets::LfgList::LfgListSearchResults::Write()
{
    _worldPacket << uint16(Entries.size());
    _worldPacket << uint32(Entries.size());

    for (const auto& entry : Entries)
    {
        _worldPacket << entry.Ticket;

        _worldPacket << uint32(entry.SequenceNum);

        _worldPacket << uint8(entry.Unk);

        _worldPacket << entry.Leader;
        _worldPacket << entry.LastTouchedAny;
        _worldPacket << entry.LastTouchedName;
        _worldPacket << entry.LastTouchedComment;
        _worldPacket << entry.LastTouchedVoiceChat;

        _worldPacket << uint32(entry.VirtualRealmAddress);

        _worldPacket << uint32(entry.Unk2);
        _worldPacket << uint32(entry.BnetFriends);
        _worldPacket << uint32(entry.CharFriends);
        _worldPacket << uint32(entry.GuildMates);
        _worldPacket << uint32(entry.Unk3);
        _worldPacket << uint32(entry.MemberCount);

        _worldPacket << uint32(entry.CompletedEncountersMask);
        _worldPacket << uint32(entry.CreationTime);
        _worldPacket << uint32(entry.Unk4);
        _worldPacket << uint8(entry.Unk5);

        _worldPacket << entry.PartyGUID;

        // TODO:
#if 0
        for (uint8 i = 0; i < entry.BnetFriends; i++)
            _worldPacket << GUID;

        for (uint8 i = 0; i < entry.CharFriends; i++)
            _worldPacket << GUID;

        for (uint8 i = 0; i < entry.GuildMates; i++)
            _worldPacket << GUID;
#endif

        for (uint8 i = 0; i != entry.Unknown.size(); ++i)
       {
            _worldPacket << uint32(entry.Unknown[i].Unk6);
            _worldPacket << uint8(entry.Unknown[i].Unk7);
        }

        // Lfg join request
        {
            _worldPacket << int32(0x5);

            _worldPacket << int32(entry.GroupFinderActivityId);

            _worldPacket << int32(entry.RequiredItemLevel);

            _worldPacket << int32(entry.RequiredHonorLevel);

            _worldPacket.WriteBits(entry.Name.size(), 10);
            _worldPacket.WriteBits(entry.Comment.size(), 11);
            _worldPacket.WriteBits(entry.Voice.size(), 8);

            _worldPacket.WriteBit(entry.AutoAccept);
            _worldPacket.WriteBit(entry.IsPrivate);
            _worldPacket.WriteBit(entry.QuestID.has_value());

            _worldPacket.FlushBits();

            _worldPacket << uint8(entry.Unk16);

            _worldPacket.WriteString(entry.Name);
            _worldPacket.WriteString(entry.Comment);
            _worldPacket.WriteString(entry.Voice);

            if (entry.QuestID.has_value())
                _worldPacket << uint32(*entry.QuestID);
        }

        _worldPacket << uint8(entry.Unk8);
        _worldPacket << int32(entry.Unk9);
        _worldPacket << int32(entry.Unk10);
        _worldPacket << int32(entry.Unk11);
        _worldPacket << uint8(entry.Unk12);

        for (uint8 i = 0; i != entry.Members.size(); ++i)
        {
            _worldPacket << entry.Members[i].Member;
            _worldPacket << uint8(entry.Members[i].Level);
            _worldPacket << uint8(entry.Members[i].Class);
            _worldPacket << uint8(entry.Members[i].Role);

            _worldPacket << uint32(entry.Members[i].Unk13);
            _worldPacket << uint16(entry.Members[i].Unk14);
        }
    }

    return &_worldPacket;
}

void WorldPackets::LfgList::LfgListUpdateRequest::Read()
{
    _worldPacket >> Ticket;
    _worldPacket >> UpdateRequest;
}

void WorldPackets::LfgList::LfgListApplyToGroup::Read()
{
    _worldPacket >> application.ApplicationTicket;
    _worldPacket >> application.ActivityID;
    application.Role = _worldPacket.read<uint8>();
    application.Comment = _worldPacket.ReadString(_worldPacket.ReadBits(8));
}

void WorldPackets::LfgList::LfgListCancelApplication::Read()
{
    _worldPacket >> ApplicantTicket;
}

void WorldPackets::LfgList::LfgListDeclineApplicant::Read()
{
    _worldPacket >> ApplicantTicket;
    _worldPacket >> ApplicationTicket;
}

WorldPacket const* WorldPackets::LfgList::LfgListApplicationUpdate::Write()
{
    _worldPacket << ApplicantTicket;

    int32 unk0 { 0 }, unk1 {0};
    int16 unk2 { 2108 };

    _worldPacket << unk0;
    _worldPacket << unk1;
    _worldPacket << unk2;

    _worldPacket << ApplicationTicket;

    _worldPacket << uint8(ApplicationStatus);

    return &_worldPacket;
}

WorldPacket const* WorldPackets::LfgList::LfgListApplicantListUpdate::Write()
{
    //Player* sylea = ObjectAccessor::FindPlayerByName("Sylea");
    //Player* jed = ObjectAccessor::FindPlayerByName("Jed");
    
    //auto ticket = sLFGMgr->GetTicket(sylea->GetGUID());

    _worldPacket << ApplicationTicket;

    _worldPacket << uint32(1);
    _worldPacket << uint32(6);

    _worldPacket << ApplicantTicket;
    /*_worldPacket << jed->GetGUID();
    _worldPacket << uint32(jed->GetGUID().GetCounter());
    _worldPacket << uint32(6);
    _worldPacket << GameTime::GetGameTime();
    _worldPacket.WriteBit(false);
    _worldPacket.FlushBits();*/

    _worldPacket << ApplicantTicket.RequesterGuid;
    _worldPacket << uint32(1);

    _worldPacket << uint8(0x18);
    _worldPacket << uint8(0x18);

    _worldPacket << ApplicantTicket.RequesterGuid;

    _worldPacket << uint32(GetVirtualRealmAddress());

    _worldPacket << uint32(80);
    _worldPacket << uint32(0);
    _worldPacket << uint32(1342177288);
    _worldPacket << uint32(1067729786);
    _worldPacket << uint32(17281);
    _worldPacket << uint16(0);

    for (int i = 0; i != 7; ++i)
    {
        _worldPacket << uint32(0);
        _worldPacket << uint8(0xFF);
    }

    _worldPacket << uint32(1211001008);
    _worldPacket << uint32(32630);

    _worldPacket << uint32(0);
    _worldPacket << uint32(0);
    _worldPacket << uint32(0);

    _worldPacket << uint8(0);
    _worldPacket << uint8(0);
    _worldPacket << uint8(0);

    return &_worldPacket;
}