#ifndef LfgListPackets_h__
#define LfgListPackets_h__

#include "Packet.h"
#include "PacketUtilities.h"
#include "LFGPacketsCommon.h"
#include "Optional.h"
#include "LFGList.h"

namespace WorldPackets
{
    namespace LfgList
    {
        //------------------------------------------------------------------------
        // Structs
        struct LFGListBlacklist
        {
            uint32 ActivityID = 0;
            uint32 Reason = 0;
        };

        struct ListRequest
        {
            ListRequest() = default;

            Optional<uint32> QuestID;
            uint32 ActivityID = 0;
            uint32 HonorLevel = 0;
            float ItemLevel = 0.0f;
            std::string GroupName;
            std::string Comment;
            std::string VoiceChat;
            bool AutoAccept = false;
            bool PrivateGroup = false;
        };

        struct ApplicationToGroup
        {
            LFG::RideTicket ApplicationTicket;
            uint32 ActivityID = 0;
            std::string Comment;
            uint8 Role = 0;
        };

        struct MemberInfo
        {
            MemberInfo() {}
            MemberInfo(ObjectGuid guid, uint8 level, uint8 classID, uint8 role) 
                : Member(guid), Level(level), Class(classID), Role(role) {}

            ObjectGuid Member;
            uint8 Level = 1;
            uint8 Class = CLASS_WARRIOR;
            uint8 Role = 0;
            uint32 Unk13 = 0;
            uint16 Unk14 = 0;
        };

        struct ListSearchResult
        {
            LFG::RideTicket ApplicationTicket;
            ListRequest JoinRequest;
            std::vector<MemberInfo> Members;
            GuidList BNetFriendsGuids;
            GuidList NumCharFriendsGuids;
            GuidList NumGuildMateGuids;
            ObjectGuid UnkGuid1;
            ObjectGuid UnkGuid2;
            ObjectGuid UnkGuid3;
            ObjectGuid UnkGuid4;
            ObjectGuid UnkGuid5;
            uint32 VirtualRealmAddress = 0;
            uint32 CompletedEncounters = 0;
            uint32 Age = 0;
            uint32 ResultID = 0;
            uint8 ApplicationStatus = 0;
        };

        //------------------------------------------------------------------------
        // Client Packets
        class LfgListJoin final : public ClientPacket
        {
        public:
            LfgListJoin(WorldPacket&& packet) : ClientPacket(CMSG_LFG_LIST_JOIN, std::move(packet)) {}

            void Read() override;

            ListRequest Request;
        };

        class LfgListLeave final : public ClientPacket
        {
        public:
            LfgListLeave(WorldPacket&& packet) : ClientPacket(CMSG_LFG_LIST_LEAVE, std::move(packet)) {}

            void Read() override;

            LFG::RideTicket ApplicationTicket;
        };

        class RequestLfgListBlacklist final : public ClientPacket
        {
        public:
            RequestLfgListBlacklist(WorldPacket&& packet) : ClientPacket(CMSG_REQUEST_LFG_LIST_BLACKLIST, std::move(packet)) { }

            void Read() override { };
        };

        class LfgListUpdateRequest final : public ClientPacket
        {
        public:
            LfgListUpdateRequest(WorldPacket&& packet) : ClientPacket(CMSG_LFG_LIST_UPDATE_REQUEST, std::move(packet)) {}

            void Read() override;

            LFG::RideTicket Ticket;
            ListRequest UpdateRequest;
        };

        class LfgListGetStatus final : public ClientPacket
        {
        public:
            LfgListGetStatus(WorldPacket&& packet) : ClientPacket(CMSG_LFG_LIST_GET_STATUS, std::move(packet)) {}

            void Read() override {}
        };

        class LfgListApplyToGroup final : public ClientPacket
        {
        public:
            LfgListApplyToGroup(WorldPacket&& packet) : ClientPacket(CMSG_LFG_LIST_APPLY_TO_GROUP, std::move(packet)) {}

            void Read() override;

            ApplicationToGroup application;
        };

        class LfgListCancelApplication final : public ClientPacket
        {
        public:
            LfgListCancelApplication(WorldPacket&& packet) : ClientPacket(CMSG_LFG_LIST_CANCEL_APPLICATION, std::move(packet)) {}

            void Read() override;

            LFG::RideTicket ApplicantTicket;
        };

        class LfgListDeclineApplicant final : public ClientPacket
        {
        public:
            LfgListDeclineApplicant(WorldPacket&& packet) : ClientPacket(CMSG_LFG_LIST_DECLINE_APPLICANT, std::move(packet)) {}

            void Read() override;

            LFG::RideTicket ApplicantTicket;
            LFG::RideTicket ApplicationTicket;
        };








        struct LFGUnk
        {
            uint32 Unk6 = 0;
            uint8 Unk7 = 255;
        };

        struct LFGMemberResult
        {
            ObjectGuid Member;
            uint8 Level = 1;
            uint8 Class = CLASS_WARRIOR;
            uint8 Role = 0;
            uint32 Unk13 = 0;
            uint16 Unk14 = 0;
        };

        struct LFGTEMP
        {
            WorldPackets::LFG::RideTicket Ticket;

            uint32 SequenceNum = 0;
            uint8 Unk = 0;
            ObjectGuid Leader;
            ObjectGuid LastTouchedAny;
            ObjectGuid LastTouchedName;
            ObjectGuid LastTouchedComment;
            ObjectGuid LastTouchedVoiceChat;
            uint32 VirtualRealmAddress = 0;
            uint32 Unk2 = 0;
            uint32 BnetFriends = 0;
            uint32 CharFriends = 0;
            uint32 GuildMates = 0;
            uint32 Unk3 = 0;
            uint32 MemberCount = 0;
            uint32 CompletedEncountersMask = 0;
            uint32 CreationTime = 0;
            uint32 Unk4 = 0;
            uint8 Unk5 = 0;
            ObjectGuid PartyGUID;

            std::array<LFGUnk, 7> Unknown;

            int32 GroupFinderActivityId = 0;
            uint32 RequiredItemLevel = 0;
            uint32 RequiredHonorLevel = 0;
            uint32 Unk15 = 0;

            std::string Name;
            std::string Comment;
            std::string Voice;

            bool AutoAccept = false;
            bool IsPrivate = false;

            uint8 Unk16 = 0;

            Optional<uint32> QuestID;

            uint8 Unk8 = 0;
            int32 Unk9 = 0;
            int32 Unk10 = 0;
            int32 Unk11 = 0;
            uint8 Unk12 = 0;

            std::vector<LFGMemberResult> Members;
        };



      

        class LfgListSearch final : public ClientPacket
        {
        public:
            LfgListSearch(WorldPacket&& packet) : ClientPacket(CMSG_LFG_LIST_SEARCH, std::move(packet)) {}

            void Read() override;

            uint32 SearchFilterNum = 0;
            int32 GroupFinderCategoryId = 0;
            int32 SubActivityGroupID = 0;
            int32 LFGListFilter = 0;
            uint32 LanguageFilter = 0;
        };

        //------------------------------------------------------------------------
        // Server Packets

        class LfgListSearchResults final : public ServerPacket
        {
        public:
            LfgListSearchResults() : ServerPacket(SMSG_LFG_LIST_SEARCH_RESULTS, 250) {}

           WorldPacket const* Write() override;

            std::vector<LFGTEMP> Entries;
        };

        class LFGListUpdateBlacklist final : public ServerPacket
        {
       public:
            LFGListUpdateBlacklist() : ServerPacket(SMSG_LFG_LIST_UPDATE_BLACKLIST, 12) {}

            WorldPacket const* Write() override;

            std::vector<LFGListBlacklist> Blacklist;
        };

        class LfgListUpdateStatus final : public ServerPacket
        {
        public:
            LfgListUpdateStatus() : ServerPacket(SMSG_LFG_LIST_UPDATE_STATUS, 28 + 1 + 1 + 4 + 4 + 2 + 2 + 2) {}

            WorldPacket const* Write() override;

            LFG::RideTicket ApplicationTicket;
            ListRequest Request;
            uint32 ExpirationTime = 0;
            uint8 Status = 0;
            bool Listed = false;
        };

        // SMSG_LFG_LIST_APPLY_TO_GROUP_RESULT

        class LfgListApplyToGroupResponce final : public ServerPacket
        {
        public:
            LfgListApplyToGroupResponce() : ServerPacket(SMSG_LFG_LIST_APPLY_TO_GROUP_RESULT, 28 + 28 + 4 + 4 + 1 + 1 + 150) {}

            WorldPacket const* Write() override;

            ListSearchResult SearchResult;
            LFG::RideTicket ApplicantTicket;
            LFG::RideTicket ApplicationTicket;
            uint32 InviteExpireTimer = 0;
            uint8 Status = 0;
            uint8 Role = 0;
            uint8 ApplicationStatus = 0;
        };

        class LfgListGroupInviteResponce final : public ServerPacket
        {
        public:
            LfgListGroupInviteResponce() : ServerPacket(SMSG_LFG_LIST_JOIN_RESULT, 28 + 28 + 4 + 4 + 1 + 1) {}

            WorldPacket const* Write() override;

            LFG::RideTicket ApplicantTicket;
            LFG::RideTicket ApplicationTicket;
            uint32 InviteExpireTimer = 0;
            uint8 Status = 0;
            uint8 Role = 0;
            uint8 ApplicationStatus = 0;
        };

        class LfgListApplicationUpdate final : public ServerPacket
        {
        public:
            LfgListApplicationUpdate() : ServerPacket(SMSG_LFG_LIST_APPLICATION_STATUS_UPDATE, 4 + 4 + 4) {}

            WorldPacket const* Write() override;

            LFG::RideTicket ApplicantTicket;
            LFG::RideTicket ApplicationTicket;
            LFGListApplicationStatus ApplicationStatus = LFGListApplicationStatus::None;
        };

        class LfgListApplicantListUpdate final : public ServerPacket
        {
        public:
            LfgListApplicantListUpdate() : ServerPacket(SMSG_LFG_LIST_APPLICANT_LIST_UPDATE, 4 + 4 + 4) {}

            WorldPacket const* Write() override;

            LFG::RideTicket ApplicationTicket;
            LFG::RideTicket ApplicantTicket;
            uint8 Status = 0;
            bool Listed = false;
        };
    }
}

ByteBuffer& operator<<(ByteBuffer& data, WorldPackets::LfgList::ListRequest const& join);
ByteBuffer& operator>>(ByteBuffer& data, WorldPackets::LfgList::ListRequest& join);
ByteBuffer& operator<<(ByteBuffer& data, WorldPackets::LfgList::ListSearchResult const& listSearch);
ByteBuffer& operator<<(ByteBuffer& data, WorldPackets::LfgList::MemberInfo const& memberInfo);

#endif