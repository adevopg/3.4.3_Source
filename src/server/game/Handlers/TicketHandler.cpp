/*
 * This file is part of the TrinityCore Project. See AUTHORS file for Copyright information
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "WorldSession.h"
#include "Common.h"
#include "DatabaseEnv.h"
#include "SupportMgr.h"
#include "TicketPackets.h"
#include "Player.h"
#include "Random.h"
#include <ctime>
#include <sstream>

std::string WorldSession::RefreshSupportToken()
{
    uint32 const accountId = GetAccountId();
    uint64 issued = uint64(time(nullptr));
    uint64 expiry = issued + 14400;

    std::ostringstream tok;
    tok << "SP-" << accountId << "-" << uint32(issued) << "-" << urand(100000, 999999);
    std::string token = tok.str();
    std::string tokEsc = token; LoginDatabase.EscapeString(tokEsc);
    // Guardamos la IP del jugador: el navegador de soporte abre www.inna.cl/s SIN
    // token y la web lo auto-loguea emparejando esta IP con el token. SÍNCRONO
    // (DirectPExecute) para que esté commiteado antes de que el navegador llegue;
    // battlepay_sso no tiene contención de locks, así que es seguro en el hilo World.
    std::string ip = GetRemoteAddress(); LoginDatabase.EscapeString(ip);
    LoginDatabase.DirectPExecute(
        "INSERT INTO battlepay_sso (account_id, token, issued_at, expiry_at, client_ip) VALUES ({}, '{}', {}, {}, '{}') "
        "ON DUPLICATE KEY UPDATE token = VALUES(token), issued_at = VALUES(issued_at), expiry_at = VALUES(expiry_at), client_ip = VALUES(client_ip)",
        accountId, tokEsc, issued, expiry, ip);
    return token;
}

void WorldSession::HandleGMTicketGetCaseStatusOpcode(WorldPackets::Ticket::GMTicketGetCaseStatus& /*packet*/)
{
    WorldPackets::Ticket::GMTicketCaseStatus response;

    // Refrescamos el token (y la IP) y mandamos un caso cuya Url apunta a nuestro
    // portal autenticado (el "open your ticket" lleva el token directo).
    std::string token = RefreshSupportToken();

    WorldPackets::Ticket::GMTicketCaseStatus::GMTicketCase c;
    c.CaseID = 1;
    c.CaseStatus = 1;
    c.CfgRealmID = 1;
    c.CharacterID = GetPlayer() ? GetPlayer()->GetGUID().GetCounter() : 0;
    c.WaitTimeOverrideMinutes = 0;
    c.Url = "https://www.inna.cl/login/sso?dest=soporte&token=" + token;
    response.Cases.push_back(c);

    SendPacket(response.Write());

    TC_LOG_INFO("server.BattlePay", "SMSG_GM_TICKET_CASE_STATUS Url={} | cuenta {}", c.Url, GetAccountId());
}

void WorldSession::HandleGMTicketSystemStatusOpcode(WorldPackets::Ticket::GMTicketGetSystemStatus& /*packet*/)
{
    // Status=1 FIJO -> habilita el soporte (sin depender del config).
    // Refrescamos el token aquí también (se pide al abrir la ayuda, antes del case).
    RefreshSupportToken();

    WorldPackets::Ticket::GMTicketSystemStatus response;
    response.Status = 1;
    SendPacket(response.Write());

    TC_LOG_INFO("server.BattlePay", "SMSG_GM_TICKET_SYSTEM_STATUS Status=1 | cuenta {}", GetAccountId());
}

void WorldSession::HandleSubmitUserFeedback(WorldPackets::Ticket::SubmitUserFeedback& userFeedback)
{
    if (userFeedback.IsSuggestion)
    {
        if (!sSupportMgr->GetSuggestionSystemStatus())
            return;

        SuggestionTicket* ticket = new SuggestionTicket(GetPlayer());
        ticket->SetPosition(userFeedback.Header.MapID, userFeedback.Header.Position);
        ticket->SetFacing(userFeedback.Header.Facing);
        ticket->SetNote(userFeedback.Note);

        sSupportMgr->AddTicket(ticket);
    }
    else
    {
        if (!sSupportMgr->GetBugSystemStatus())
            return;

        BugTicket* ticket = new BugTicket(GetPlayer());
        ticket->SetPosition(userFeedback.Header.MapID, userFeedback.Header.Position);
        ticket->SetFacing(userFeedback.Header.Facing);
        ticket->SetNote(userFeedback.Note);

        sSupportMgr->AddTicket(ticket);
    }
}

void WorldSession::HandleSupportTicketSubmitComplaint(WorldPackets::Ticket::SupportTicketSubmitComplaint& packet)
{
    if (!sSupportMgr->GetComplaintSystemStatus())
        return;

    ComplaintTicket* comp = new ComplaintTicket(GetPlayer());
    comp->SetPosition(packet.Header.MapID, packet.Header.Position);
    comp->SetFacing(packet.Header.Facing);
    comp->SetChatLog(packet.ChatLog);
    comp->SetTargetCharacterGuid(packet.TargetCharacterGUID);
    comp->SetReportType(ReportType(packet.ReportType));
    comp->SetMajorCategory(ReportMajorCategory(packet.MajorCategory));
    comp->SetMinorCategoryFlags(ReportMinorCategory(packet.MinorCategoryFlags));
    comp->SetNote(packet.Note);

    sSupportMgr->AddTicket(comp);
}

void WorldSession::HandleBugReportOpcode(WorldPackets::Ticket::BugReport& bugReport)
{
    // Note: There is no way to trigger this with standard UI except /script ReportBug("text")
    if (!sSupportMgr->GetBugSystemStatus())
        return;

    CharacterDatabasePreparedStatement* stmt = CharacterDatabase.GetPreparedStatement(CHAR_INS_BUG_REPORT);
    stmt->setString(0, bugReport.Text);
    stmt->setString(1, bugReport.DiagInfo);
    CharacterDatabase.Execute(stmt);
}

void WorldSession::HandleComplaint(WorldPackets::Ticket::Complaint& packet)
{    // NOTE: all chat messages from this spammer are automatically ignored by the spam reporter until logout in case of chat spam.
     // if it's mail spam - ALL mails from this spammer are automatically removed by client

    WorldPackets::Ticket::ComplaintResult result;
    result.ComplaintType = packet.ComplaintType;
    result.Result = 0;
    SendPacket(result.Write());
}
