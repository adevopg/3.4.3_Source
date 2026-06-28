#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "BnetServerWindow.h"
#include <shellapi.h>
#include <richedit.h>
#include <commctrl.h>
#include <functional>
#include <string>
#include <atomic>
#include <ctime>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Comctl32.lib")

namespace BnetServerWindow
{
    // =========================================================================
    // Palette
    // =========================================================================
    static const COLORREF CLR_BG     = RGB( 13,  14,  22);
    static const COLORREF CLR_CARD   = RGB( 22,  25,  40);
    static const COLORREF CLR_BORDER = RGB( 45,  50,  75);
    static const COLORREF CLR_TEXT   = RGB(210, 215, 235);
    static const COLORREF CLR_MUTED  = RGB(100, 108, 140);
    static const COLORREF CLR_GREEN  = RGB( 50, 215,  90);
    static const COLORREF CLR_RED    = RGB(220,  65,  65);
    static const COLORREF CLR_YELLOW = RGB(255, 195,  45);
    static const COLORREF CLR_ACCENT = RGB( 90, 140, 255);
    static const COLORREF CLR_LOGBG  = RGB( 10,  10,  17);

    // =========================================================================
    // Message IDs / control IDs
    // =========================================================================
    static constexpr UINT WM_TRAYICON  = WM_APP + 1;
    static constexpr UINT WM_APPENDLOG = WM_APP + 2;
    static constexpr UINT WM_SRVSTOP   = WM_APP + 3;
    static constexpr UINT ID_TRAY      = 1001;
    static constexpr UINT ID_SHOW      = 2001;
    static constexpr UINT ID_STOP      = 2002;
    static constexpr UINT ID_EXIT      = 2003;
    static constexpr UINT ID_CLEAR     = 2004;
    static constexpr UINT ID_OPENLOG   = 2005;
    static constexpr UINT ID_FILTER    = 2006;
    static constexpr UINT ID_TIMER     = 3001;
    static constexpr char k_Class[]    = "BnetServerGUI";
    static constexpr char k_ConsClass[]= "BnetConsolePanel";
    static constexpr char k_MgrClass[] = "BnetManagePanel";

    // =========================================================================
    // Global state
    // =========================================================================
    static HWND   g_hWnd      = nullptr;
    static HWND   g_hTabCtrl  = nullptr;
    static HWND   g_hConsPane = nullptr;
    static HWND   g_hMgrPane  = nullptr;
    static HWND   g_hLog      = nullptr;
    static HWND   g_hFilter   = nullptr;
    static HWND   g_hStatus   = nullptr;
    static HWND   g_hStopBtn  = nullptr;
    static HWND   g_hOpenBtn  = nullptr;
    static HINSTANCE g_hInst  = nullptr;
    static NOTIFYICONDATAA g_nid = {};
    static std::atomic<bool> g_stopping = false;
    static std::atomic<int>  g_logLines = 0;
    static std::atomic<int>  g_sessions = 0;
    static LogLevel g_minLevel = LOG_LEVEL_DEBUG;
    static std::function<void()> g_onStop;
    static time_t  g_startTime = 0;
    static int     g_bnetPort  = 1119;
    static int     g_httpPort  = 8081;
    static int     g_tactPort  = 8082;
    static std::string g_logsDir;

    static HFONT g_hFontUI   = nullptr;
    static HFONT g_hFontBold = nullptr;
    static HFONT g_hFontBig  = nullptr;
    static HFONT g_hFontMono = nullptr;

    struct LogEntry { LogLevel level; std::string text; };

    // =========================================================================
    // Helpers
    // =========================================================================
    static HFONT MakeFont(int pt, bool bold, char const* face = "Segoe UI")
    {
        return CreateFontA(-MulDiv(pt, 96, 72), 0, 0, 0,
            bold ? FW_BOLD : FW_NORMAL,
            FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, face);
    }

    static COLORREF ColorForLevel(LogLevel level)
    {
        switch (level)
        {
            case LOG_LEVEL_TRACE: return RGB( 80,  85, 105);
            case LOG_LEVEL_DEBUG: return RGB(130, 135, 165);
            case LOG_LEVEL_INFO:  return RGB(200, 208, 228);
            case LOG_LEVEL_WARN:  return CLR_YELLOW;
            case LOG_LEVEL_ERROR: return CLR_RED;
            case LOG_LEVEL_FATAL: return RGB(255,  40, 100);
            default:              return CLR_TEXT;
        }
    }

    static void GetUptimeStr(char* buf, size_t sz)
    {
        if (!g_startTime) { strcpy_s(buf, sz, "N/A"); return; }
        long long e = (long long)(time(nullptr) - g_startTime);
        long long h = e / 3600, m = (e % 3600) / 60, s = e % 60;
        if (h > 0) sprintf_s(buf, sz, "%02lluh %02llum %02llus", h, m, s);
        else        sprintf_s(buf, sz, "%02llum %02llus", m, s);
    }

    // =========================================================================
    // Status bar
    // =========================================================================
    static void UpdateStatusBar()
    {
        if (!g_hStatus) return;
        SendMessageA(g_hStatus, SB_SETTEXTA, 0,
            (LPARAM)(g_stopping ? "  Deteniendo..." : "  Corriendo"));
        char buf[64];
        sprintf_s(buf, "  Logs: %d", g_logLines.load());
        SendMessageA(g_hStatus, SB_SETTEXTA, 1, (LPARAM)buf);
        GetUptimeStr(buf, _countof(buf));
        std::string up = std::string("  Uptime: ") + buf;
        SendMessageA(g_hStatus, SB_SETTEXTA, 2, (LPARAM)up.c_str());
    }

    // =========================================================================
    // Console panel
    // =========================================================================
    static void AppendToRichEdit(LogLevel level, std::string const& text)
    {
        if (!g_hLog) return;
        CHARRANGE cr = { -1, -1 };
        SendMessageA(g_hLog, EM_EXSETSEL, 0, (LPARAM)&cr);
        CHARFORMATA cf = {};
        cf.cbSize      = sizeof(cf);
        cf.dwMask      = CFM_COLOR | CFM_FACE | CFM_SIZE | CFM_BOLD;
        cf.crTextColor = ColorForLevel(level);
        cf.yHeight     = 160;
        cf.dwEffects   = 0;
        strcpy_s(cf.szFaceName, "Consolas");
        SendMessageA(g_hLog, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
        std::string line = text + "\r\n";
        SendMessageA(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());
        int lines = (int)SendMessageA(g_hLog, EM_GETLINECOUNT, 0, 0);
        if (lines > 8500)
        {
            int end500 = (int)SendMessageA(g_hLog, EM_LINEINDEX, 500, 0);
            CHARRANGE del = { 0, end500 };
            SendMessageA(g_hLog, EM_EXSETSEL, 0, (LPARAM)&del);
            SendMessageA(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)"");
            g_logLines -= 500;
            if (g_logLines < 0) g_logLines = 0;
        }
        ++g_logLines;
        UpdateStatusBar();
    }

    static LRESULT CALLBACK ConsolePanelProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        switch (msg)
        {
            case WM_CREATE:
            {
                g_hFilter = CreateWindowA("COMBOBOX", nullptr,
                    WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                    8, 5, 130, 200, hWnd, (HMENU)(UINT_PTR)ID_FILTER, g_hInst, nullptr);
                SendMessageA(g_hFilter, CB_ADDSTRING, 0, (LPARAM)"Todos");
                SendMessageA(g_hFilter, CB_ADDSTRING, 0, (LPARAM)"Debug");
                SendMessageA(g_hFilter, CB_ADDSTRING, 0, (LPARAM)"Info");
                SendMessageA(g_hFilter, CB_ADDSTRING, 0, (LPARAM)"Avisos");
                SendMessageA(g_hFilter, CB_ADDSTRING, 0, (LPARAM)"Errores");
                SendMessageA(g_hFilter, CB_SETCURSEL, 0, 0);

                CreateWindowA("BUTTON", "Limpiar",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    146, 5, 72, 24, hWnd, (HMENU)(UINT_PTR)ID_CLEAR, g_hInst, nullptr);

                g_hLog = CreateWindowExA(0, "RICHEDIT50W", nullptr,
                    WS_CHILD | WS_VISIBLE | WS_VSCROLL |
                    ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_NOHIDESEL,
                    0, 34, 100, 100, hWnd, nullptr, g_hInst, nullptr);
                SendMessageA(g_hLog, EM_SETLIMITTEXT, (WPARAM)-1, 0);
                SendMessageA(g_hLog, EM_SETBKGNDCOLOR, 0, CLR_LOGBG);
                return 0;
            }
            case WM_SIZE:
            {
                RECT rc; GetClientRect(hWnd, &rc);
                if (g_hLog) MoveWindow(g_hLog, 0, 34, rc.right, rc.bottom - 34, TRUE);
                return 0;
            }
            case WM_ERASEBKGND:
            {
                RECT rc; GetClientRect(hWnd, &rc);
                HBRUSH br = CreateSolidBrush(RGB(18, 19, 28));
                FillRect((HDC)wParam, &rc, br);
                DeleteObject(br);
                return 1;
            }
            case WM_COMMAND:
                if (LOWORD(wParam) == ID_CLEAR && g_hLog)
                {
                    SetWindowTextA(g_hLog, "");
                    g_logLines = 0;
                    UpdateStatusBar();
                }
                else if (LOWORD(wParam) == ID_FILTER && HIWORD(wParam) == CBN_SELCHANGE)
                {
                    static const LogLevel kLevels[] = {
                        LOG_LEVEL_DEBUG, LOG_LEVEL_DEBUG, LOG_LEVEL_INFO,
                        LOG_LEVEL_WARN, LOG_LEVEL_ERROR };
                    int sel = (int)SendMessageA(g_hFilter, CB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < 5) g_minLevel = kLevels[sel];
                }
                return 0;
        }
        return DefWindowProcA(hWnd, msg, wParam, lParam);
    }

    // =========================================================================
    // Management panel — custom painted
    // =========================================================================
    static void DrawLabel(HDC hdc, int x, int y, int w, int h,
                          char const* label, char const* value, COLORREF valColor)
    {
        RECT lr = { x, y, x + 140, y + h };
        SetTextColor(hdc, CLR_MUTED);
        SelectObject(hdc, g_hFontUI);
        DrawTextA(hdc, label, -1, &lr, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        RECT vr = { x + 140, y, x + w, y + h };
        SetTextColor(hdc, valColor);
        SelectObject(hdc, g_hFontBold);
        DrawTextA(hdc, value, -1, &vr, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    }

    static void DrawCard(HDC hdc, RECT rc, char const* heading)
    {
        HBRUSH brCard = CreateSolidBrush(CLR_CARD);
        FillRect(hdc, &rc, brCard);
        DeleteObject(brCard);
        HBRUSH brBdr = CreateSolidBrush(CLR_BORDER);
        FrameRect(hdc, &rc, brBdr);
        DeleteObject(brBdr);
        if (heading && heading[0])
        {
            RECT hr = { rc.left + 10, rc.top + 7, rc.right - 10, rc.top + 24 };
            SetTextColor(hdc, CLR_MUTED);
            SelectObject(hdc, g_hFontBold);
            DrawTextA(hdc, heading, -1, &hr, DT_LEFT | DT_SINGLELINE);
        }
    }

    static LRESULT CALLBACK ManagePanelProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        switch (msg)
        {
            case WM_CREATE:
                g_hStopBtn = CreateWindowA("BUTTON", "Detener Servidor",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 162, 30, hWnd, (HMENU)(UINT_PTR)ID_STOP, g_hInst, nullptr);
                g_hOpenBtn = CreateWindowA("BUTTON", "Abrir Carpeta de Logs",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 182, 30, hWnd, (HMENU)(UINT_PTR)ID_OPENLOG, g_hInst, nullptr);
                return 0;

            case WM_SIZE:
            {
                RECT rc; GetClientRect(hWnd, &rc);
                int ay = rc.bottom - 56;
                if (g_hStopBtn) MoveWindow(g_hStopBtn, 16, ay, 162, 30, TRUE);
                if (g_hOpenBtn) MoveWindow(g_hOpenBtn, 194, ay, 182, 30, TRUE);
                InvalidateRect(hWnd, nullptr, TRUE);
                return 0;
            }

            case WM_ERASEBKGND:
            {
                RECT rc; GetClientRect(hWnd, &rc);
                HBRUSH br = CreateSolidBrush(CLR_BG);
                FillRect((HDC)wParam, &rc, br);
                DeleteObject(br);
                return 1;
            }

            case WM_PAINT:
            {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hWnd, &ps);
                RECT rc; GetClientRect(hWnd, &rc);

                // Double-buffer to avoid flicker
                HDC mdc = CreateCompatibleDC(hdc);
                HBITMAP bmp = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
                HGDIOBJ old = SelectObject(mdc, bmp);

                HBRUSH brBg = CreateSolidBrush(CLR_BG);
                FillRect(mdc, &rc, brBg);
                DeleteObject(brBg);
                SetBkMode(mdc, TRANSPARENT);

                int M = 16, G = 10;
                int W = rc.right - 2 * M;
                bool running = !g_stopping;

                // ---- Card 1: Estado del servidor ----
                RECT c1 = { M, M, rc.right - M, M + 98 };
                DrawCard(mdc, c1, "ESTADO DEL SERVIDOR");

                // Status dot
                HBRUSH brDot = CreateSolidBrush(running ? CLR_GREEN : CLR_RED);
                HPEN   penNul = (HPEN)GetStockObject(NULL_PEN);
                SelectObject(mdc, brDot);
                SelectObject(mdc, penNul);
                Ellipse(mdc, M + 10, M + 34, M + 28, M + 52);
                DeleteObject(brDot);

                // Big status text
                SelectObject(mdc, g_hFontBig);
                SetTextColor(mdc, running ? CLR_GREEN : CLR_RED);
                RECT stRc = { M + 36, M + 30, c1.right - 10, M + 58 };
                DrawTextA(mdc, running ? "CORRIENDO" : "DETENIDO", -1, &stRc, DT_LEFT | DT_SINGLELINE);

                // Start time
                if (g_startTime)
                {
                    struct tm tm; localtime_s(&tm, &g_startTime);
                    char buf[80];
                    sprintf_s(buf, "Iniciado: %02d/%02d/%04d a las %02d:%02d:%02d",
                        tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900,
                        tm.tm_hour, tm.tm_min, tm.tm_sec);
                    SelectObject(mdc, g_hFontUI);
                    SetTextColor(mdc, CLR_MUTED);
                    RECT tr = { M + 36, M + 62, c1.right - 10, M + 80 };
                    DrawTextA(mdc, buf, -1, &tr, DT_LEFT | DT_SINGLELINE);
                }

                // ---- Card 2: Red (left) / Card 3: Stats (right) ----
                int halfW = (W - G) / 2;
                int row2y  = c1.bottom + G;

                RECT c2 = { M, row2y, M + halfW, row2y + 115 };
                DrawCard(mdc, c2, "CONFIGURACION DE RED");
                char pb[32];
                sprintf_s(pb, "%d", g_bnetPort);
                DrawLabel(mdc, c2.left+10, c2.top+30, halfW-20, 22, "Puerto BNet:", pb, CLR_ACCENT);
                sprintf_s(pb, "%d", g_httpPort);
                DrawLabel(mdc, c2.left+10, c2.top+56, halfW-20, 22, "Puerto HTTP:", pb, CLR_ACCENT);
                if (g_tactPort > 0) sprintf_s(pb, "%d", g_tactPort); else strcpy_s(pb, "N/A");
                DrawLabel(mdc, c2.left+10, c2.top+82, halfW-20, 22, "Puerto TACT:", pb, CLR_ACCENT);

                RECT c3 = { M + halfW + G, row2y, rc.right - M, row2y + 115 };
                DrawCard(mdc, c3, "ESTADISTICAS");
                char upBuf[64]; GetUptimeStr(upBuf, _countof(upBuf));
                DrawLabel(mdc, c3.left+10, c3.top+30, c3.right-c3.left-20, 22, "Tiempo activo:", upBuf, CLR_TEXT);
                char lb[32]; sprintf_s(lb, "%d", g_logLines.load());
                DrawLabel(mdc, c3.left+10, c3.top+56, c3.right-c3.left-20, 22, "Lineas de log:", lb, CLR_TEXT);
                char sb[32]; sprintf_s(sb, "%d", g_sessions.load());
                DrawLabel(mdc, c3.left+10, c3.top+82, c3.right-c3.left-20, 22, "Sesiones activas:", sb, CLR_TEXT);

                // ---- Actions heading ----
                RECT ah = { M, c2.bottom + G, rc.right - M, c2.bottom + G + 22 };
                SelectObject(mdc, g_hFontBold);
                SetTextColor(mdc, CLR_MUTED);
                DrawTextA(mdc, "ACCIONES", -1, &ah, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

                BitBlt(hdc, 0, 0, rc.right, rc.bottom, mdc, 0, 0, SRCCOPY);
                SelectObject(mdc, old);
                DeleteObject(bmp);
                DeleteDC(mdc);
                EndPaint(hWnd, &ps);
                return 0;
            }

            case WM_COMMAND:
                if (LOWORD(wParam) == ID_STOP)
                    PostMessageA(GetParent(hWnd), WM_COMMAND, MAKEWPARAM(ID_STOP, 0), 0);
                else if (LOWORD(wParam) == ID_OPENLOG)
                {
                    std::string dir = g_logsDir.empty() ? "." : g_logsDir;
                    ShellExecuteA(nullptr, "open", dir.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
                }
                return 0;
        }
        return DefWindowProcA(hWnd, msg, wParam, lParam);
    }

    // =========================================================================
    // Tab layout helpers
    // =========================================================================
    static void LayoutPanels()
    {
        if (!g_hWnd) return;
        RECT rc; GetClientRect(g_hWnd, &rc);

        // Status bar height
        int sbH = 0;
        if (g_hStatus)
        {
            RECT sbRc; GetWindowRect(g_hStatus, &sbRc);
            sbH = sbRc.bottom - sbRc.top;
        }

        // Tab control strip
        int tabH = 30;
        if (g_hTabCtrl) MoveWindow(g_hTabCtrl, 0, 0, rc.right, tabH, TRUE);

        // Content area
        int cy = tabH + 1, ch = rc.bottom - tabH - 1 - sbH;
        if (g_hConsPane) MoveWindow(g_hConsPane, 0, cy, rc.right, ch, TRUE);
        if (g_hMgrPane)  MoveWindow(g_hMgrPane,  0, cy, rc.right, ch, TRUE);
    }

    static void SwitchTab(int idx)
    {
        ShowWindow(g_hConsPane, idx == 0 ? SW_SHOW : SW_HIDE);
        ShowWindow(g_hMgrPane,  idx == 1 ? SW_SHOW : SW_HIDE);
        if (idx == 1) InvalidateRect(g_hMgrPane, nullptr, TRUE);
    }

    // =========================================================================
    // Tray menu
    // =========================================================================
    static void ShowTrayMenu()
    {
        POINT pt; GetCursorPos(&pt);
        HMENU hm = CreatePopupMenu();
        bool vis = IsWindowVisible(g_hWnd) != FALSE;
        AppendMenuA(hm, MF_STRING, ID_SHOW, vis ? "Ocultar ventana" : "Mostrar ventana");
        AppendMenuA(hm, MF_SEPARATOR, 0, nullptr);
        AppendMenuA(hm, MF_STRING | (g_stopping ? MF_GRAYED : 0), ID_STOP, "Detener servidor");
        AppendMenuA(hm, MF_SEPARATOR, 0, nullptr);
        AppendMenuA(hm, MF_STRING, ID_EXIT, "Salir");
        SetForegroundWindow(g_hWnd);
        TrackPopupMenuEx(hm, TPM_RIGHTALIGN | TPM_BOTTOMALIGN, pt.x, pt.y, g_hWnd, nullptr);
        DestroyMenu(hm);
    }

    // =========================================================================
    // Main window proc
    // =========================================================================
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        switch (msg)
        {
            case WM_CREATE:
            {
                // Tab control
                g_hTabCtrl = CreateWindowExA(0, WC_TABCONTROLA, nullptr,
                    WS_CHILD | WS_VISIBLE | TCS_FIXEDWIDTH,
                    0, 0, 0, 0, hWnd, nullptr, g_hInst, nullptr);
                TCITEMA ti = {}; ti.mask = TCIF_TEXT;
                ti.pszText = const_cast<char*>("   Consola   ");
                TabCtrl_InsertItem(g_hTabCtrl, 0, &ti);
                ti.pszText = const_cast<char*>("   Gestion   ");
                TabCtrl_InsertItem(g_hTabCtrl, 1, &ti);

                // Console content panel
                g_hConsPane = CreateWindowExA(0, k_ConsClass, nullptr,
                    WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                    0, 0, 0, 0, hWnd, nullptr, g_hInst, nullptr);

                // Management content panel (hidden until tab selected)
                g_hMgrPane = CreateWindowExA(0, k_MgrClass, nullptr,
                    WS_CHILD | WS_CLIPSIBLINGS,
                    0, 0, 0, 0, hWnd, nullptr, g_hInst, nullptr);

                // Status bar
                g_hStatus = CreateStatusWindowA(
                    WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                    nullptr, hWnd, 0);

                // Tray
                g_nid.cbSize           = sizeof(g_nid);
                g_nid.hWnd             = hWnd;
                g_nid.uID              = ID_TRAY;
                g_nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
                g_nid.uCallbackMessage = WM_TRAYICON;
                g_nid.hIcon            = LoadIconA(nullptr, IDI_APPLICATION);
                strcpy_s(g_nid.szTip, "BnetServer - Corriendo");
                Shell_NotifyIconA(NIM_ADD, &g_nid);

                SetTimer(hWnd, ID_TIMER, 1000, nullptr);
                return 0;
            }

            case WM_SIZE:
            {
                if (g_hStatus)
                {
                    SendMessageA(g_hStatus, WM_SIZE, 0, 0);
                    RECT rc; GetClientRect(hWnd, &rc);
                    int parts[3] = { rc.right * 30/100, rc.right * 60/100, -1 };
                    SendMessageA(g_hStatus, SB_SETPARTS, 3, (LPARAM)parts);
                }
                LayoutPanels();
                UpdateStatusBar();
                return 0;
            }

            case WM_TIMER:
                if (wParam == ID_TIMER)
                {
                    UpdateStatusBar();
                    if (g_hMgrPane && IsWindowVisible(g_hMgrPane))
                        InvalidateRect(g_hMgrPane, nullptr, FALSE);
                }
                return 0;

            case WM_NOTIFY:
            {
                NMHDR* nm = reinterpret_cast<NMHDR*>(lParam);
                if (nm->hwndFrom == g_hTabCtrl && nm->code == TCN_SELCHANGE)
                    SwitchTab(TabCtrl_GetCurSel(g_hTabCtrl));
                return 0;
            }

            case WM_COMMAND:
                switch (LOWORD(wParam))
                {
                    case ID_SHOW:
                        ShowWindow(hWnd, IsWindowVisible(hWnd) ? SW_HIDE : SW_SHOW);
                        break;
                    case ID_STOP:
                        if (!g_stopping.exchange(true))
                        {
                            UpdateTitle("Deteniendo...");
                            strcpy_s(g_nid.szTip, "BnetServer - Deteniendo");
                            Shell_NotifyIconA(NIM_MODIFY, &g_nid);
                            UpdateStatusBar();
                            if (g_onStop) g_onStop();
                        }
                        break;
                    case ID_EXIT:
                        if (!g_stopping.exchange(true) && g_onStop) g_onStop();
                        Shell_NotifyIconA(NIM_DELETE, &g_nid);
                        DestroyWindow(hWnd);
                        break;
                }
                return 0;

            case WM_TRAYICON:
                if      (lParam == WM_RBUTTONUP)      ShowTrayMenu();
                else if (lParam == WM_LBUTTONDBLCLK)  ShowWindow(hWnd, IsWindowVisible(hWnd) ? SW_HIDE : SW_SHOW);
                return 0;

            case WM_CLOSE:
                ShowWindow(hWnd, SW_HIDE);
                return 0;

            case WM_DESTROY:
                KillTimer(hWnd, ID_TIMER);
                Shell_NotifyIconA(NIM_DELETE, &g_nid);
                if (g_hFontUI)   DeleteObject(g_hFontUI);
                if (g_hFontBold) DeleteObject(g_hFontBold);
                if (g_hFontBig)  DeleteObject(g_hFontBig);
                if (g_hFontMono) DeleteObject(g_hFontMono);
                PostQuitMessage(0);
                return 0;

            case WM_SRVSTOP:
                if (!g_stopping.exchange(true)) UpdateTitle("Detenido");
                UpdateStatusBar();
                PostMessageA(hWnd, WM_CLOSE, 0, 0);
                return 0;

            case WM_APPENDLOG:
            {
                auto* e = reinterpret_cast<LogEntry*>(lParam);
                if (e) { AppendToRichEdit(e->level, e->text); delete e; }
                return 0;
            }
        }
        return DefWindowProcA(hWnd, msg, wParam, lParam);
    }

    // =========================================================================
    // Public API
    // =========================================================================
    bool Initialize(HINSTANCE hInst)
    {
        g_hInst    = hInst;
        g_startTime = time(nullptr);

        LoadLibraryA("Msftedit.dll");

        INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_BAR_CLASSES | ICC_TAB_CLASSES };
        InitCommonControlsEx(&icc);

        g_hFontUI   = MakeFont( 9, false);
        g_hFontBold = MakeFont( 9, true);
        g_hFontBig  = MakeFont(16, true);
        g_hFontMono = MakeFont( 9, false, "Consolas");

        // Register child panel classes first
        WNDCLASSEXA wc = {};
        wc.cbSize        = sizeof(wc);
        wc.hInstance     = hInst;
        wc.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
        wc.hCursor       = LoadCursorA(nullptr, IDC_ARROW);

        wc.lpfnWndProc   = ConsolePanelProc;
        wc.lpszClassName = k_ConsClass;
        RegisterClassExA(&wc);

        wc.lpfnWndProc   = ManagePanelProc;
        wc.lpszClassName = k_MgrClass;
        RegisterClassExA(&wc);

        // Main window
        wc.lpfnWndProc   = WndProc;
        wc.hIcon         = LoadIconA(nullptr, IDI_APPLICATION);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
        wc.lpszClassName = k_Class;
        if (!RegisterClassExA(&wc)) return false;

        g_hWnd = CreateWindowExA(0, k_Class, "BnetServer - Iniciando",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 1100, 720,
            nullptr, nullptr, hInst, nullptr);
        if (!g_hWnd) return false;

        // Force an initial layout pass
        RECT rc; GetClientRect(g_hWnd, &rc);
        SendMessageA(g_hWnd, WM_SIZE, SIZE_RESTORED, MAKELPARAM(rc.right, rc.bottom));

        ShowWindow(g_hWnd, SW_SHOW);
        UpdateWindow(g_hWnd);
        return true;
    }

    void Run()
    {
        MSG msg;
        while (GetMessageA(&msg, nullptr, 0, 0) > 0)
        {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }

    void AppendLog(LogLevel level, std::string const& text)
    {
        if (!g_hWnd || level < g_minLevel) return;
        PostMessageA(g_hWnd, WM_APPENDLOG, 0, (LPARAM)(new LogEntry{ level, text }));
    }

    void SetShutdownCallback(std::function<void()> cb) { g_onStop = std::move(cb); }

    void UpdateTitle(char const* status)
    {
        if (g_hWnd)
            SetWindowTextA(g_hWnd, (std::string("BnetServer - ") + status).c_str());
    }

    void SetPorts(int bnet, int http, int tact)
    {
        g_bnetPort = bnet;
        g_httpPort = http;
        g_tactPort = tact;
    }

    void SetConnectionCount(int active)
    {
        g_sessions = active;
    }

    void SetLogsDir(std::string const& dir)
    {
        g_logsDir = dir;
    }
}
#endif
