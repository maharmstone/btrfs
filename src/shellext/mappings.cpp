#include "shellext.h"
#include "resource.h"
#include <windows.h>
#include <commctrl.h>
#include <stdexcept>

using namespace std;

static void init_dialog(HWND hwnd) {
    TCITEMW tie;
    LVCOLUMNW lvc;
    wstring uid_mappings_str, gid_mappings_str, principal_str, uid_str;

    load_string(module, IDS_MAPPINGS_UID_MAPPINGS, uid_mappings_str);
    load_string(module, IDS_MAPPINGS_GID_MAPPINGS, gid_mappings_str);
    load_string(module, IDS_MAPPINGS_PRINCIPAL, principal_str);
    load_string(module, IDS_MAPPINGS_UID, uid_str);

    auto tab = GetDlgItem(hwnd, IDC_MAPPINGS_TAB);

    memset(&tie, 0, sizeof(tie));

    tie.mask = TCIF_TEXT;
    tie.iImage = -1;
    tie.pszText = (WCHAR*)uid_mappings_str.c_str();
    SendMessageW(tab, TCM_INSERTITEMW, 0, (LPARAM)&tie);
    tie.pszText = (WCHAR*)gid_mappings_str.c_str();
    SendMessageW(tab, TCM_INSERTITEMW, 1, (LPARAM)&tie);

    auto list = GetDlgItem(hwnd, IDC_MAPPINGS_LIST);

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

    lvc.iSubItem = 0;
    lvc.pszText = (WCHAR*)principal_str.c_str();
    lvc.cx = 300;
    lvc.fmt = LVCFMT_LEFT;
    SendMessageW(list, LVM_INSERTCOLUMNW, 0, (LPARAM)&lvc);

    lvc.iSubItem = 1;
    lvc.pszText = (WCHAR*)uid_str.c_str(); // change when tab changes
    lvc.cx = 100;
    lvc.fmt = LVCFMT_LEFT;
    SendMessageW(list, LVM_INSERTCOLUMNW, 1, (LPARAM)&lvc);

    // FIXME - populate list
}

static INT_PTR CALLBACK MappingsDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    try {
        switch (uMsg) {
            case WM_INITDIALOG:
                init_dialog(hwndDlg);
                return true;

            case WM_COMMAND:
                switch (HIWORD(wParam)) {
                    case BN_CLICKED:
                        switch (LOWORD(wParam)) {
                            case IDOK:
                            case IDCANCEL:
                                EndDialog(hwndDlg, 1);
                            return true;
                        }
                    break;
                }
            break;
        }
    } catch (const exception& e) {
        error_message(hwndDlg, e.what());
    }

    return false;
}

extern "C"
void CALLBACK MappingsTest(HWND hwnd, HINSTANCE, LPWSTR, int) {
    try {
        set_dpi_aware();

        if (DialogBoxParamW(module, MAKEINTRESOURCEW(IDD_MAPPINGS), hwnd, MappingsDlgProc, 0) <= 0)
            throw last_error(GetLastError());
    } catch (const exception& e) {
        error_message(hwnd, e.what());
    }
}
