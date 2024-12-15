#include "shellext.h"
#include "resource.h"
#include <windows.h>
#include <commctrl.h>
#include <stdexcept>

using namespace std;

static void init_dialog(HWND hwnd) {
    TCITEMW tie;

    auto tab = GetDlgItem(hwnd, IDC_MAPPINGS_TAB);

    memset(&tie, 0, sizeof(tie));

    tie.mask = TCIF_TEXT;
    tie.iImage = -1;
    tie.pszText = L"UID mappings"; // FIXME - LoadString
    SendMessageW(tab, TCM_INSERTITEMW, 0, (LPARAM)&tie);
    tie.pszText = L"GID mappings"; // FIXME - LoadString
    SendMessageW(tab, TCM_INSERTITEMW, 1, (LPARAM)&tie);

    // FIXME - set list header names
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
