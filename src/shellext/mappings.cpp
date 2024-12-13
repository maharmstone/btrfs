#include "shellext.h"
#include "resource.h"
#include <windows.h>
#include <stdexcept>

using namespace std;

static INT_PTR CALLBACK MappingsDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    try {
        switch (uMsg) {
            case WM_INITDIALOG:
                // FIXME
            break;

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
