#include <windows.h>
#include <strsafe.h>
#include <winternl.h>
#include <shlwapi.h>
#include <uxtheme.h>

#include "propsheet.h"
#include "resource.h"

// FIXME - is there a way to link to the proper header files without breaking everything?
#ifdef __cplusplus
extern "C" {
#endif
NTSYSCALLAPI NTSTATUS NTAPI NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
#ifdef __cplusplus
}
#endif

#define STATUS_SUCCESS          (NTSTATUS)0x00000000

#define BTRFS_TYPE_FILE      1
#define BTRFS_TYPE_DIRECTORY 2
#define BTRFS_TYPE_CHARDEV   3
#define BTRFS_TYPE_BLOCKDEV  4
#define BTRFS_TYPE_FIFO      5
#define BTRFS_TYPE_SOCKET    6
#define BTRFS_TYPE_SYMLINK   7

extern HMODULE module;

HRESULT __stdcall BtrfsPropSheet::QueryInterface(REFIID riid, void **ppObj) {
    if (riid == IID_IUnknown || riid == IID_IShellPropSheetExt) {
        *ppObj = static_cast<IShellPropSheetExt*>(this); 
        AddRef();
        return S_OK;
    } else if (riid == IID_IShellExtInit) {
        *ppObj = static_cast<IShellExtInit*>(this); 
        AddRef();
        return S_OK;
    }

    *ppObj = NULL;
    return E_NOINTERFACE;
}

HRESULT __stdcall BtrfsPropSheet::Initialize(PCIDLIST_ABSOLUTE pidlFolder, IDataObject* pdtobj, HKEY hkeyProgID) {
    HANDLE h;
    IO_STATUS_BLOCK iosb;
    NTSTATUS Status;
    FORMATETC format = { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
    UINT num_files;
    WCHAR fn[MAX_PATH];
    HDROP hdrop;
    
    if (pidlFolder)
        return E_FAIL;
        
    
    if (!pdtobj)
        return E_FAIL;
    
    stgm.tymed = TYMED_HGLOBAL;
    
    if (FAILED(pdtobj->GetData(&format, &stgm)))
        return E_INVALIDARG;
    
    stgm_set = TRUE;
    
    hdrop = (HDROP)GlobalLock(stgm.hGlobal);
    
    if (!hdrop) {
        ReleaseStgMedium(&stgm);
        stgm_set = FALSE;
        return E_INVALIDARG;
    }
        
    num_files = DragQueryFileW((HDROP)stgm.hGlobal, 0xFFFFFFFF, NULL, 0);
    
    if (num_files > 1)
        return E_FAIL; // FIXME - make this work with multiple files

    if (DragQueryFileW((HDROP)stgm.hGlobal, 0/*i*/, fn, sizeof(fn) / sizeof(MAX_PATH))) {
        h = CreateFileW(fn, FILE_TRAVERSE | FILE_READ_ATTRIBUTES | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        
        if (h != INVALID_HANDLE_VALUE)
            can_change_perms = TRUE;
        else
            CloseHandle(h);
        
        h = CreateFileW(fn, FILE_TRAVERSE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

        if (h == INVALID_HANDLE_VALUE && (GetLastError() == ERROR_ACCESS_DENIED || GetLastError() == ERROR_WRITE_PROTECT)) {
            h = CreateFileW(fn, FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
            
            readonly = TRUE;
        }

        if (h != INVALID_HANDLE_VALUE) {
            Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_INODE_INFO, NULL, 0, &bii, sizeof(btrfs_inode_info));
                
            if (Status == STATUS_SUCCESS && !bii.top) {
                LARGE_INTEGER filesize;
                
                ignore = FALSE;
                
                if (bii.type != BTRFS_TYPE_DIRECTORY && GetFileSizeEx(h, &filesize))
                    empty = filesize.QuadPart == 0;
                
                CloseHandle(h);
                return S_OK;
            }
            
            CloseHandle(h);
        }
    }

    return E_FAIL;
}

static ULONG inode_type_to_string_ref(UINT8 type) {
    switch (type) {    
        case BTRFS_TYPE_FILE:
            return IDS_INODE_FILE;
        
        case BTRFS_TYPE_DIRECTORY:
            return IDS_INODE_DIR;
            
        case BTRFS_TYPE_CHARDEV:
            return IDS_INODE_CHAR;
            
        case BTRFS_TYPE_BLOCKDEV:
            return IDS_INODE_BLOCK;
            
        case BTRFS_TYPE_FIFO:
            return IDS_INODE_FIFO;
            
        case BTRFS_TYPE_SOCKET:
            return IDS_INODE_SOCKET;
            
        case BTRFS_TYPE_SYMLINK:
            return IDS_INODE_SYMLINK;
            
        default:
            return IDS_INODE_UNKNOWN;
    }
}

static void ShowError(HWND hwnd, ULONG err) {
    WCHAR* buf;
    
    if (FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                       err, 0, (WCHAR*)&buf, 0, NULL) == 0) {
        MessageBoxW(hwnd, L"FormatMessage failed", L"Error", MB_ICONERROR);
        return;
    }
    
    MessageBoxW(hwnd, buf, L"Error", MB_ICONERROR);
    
    LocalFree(buf);
}

void BtrfsPropSheet::change_inode_flag(HWND hDlg, UINT64 flag, BOOL on) {
    if (flag & BTRFS_INODE_NODATACOW)
        flag |= BTRFS_INODE_NODATASUM;
    
    // FIXME - only allow NODATACOW to be changed if file is empty
    
    if (on)
        bii.flags |= flag;
    else
        bii.flags &= ~flag;
    
    flags_changed = TRUE;
    
    SendMessageW(GetParent(hDlg), PSM_CHANGED, 0, 0);
}

void BtrfsPropSheet::apply_changes(HWND hDlg) {
    UINT num_files;
    WCHAR fn[MAX_PATH]; // FIXME - is this long enough?
    HANDLE h;
    IO_STATUS_BLOCK iosb;
    NTSTATUS Status;
    btrfs_set_inode_info bsii;
    
    if (readonly)
        return;
    
    num_files = DragQueryFileW((HDROP)stgm.hGlobal, 0xFFFFFFFF, NULL, 0);
    
    if (num_files > 1)
        return; // FIXME - make this work with multiple files

    if (DragQueryFileW((HDROP)stgm.hGlobal, 0/*i*/, fn, sizeof(fn) / sizeof(MAX_PATH))) {
        ULONG perms = FILE_TRAVERSE | FILE_READ_ATTRIBUTES;
        
        if (flags_changed)
            perms |= FILE_WRITE_ATTRIBUTES;
        
        if (perms_changed)
            perms |= WRITE_DAC;
        
        h = CreateFileW(fn, perms, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

        if (h == INVALID_HANDLE_VALUE) {
            ShowError(hDlg, GetLastError());
            return;
        }
        
        ZeroMemory(&bsii, sizeof(btrfs_set_inode_info));
        
        if (flags_changed) {
            bsii.flags_changed = TRUE;
            bsii.flags = bii.flags;
        }
        
        if (perms_changed) {
            bsii.mode_changed = TRUE;
            bsii.st_mode = bii.st_mode;
        }
        
        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_SET_INODE_INFO, NULL, 0, &bsii, sizeof(btrfs_set_inode_info));
        CloseHandle(h);

        if (Status != STATUS_SUCCESS) {
            WCHAR s[255], t[255];
            
            if (!LoadStringW(module, IDS_SET_INODE_INFO_ERROR, t, sizeof(t) / sizeof(WCHAR))) {
                ShowError(hDlg, GetLastError());
                return;
            }
            
            if (StringCchPrintfW(s, sizeof(s) / sizeof(WCHAR), t, Status) == STRSAFE_E_INSUFFICIENT_BUFFER) {
                ShowError(hDlg, ERROR_INSUFFICIENT_BUFFER);
                return;
            }
            
            MessageBoxW(hDlg, s, L"Error", MB_ICONERROR);
        }
    }
}

typedef struct {
    ULONG delta;
    ULONG top;
} resize_params;

static BOOL CALLBACK resize_callback(HWND hwnd, LPARAM lParam) {
    resize_params* rp = (resize_params*)lParam;
    RECT r;
    
    GetWindowRect(hwnd, &r);
    
    if (r.top > rp->top) {
        POINT pt;
        
        pt.x = r.left;
        pt.y = r.top + rp->delta;
        
        ScreenToClient(GetParent(hwnd), &pt);

        SetWindowPos(hwnd, NULL, pt.x, pt.y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }
    
    return TRUE;
}

void BtrfsPropSheet::set_size_on_disk(HWND hwndDlg) {
    HWND hc;
    HDC hDC;
    HFONT font, oldfont;
    RECT origrect, r;
    
    hc = GetDlgItem(hwndDlg, IDC_SIZE_ON_DISK);
    hDC = GetDC(hc);
    
    GetWindowRect(hc, &origrect);
    
    font = (HFONT)SendMessageW(hc, WM_GETFONT, 0, 0);
    
    if (font)
        oldfont = (HFONT)SelectObject(hDC, font);
        
    r = origrect;
    DrawTextW(hDC, size_on_disk, -1, &r, DT_CALCRECT);
    
    if (font)
        SelectObject(hDC, oldfont);
    
    ReleaseDC(hc, hDC);
    
    SetDlgItemTextW(hwndDlg, IDC_SIZE_ON_DISK, size_on_disk);
    
    SetWindowPos(hc, NULL, 0, 0, origrect.right - origrect.left, r.bottom - r.top, SWP_NOMOVE | SWP_NOZORDER);
    
    if (r.bottom - r.top > origrect.bottom - origrect.top) {
        ULONG delta = (r.bottom - r.top) - (origrect.bottom - origrect.top);
        resize_params rp;
        
        rp.delta = delta;
        rp.top = r.top;
        
        EnumChildWindows(hwndDlg, resize_callback, (LPARAM)&rp);
        
        GetWindowRect(GetDlgItem(hwndDlg, IDC_GROUP_INFORMATION), &r);
        SetWindowPos(GetDlgItem(hwndDlg, IDC_GROUP_INFORMATION), NULL, 0, 0, r.right - r.left, r.bottom - r.top + delta, SWP_NOMOVE | SWP_NOZORDER);
    }
}

void BtrfsPropSheet::change_perm_flag(HWND hDlg, ULONG flag, BOOL on) {
    if (on)
        bii.st_mode |= flag;
    else
        bii.st_mode &= ~flag;
    
    perms_changed = TRUE;
    
    SendMessageW(GetParent(hDlg), PSM_CHANGED, 0, 0);
}

static INT_PTR CALLBACK PropSheetDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
        {
            PROPSHEETPAGE* psp = (PROPSHEETPAGE*)lParam;
            BtrfsPropSheet* bps = (BtrfsPropSheet*)psp->lParam;
            WCHAR s[255];
            ULONG sr;
            
            EnableThemeDialogTexture(hwndDlg, ETDT_ENABLETAB);
            
            if (StringCchPrintfW(s, sizeof(s) / sizeof(WCHAR), L"%llx", bps->bii.subvol) == STRSAFE_E_INSUFFICIENT_BUFFER)
                return FALSE;
            
            SetDlgItemTextW(hwndDlg, IDC_SUBVOL, s);
            
            if (StringCchPrintfW(s, sizeof(s) / sizeof(WCHAR), L"%llx", bps->bii.inode) == STRSAFE_E_INSUFFICIENT_BUFFER)
                return FALSE;
            
            SetDlgItemTextW(hwndDlg, IDC_INODE, s);
            
            sr = inode_type_to_string_ref(bps->bii.type);
            
            if (sr == IDS_INODE_UNKNOWN) {
                WCHAR t[255];
                
                if (!LoadStringW(module, sr, t, sizeof(t) / sizeof(WCHAR))) {
                    ShowError(hwndDlg, GetLastError());
                    return FALSE;
                }
                
                if (StringCchPrintfW(s, sizeof(s) / sizeof(WCHAR), t, bps->bii.type) == STRSAFE_E_INSUFFICIENT_BUFFER)
                    return FALSE;
            } else if (sr == IDS_INODE_CHAR || sr == IDS_INODE_BLOCK) {
                WCHAR t[255];
                
                if (!LoadStringW(module, sr, t, sizeof(t) / sizeof(WCHAR))) {
                    ShowError(hwndDlg, GetLastError());
                    return FALSE;
                }
                
                if (StringCchPrintfW(s, sizeof(s) / sizeof(WCHAR), t, (UINT64)((bps->bii.st_rdev & 0xFFFFFFFFFFF) >> 20), (UINT32)(bps->bii.st_rdev & 0xFFFFF)) == STRSAFE_E_INSUFFICIENT_BUFFER)
                    return FALSE;
            } else {
                if (!LoadStringW(module, sr, s, sizeof(s) / sizeof(WCHAR))) {
                    ShowError(hwndDlg, GetLastError());
                    return FALSE;
                }
            }
            
            SetDlgItemTextW(hwndDlg, IDC_TYPE, s);
            
            bps->set_size_on_disk(hwndDlg);
            
            SendDlgItemMessage(hwndDlg, IDC_NODATACOW, BM_SETCHECK, bps->bii.flags & BTRFS_INODE_NODATACOW ? BST_CHECKED : BST_UNCHECKED, 0);
            SendDlgItemMessage(hwndDlg, IDC_COMPRESS, BM_SETCHECK, bps->bii.flags & BTRFS_INODE_COMPRESS ? BST_CHECKED : BST_UNCHECKED, 0);
            
            SendDlgItemMessage(hwndDlg, IDC_USERR, BM_SETCHECK, bps->bii.st_mode & S_IRUSR ? BST_CHECKED : BST_UNCHECKED, 0);
            SendDlgItemMessage(hwndDlg, IDC_USERW, BM_SETCHECK, bps->bii.st_mode & S_IWUSR ? BST_CHECKED : BST_UNCHECKED, 0);
            SendDlgItemMessage(hwndDlg, IDC_USERX, BM_SETCHECK, bps->bii.st_mode & S_IXUSR ? BST_CHECKED : BST_UNCHECKED, 0);
            SendDlgItemMessage(hwndDlg, IDC_GROUPR, BM_SETCHECK, bps->bii.st_mode & S_IRGRP ? BST_CHECKED : BST_UNCHECKED, 0);
            SendDlgItemMessage(hwndDlg, IDC_GROUPW, BM_SETCHECK, bps->bii.st_mode & S_IWGRP ? BST_CHECKED : BST_UNCHECKED, 0);
            SendDlgItemMessage(hwndDlg, IDC_GROUPX, BM_SETCHECK, bps->bii.st_mode & S_IXGRP ? BST_CHECKED : BST_UNCHECKED, 0);
            SendDlgItemMessage(hwndDlg, IDC_OTHERR, BM_SETCHECK, bps->bii.st_mode & S_IROTH ? BST_CHECKED : BST_UNCHECKED, 0);
            SendDlgItemMessage(hwndDlg, IDC_OTHERW, BM_SETCHECK, bps->bii.st_mode & S_IWOTH ? BST_CHECKED : BST_UNCHECKED, 0);
            SendDlgItemMessage(hwndDlg, IDC_OTHERX, BM_SETCHECK, bps->bii.st_mode & S_IXOTH ? BST_CHECKED : BST_UNCHECKED, 0);
            
            if (StringCchPrintfW(s, sizeof(s) / sizeof(WCHAR), L"%u", bps->bii.st_uid) == STRSAFE_E_INSUFFICIENT_BUFFER)
                return FALSE;
            
            SetDlgItemTextW(hwndDlg, IDC_UID, s);
            
            if (StringCchPrintfW(s, sizeof(s) / sizeof(WCHAR), L"%u", bps->bii.st_gid) == STRSAFE_E_INSUFFICIENT_BUFFER)
                return FALSE;
            
            SetDlgItemTextW(hwndDlg, IDC_GID, s);
            
            if (bps->bii.type != BTRFS_TYPE_DIRECTORY && !bps->empty) // disable nocow checkbox if not a directory and size not 0
                EnableWindow(GetDlgItem(hwndDlg, IDC_NODATACOW), 0);
            
            if (!bps->can_change_perms) {
                EnableWindow(GetDlgItem(hwndDlg, IDC_USERR), 0);
                EnableWindow(GetDlgItem(hwndDlg, IDC_USERW), 0);
                EnableWindow(GetDlgItem(hwndDlg, IDC_USERX), 0);
                EnableWindow(GetDlgItem(hwndDlg, IDC_GROUPR), 0);
                EnableWindow(GetDlgItem(hwndDlg, IDC_GROUPW), 0);
                EnableWindow(GetDlgItem(hwndDlg, IDC_GROUPX), 0);
                EnableWindow(GetDlgItem(hwndDlg, IDC_OTHERR), 0);
                EnableWindow(GetDlgItem(hwndDlg, IDC_OTHERW), 0);
                EnableWindow(GetDlgItem(hwndDlg, IDC_OTHERX), 0);
            }
            
            if (bps->readonly) {
                EnableWindow(GetDlgItem(hwndDlg, IDC_NODATACOW), 0);
                EnableWindow(GetDlgItem(hwndDlg, IDC_COMPRESS), 0);
                
                // FIXME - also others
            }
            
            SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)bps);
            
            return FALSE;
        }
        
        case WM_COMMAND:
        {
            BtrfsPropSheet* bps = (BtrfsPropSheet*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
            
            if (bps && !bps->readonly) {
                switch (HIWORD(wParam)) {
                    case BN_CLICKED: {
                        switch (LOWORD(wParam)) {
                            case IDC_NODATACOW:
                                bps->change_inode_flag(hwndDlg, BTRFS_INODE_NODATACOW, IsDlgButtonChecked(hwndDlg, LOWORD(wParam)) == BST_CHECKED);
                            break;
                            
                            case IDC_COMPRESS:
                                bps->change_inode_flag(hwndDlg, BTRFS_INODE_COMPRESS, IsDlgButtonChecked(hwndDlg, LOWORD(wParam)) == BST_CHECKED);
                            break;
                            
                            case IDC_USERR:
                                bps->change_perm_flag(hwndDlg, S_IRUSR, IsDlgButtonChecked(hwndDlg, LOWORD(wParam)) == BST_CHECKED);
                            break;
                            
                            case IDC_USERW:
                                bps->change_perm_flag(hwndDlg, S_IWUSR, IsDlgButtonChecked(hwndDlg, LOWORD(wParam)) == BST_CHECKED);
                            break;
                            
                            case IDC_USERX:
                                bps->change_perm_flag(hwndDlg, S_IXUSR, IsDlgButtonChecked(hwndDlg, LOWORD(wParam)) == BST_CHECKED);
                            break;
                            
                            case IDC_GROUPR:
                                bps->change_perm_flag(hwndDlg, S_IRGRP, IsDlgButtonChecked(hwndDlg, LOWORD(wParam)) == BST_CHECKED);
                            break;
                            
                            case IDC_GROUPW:
                                bps->change_perm_flag(hwndDlg, S_IWGRP, IsDlgButtonChecked(hwndDlg, LOWORD(wParam)) == BST_CHECKED);
                            break;
                            
                            case IDC_GROUPX:
                                bps->change_perm_flag(hwndDlg, S_IXGRP, IsDlgButtonChecked(hwndDlg, LOWORD(wParam)) == BST_CHECKED);
                            break;
                            
                            case IDC_OTHERR:
                                bps->change_perm_flag(hwndDlg, S_IROTH, IsDlgButtonChecked(hwndDlg, LOWORD(wParam)) == BST_CHECKED);
                            break;
                            
                            case IDC_OTHERW:
                                bps->change_perm_flag(hwndDlg, S_IWOTH, IsDlgButtonChecked(hwndDlg, LOWORD(wParam)) == BST_CHECKED);
                            break;
                            
                            case IDC_OTHERX:
                                bps->change_perm_flag(hwndDlg, S_IXOTH, IsDlgButtonChecked(hwndDlg, LOWORD(wParam)) == BST_CHECKED);
                            break;
                        }
                    }
                }
            }
            
            break;
        }
        
        case WM_NOTIFY:
        {
            switch (((LPNMHDR)lParam)->code) {
                case PSN_KILLACTIVE:
                    SetWindowLongPtrW(hwndDlg, DWLP_MSGRESULT, FALSE);
                break;
                    
                case PSN_APPLY: {
                    BtrfsPropSheet* bps = (BtrfsPropSheet*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
                    
                    bps->apply_changes(hwndDlg);
                    SetWindowLongPtrW(hwndDlg, DWLP_MSGRESULT, PSNRET_NOERROR);
                    break;
                }
            }
        }
    }
    
    return FALSE;
}

static void format_size(UINT64 size, WCHAR* s, ULONG len) {
    WCHAR t[255], bytes[255];
    WCHAR kb[255];
    ULONG sr;
    float f;
    
    if (size < 1024) {
        if (!LoadStringW(module, size == 1 ? IDS_SIZE_BYTE : IDS_SIZE_BYTES, t, sizeof(t) / sizeof(WCHAR))) {
            ShowError(NULL, GetLastError());
            return;
        }
        
        if (StringCchPrintfW(s, len, t, size) == STRSAFE_E_INSUFFICIENT_BUFFER) {
            ShowError(NULL, ERROR_INSUFFICIENT_BUFFER);
            return;
        }
        
        return;
    }
    
    if (!LoadStringW(module, IDS_SIZE_BYTES, t, sizeof(t) / sizeof(WCHAR))) {
        ShowError(NULL, GetLastError());
        return;
    }
    
    if (StringCchPrintfW(bytes, sizeof(bytes) / sizeof(WCHAR), t, size) == STRSAFE_E_INSUFFICIENT_BUFFER) {
        ShowError(NULL, ERROR_INSUFFICIENT_BUFFER);
        return;
    }
    
    if (size >= 1152921504606846976) {
        sr = IDS_SIZE_EB;
        f = (float)size / 1152921504606846976.0f;
    } else if (size >= 1125899906842624) {
        sr = IDS_SIZE_PB;
        f = (float)size / 1125899906842624.0f;
    } else if (size >= 1099511627776) {
        sr = IDS_SIZE_TB;
        f = (float)size / 1099511627776.0f;
    } else if (size >= 1073741824) {
        sr = IDS_SIZE_GB;
        f = (float)size / 1073741824.0f;
    } else if (size >= 1048576) {
        sr = IDS_SIZE_MB;
        f = (float)size / 1048576.0f;
    } else {
        sr = IDS_SIZE_KB;
        f = (float)size / 1024.0f;
    }
    
    if (!LoadStringW(module, sr, t, sizeof(t) / sizeof(WCHAR))) {
        ShowError(NULL, GetLastError());
        return;
    }
    
    if (StringCchPrintfW(kb, sizeof(kb) / sizeof(WCHAR), t, f) == STRSAFE_E_INSUFFICIENT_BUFFER) {
        ShowError(NULL, ERROR_INSUFFICIENT_BUFFER);
        return;
    }
    
    if (!LoadStringW(module, IDS_SIZE_LARGE, t, sizeof(t) / sizeof(WCHAR))) {
        ShowError(NULL, GetLastError());
        return;
    }
    
    if (StringCchPrintfW(s, len, t, kb, bytes) == STRSAFE_E_INSUFFICIENT_BUFFER) {
        ShowError(NULL, ERROR_INSUFFICIENT_BUFFER);
        return;
    }
}

// From https://msdn.microsoft.com/en-us/library/windows/desktop/ms645398.aspx
// Not in any header file. This is just the beginning of the struct.
typedef struct {
  WORD      dlgVer;
  WORD      signature;
  DWORD     helpID;
  DWORD     exStyle;
  DWORD     style;
  WORD      cDlgItems;
  short     x;
  short     y;
  short     cx;
  short     cy;
} DLGTEMPLATEEX_HEAD;

HRESULT __stdcall BtrfsPropSheet::AddPages(LPFNADDPROPSHEETPAGE pfnAddPage, LPARAM lParam) {
    PROPSHEETPAGE psp;
    HPROPSHEETPAGE hPage;
    HRSRC res;
    HGLOBAL dlg;
    DLGTEMPLATEEX_HEAD* dt;
    DWORD dlgsize;
    UINT64 totalsize;
    ULONG num_lines;
    int i;
    WCHAR format[255], size[255], t[255];
    
    // This is jiggerypokery. The "size on disk" field has a variable height, but the height
    // of a property sheet is determined when it is created. We have to load the dialog resource
    // into memory and adjust its height manually.
    
    if (ignore)
        return S_OK;
    
    num_lines = 0;
    size_on_disk[0] = 0;
    totalsize = 0;
    
    if (bii.inline_length > 0) {
        totalsize += bii.inline_length;
        format_size(bii.inline_length, size, sizeof(size) / sizeof(WCHAR));
        
        if (!LoadStringW(module, IDS_SIZE_INLINE, format, sizeof(format) / sizeof(WCHAR))) {
            ShowError(NULL, GetLastError());
        }
        
        if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), format, size) == STRSAFE_E_INSUFFICIENT_BUFFER) {
            ShowError(NULL, ERROR_INSUFFICIENT_BUFFER);
        }
        
        wcscpy(size_on_disk, t);
        
        num_lines++;
    }
    
    for (i = 0; i < 3; i++) {
        if (bii.disk_size[i] > 0) {
            totalsize += bii.disk_size[i];
            format_size(bii.disk_size[i], size, sizeof(size) / sizeof(WCHAR));
            
            if (!LoadStringW(module, i == 0 ? IDS_SIZE_UNCOMPRESSED : (i == 1 ? IDS_SIZE_ZLIB : IDS_SIZE_LZO), format, sizeof(format) / sizeof(WCHAR))) {
                ShowError(NULL, GetLastError());
            }
            
            if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), format, size) == STRSAFE_E_INSUFFICIENT_BUFFER) {
                ShowError(NULL, ERROR_INSUFFICIENT_BUFFER);
            }
            
            if (size_on_disk[0] != 0)
                wcscat(size_on_disk, L"\n");
            
            wcscat(size_on_disk, t);
            
            num_lines++;
        }
    }
    
    if (num_lines > 1) {
        format_size(totalsize, size, sizeof(size) / sizeof(WCHAR));
        
        if (!LoadStringW(module, IDS_SIZE_TOTAL, format, sizeof(format) / sizeof(WCHAR))) {
            ShowError(NULL, GetLastError());
        }
        
        if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), format, size) == STRSAFE_E_INSUFFICIENT_BUFFER) {
            ShowError(NULL, ERROR_INSUFFICIENT_BUFFER);
        }
        
        if (size_on_disk[0] != 0)
            wcscat(size_on_disk, L"\n");
        
        wcscat(size_on_disk, t);
        
        num_lines++;
    }
    
    if (num_lines == 0)
        num_lines = 1;
    
    res = FindResource(module, MAKEINTRESOURCE(IDD_PROP_SHEET), RT_DIALOG);
    
    dlg = LoadResource(module, res);
    
    dlgsize = SizeofResource(module, res);
    
    dt = (DLGTEMPLATEEX_HEAD*)malloc(dlgsize);
    memcpy(dt, LockResource(dlg), dlgsize); // FIXME - free this eventually
    
    // 8 is the height of the statics in shellbtrfs.rc.
    // This is in "dialog box units", rather than pixels, so it shouldn't matter.
    dt->cy += (num_lines - 1) * 8;
    
    psp.dwSize = sizeof(psp);
    psp.dwFlags = PSP_USEREFPARENT | PSP_USETITLE | PSP_DLGINDIRECT;
    psp.hInstance = module;
//     psp.pszTemplate = MAKEINTRESOURCE(IDD_PROP_SHEET);
    psp.pResource = (DLGTEMPLATE*)dt;
    psp.hIcon = 0;
    psp.pszTitle = MAKEINTRESOURCE(IDS_PROP_SHEET_TITLE);
    psp.pfnDlgProc = (DLGPROC)PropSheetDlgProc;
    psp.pcRefParent = (UINT*)&objs_loaded;
    psp.pfnCallback = NULL;
    psp.lParam = (LPARAM)this;

    hPage = CreatePropertySheetPage(&psp);
            
    if (hPage) {
        if (pfnAddPage(hPage, lParam)) {
            this->AddRef();
            return S_OK;
        } else
            DestroyPropertySheetPage(hPage);
    } else
        return E_OUTOFMEMORY;
    
    return E_FAIL;
}

HRESULT __stdcall BtrfsPropSheet::ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE pfnReplacePage, LPARAM lParam) {
    return S_OK;
}
