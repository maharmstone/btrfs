/* Copyright (c) Mark Harmstone 2016
 * 
 * This file is part of WinBtrfs.
 * 
 * WinBtrfs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public Licence as published by
 * the Free Software Foundation, either version 3 of the Licence, or
 * (at your option) any later version.
 * 
 * WinBtrfs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public Licence for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public Licence
 * along with WinBtrfs.  If not, see <http://www.gnu.org/licenses/>. */

#define ISOLATION_AWARE_ENABLED 1

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

static void format_size(UINT64 size, WCHAR* s, ULONG len);
static void ShowError(HWND hwnd, ULONG err);

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

void BtrfsPropSheet::add_to_search_list(WCHAR* fn) {
    WCHAR* s;
    
    s = (WCHAR*)malloc((wcslen(fn) + 1) * sizeof(WCHAR));
    if (!s)
        return;
    
    memcpy(s, fn, (wcslen(fn) + 1) * sizeof(WCHAR));
    
    search_list.push_back(s);
}

void BtrfsPropSheet::do_search(WCHAR* fn) {
    HANDLE h;
    WCHAR* ss;
    WIN32_FIND_DATAW ffd;
    
    ss = (WCHAR*)malloc((wcslen(fn) + 3) * sizeof(WCHAR));
    if (!ss)
        return;
    
    memcpy(ss, fn, (wcslen(fn) + 1) * sizeof(WCHAR));
    wcscat(ss, L"\\*");
    
    h = FindFirstFileW(ss, &ffd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    
    do {
        if (ffd.cFileName[0] != '.' || ((ffd.cFileName[1] != 0) && (ffd.cFileName[1] != '.' || ffd.cFileName[2] != 0))) {
            WCHAR* fn2 = (WCHAR*)malloc((wcslen(fn) + 1 + wcslen(ffd.cFileName) + 1) * sizeof(WCHAR));
                
            memcpy(fn2, fn, (wcslen(fn) + 1) * sizeof(WCHAR));
            wcscat(fn2, L"\\");
            wcscat(fn2, ffd.cFileName);
            
            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                add_to_search_list(fn2);
            } else {
                HANDLE fh;
                
                fh = CreateFileW(fn2, FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
                
                if (fh != INVALID_HANDLE_VALUE) {
                    NTSTATUS Status;
                    IO_STATUS_BLOCK iosb;
                    btrfs_inode_info bii2;
                    
                    Status = NtFsControlFile(fh, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_INODE_INFO, NULL, 0, &bii2, sizeof(btrfs_inode_info));
                
                    if (Status == STATUS_SUCCESS) {
                        sizes[0] += bii2.inline_length;
                        sizes[1] += bii2.disk_size[0];
                        sizes[2] += bii2.disk_size[1];
                        sizes[3] += bii2.disk_size[2];
                        totalsize += bii2.inline_length + bii2.disk_size[0] + bii2.disk_size[1] + bii2.disk_size[2];
                    }
                    
                    CloseHandle(fh);
                }
                
                free(fn2);
            }
        }
    } while (FindNextFile(h, &ffd));
    
    FindClose(h);
}

DWORD BtrfsPropSheet::search_list_thread() {
    while (!search_list.empty()) {
        WCHAR* fn = search_list.front();
        
        do_search(fn);
        
        search_list.pop_front();
        free(fn);
    }
    
    thread = NULL;
    
    return 0;
}

static DWORD WINAPI global_search_list_thread(LPVOID lpParameter) {
    BtrfsPropSheet* bps = (BtrfsPropSheet*)lpParameter;
    
    return bps->search_list_thread();
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
        
        h = CreateFileW(fn, FILE_TRAVERSE | FILE_READ_ATTRIBUTES | WRITE_OWNER, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        
        if (h != INVALID_HANDLE_VALUE)
            can_change_owner = TRUE;
        else
            CloseHandle(h);
        
        h = CreateFileW(fn, FILE_TRAVERSE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

        if (h == INVALID_HANDLE_VALUE && (GetLastError() == ERROR_ACCESS_DENIED || GetLastError() == ERROR_WRITE_PROTECT)) {
            h = CreateFileW(fn, FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
            
            readonly = TRUE;
        }
        
        if (h != INVALID_HANDLE_VALUE) {
            BY_HANDLE_FILE_INFORMATION bhfi;
            
            if (GetFileInformationByHandle(h, &bhfi) && bhfi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                add_to_search_list(fn);
            
            Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_INODE_INFO, NULL, 0, &bii, sizeof(btrfs_inode_info));
                
            if (Status == STATUS_SUCCESS && !bii.top) {
                LARGE_INTEGER filesize;
                
                ignore = FALSE;
                
                if (bii.type != BTRFS_TYPE_DIRECTORY && GetFileSizeEx(h, &filesize))
                    empty = filesize.QuadPart == 0;
                
                CloseHandle(h);
            } else {
                CloseHandle(h);
                return E_FAIL;
            }
        } else
            return E_FAIL;
    } else
        return E_FAIL;
    
    if (search_list.size() > 0) {
        thread = CreateThread(NULL, 0, global_search_list_thread, this, 0, NULL);
        
        if (!thread)
            ShowError(NULL, GetLastError());
    }

    return S_OK;
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
        
        if (uid_changed || gid_changed)
            perms |= WRITE_OWNER;
        
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
        
        if (uid_changed) {
            bsii.uid_changed = TRUE;
            bsii.st_uid = bii.st_uid;
        }
        
        if (gid_changed) {
            bsii.gid_changed = TRUE;
            bsii.st_gid = bii.st_gid;
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

void BtrfsPropSheet::set_size_on_disk(HWND hwndDlg) {
    WCHAR size_on_disk[1024], s[1024], old_text[1024];
    
    format_size(totalsize, size_on_disk, sizeof(size_on_disk) / sizeof(WCHAR));
    
    if (StringCchPrintfW(s, sizeof(s) / sizeof(WCHAR), size_format, size_on_disk) == STRSAFE_E_INSUFFICIENT_BUFFER) {
        ShowError(hwndDlg, ERROR_INSUFFICIENT_BUFFER);
        return;
    }
    
    GetDlgItemTextW(hwndDlg, IDC_SIZE_ON_DISK, old_text, sizeof(old_text) / sizeof(WCHAR));
    
    if (wcscmp(s, old_text))
        SetDlgItemTextW(hwndDlg, IDC_SIZE_ON_DISK, s);
}

void BtrfsPropSheet::change_perm_flag(HWND hDlg, ULONG flag, BOOL on) {
    if (on)
        bii.st_mode |= flag;
    else
        bii.st_mode &= ~flag;
    
    perms_changed = TRUE;
    
    SendMessageW(GetParent(hDlg), PSM_CHANGED, 0, 0);
}

void BtrfsPropSheet::change_uid(HWND hDlg, UINT32 uid) {
    bii.st_uid = uid;
    
    uid_changed = TRUE;
    
    SendMessageW(GetParent(hDlg), PSM_CHANGED, 0, 0);
}

void BtrfsPropSheet::change_gid(HWND hDlg, UINT32 gid) {
    bii.st_gid = gid;
    
    gid_changed = TRUE;
    
    SendMessageW(GetParent(hDlg), PSM_CHANGED, 0, 0);
}

void BtrfsPropSheet::update_size_details_dialog(HWND hDlg) {
    WCHAR size[1024], old_text[1024];
    int i;
    ULONG items[] = { IDC_SIZE_INLINE, IDC_SIZE_UNCOMPRESSED, IDC_SIZE_ZLIB, IDC_SIZE_LZO };
    
    for (i = 0; i < 4; i++) {
        format_size(sizes[i], size, sizeof(size) / sizeof(WCHAR));
        
        GetDlgItemTextW(hDlg, items[i], old_text, sizeof(old_text) / sizeof(WCHAR));
        
        if (wcscmp(size, old_text))
            SetDlgItemTextW(hDlg, items[i], size);
    }
}

static INT_PTR CALLBACK SizeDetailsDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
        {
            BtrfsPropSheet* bps = (BtrfsPropSheet*)lParam;
            
            SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)bps);
            
            bps->update_size_details_dialog(hwndDlg);
            
            if (bps->thread)
                SetTimer(hwndDlg, 1, 250, NULL);
            
            return TRUE;
        }
            
        case WM_COMMAND:
            if (HIWORD(wParam) == BN_CLICKED && (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)) {
                EndDialog(hwndDlg, 0);
                return TRUE;
            }
        break;
        
        case WM_TIMER:
        {
            BtrfsPropSheet* bps = (BtrfsPropSheet*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
            
            if (bps) {
                bps->update_size_details_dialog(hwndDlg);
                
                if (!bps->thread)
                    KillTimer(hwndDlg, 1);
            }
            
            break;
        }
    }
    
    return FALSE;
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
            
            SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)bps);
            
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
            
            GetDlgItemTextW(hwndDlg, IDC_SIZE_ON_DISK, bps->size_format, sizeof(bps->size_format) / sizeof(WCHAR));
            bps->set_size_on_disk(hwndDlg);
            
            if (bps->thread)
                SetTimer(hwndDlg, 1, 250, NULL);
            
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
            
            if (!bps->can_change_owner) {
                EnableWindow(GetDlgItem(hwndDlg, IDC_UID), 0);
                EnableWindow(GetDlgItem(hwndDlg, IDC_GID), 0);
            }
            
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
            }
            
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
                    
                    case EN_CHANGE: {
                        switch (LOWORD(wParam)) {
                            case IDC_UID: {
                                WCHAR s[255];
                                
                                GetDlgItemTextW(hwndDlg, LOWORD(wParam), s, sizeof(s) / sizeof(WCHAR));
                                
                                bps->change_uid(hwndDlg, _wtoi(s));
                                break;
                            }
                            
                            case IDC_GID: {
                                WCHAR s[255];
                                
                                GetDlgItemTextW(hwndDlg, LOWORD(wParam), s, sizeof(s) / sizeof(WCHAR));
                                
                                bps->change_gid(hwndDlg, _wtoi(s));
                                break;
                            }
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
                
                case NM_CLICK:
                case NM_RETURN: {
                    if (((LPNMHDR)lParam)->hwndFrom == GetDlgItem(hwndDlg, IDC_SIZE_ON_DISK)) {
                        PNMLINK pNMLink = (PNMLINK)lParam;
                        
                        if (pNMLink->item.iLink == 0)
                            DialogBoxParamW(module, MAKEINTRESOURCEW(IDD_SIZE_DETAILS), hwndDlg, SizeDetailsDlgProc, GetWindowLongPtr(hwndDlg, GWLP_USERDATA));
                    }
                    break;
                }
            }
        }
        
        case WM_TIMER:
        {
            BtrfsPropSheet* bps = (BtrfsPropSheet*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
            
            if (bps) {
                bps->set_size_on_disk(hwndDlg);
                
                if (!bps->thread)
                    KillTimer(hwndDlg, 1);
            }
            
            break;
        }
    }
    
    return FALSE;
}

static void format_size(UINT64 size, WCHAR* s, ULONG len) {
    WCHAR nb[255], nb2[255], t[255], bytes[255];
    WCHAR kb[255];
    ULONG sr;
    float f;
    NUMBERFMT fmt;
    WCHAR thou[4], grouping[64], *c;
    
    _itow(size, nb, 10);
    
    GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_STHOUSAND, thou, sizeof(thou) / sizeof(WCHAR));
    
    fmt.NumDigits = 0;
    fmt.LeadingZero = 1;
    fmt.lpDecimalSep = L"."; // not used
    fmt.lpThousandSep = thou;
    fmt.NegativeOrder = 0;
    
    // Grouping code copied from dlls/shlwapi/string.c in Wine - thank you
    
    fmt.Grouping = 0;
    GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SGROUPING, grouping, sizeof(grouping) / sizeof(WCHAR));
    
    c = grouping;
    while (*c) {
        if (*c >= '0' && *c < '9') {
            fmt.Grouping *= 10;
            fmt.Grouping += *c - '0';
        }
        
        c++;
    }

    if (fmt.Grouping % 10 == 0)
        fmt.Grouping /= 10;
    else
        fmt.Grouping *= 10;
    
    GetNumberFormatW(LOCALE_USER_DEFAULT, 0, nb, &fmt, nb2, sizeof(nb2) / sizeof(WCHAR));
    
    if (size < 1024) {
        if (!LoadStringW(module, size == 1 ? IDS_SIZE_BYTE : IDS_SIZE_BYTES, t, sizeof(t) / sizeof(WCHAR))) {
            ShowError(NULL, GetLastError());
            return;
        }
        
        if (StringCchPrintfW(s, len, t, nb2) == STRSAFE_E_INSUFFICIENT_BUFFER) {
            ShowError(NULL, ERROR_INSUFFICIENT_BUFFER);
            return;
        }
        
        return;
    }
    
    if (!LoadStringW(module, IDS_SIZE_BYTES, t, sizeof(t) / sizeof(WCHAR))) {
        ShowError(NULL, GetLastError());
        return;
    }
    
    if (StringCchPrintfW(bytes, sizeof(bytes) / sizeof(WCHAR), t, nb2) == STRSAFE_E_INSUFFICIENT_BUFFER) {
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

HRESULT __stdcall BtrfsPropSheet::AddPages(LPFNADDPROPSHEETPAGE pfnAddPage, LPARAM lParam) {
    PROPSHEETPAGE psp;
    HPROPSHEETPAGE hPage;
    int i;
    INITCOMMONCONTROLSEX icex;
    
    if (ignore)
        return S_OK;
    
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LINK_CLASS;
    
    if (!InitCommonControlsEx(&icex)) {
        MessageBoxW(NULL, L"InitCommonControlsEx failed", L"Error", MB_ICONERROR);
    }
    
    totalsize = 0;
    
    if (bii.inline_length > 0) {
        totalsize += bii.inline_length;
        sizes[0] += bii.inline_length;
    }
    
    for (i = 0; i < 3; i++) {
        if (bii.disk_size[i] > 0) {
            totalsize += bii.disk_size[i];
            sizes[i + 1] += bii.disk_size[i];
        }
    }
    
    psp.dwSize = sizeof(psp);
    psp.dwFlags = PSP_USEREFPARENT | PSP_USETITLE;
    psp.hInstance = module;
    psp.pszTemplate = MAKEINTRESOURCE(IDD_PROP_SHEET);
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
