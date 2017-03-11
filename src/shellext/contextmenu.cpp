/* Copyright (c) Mark Harmstone 2016-17
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

#include "shellext.h"
#include <windows.h>
#include <strsafe.h>
#include <winternl.h>
#include <string>
#include <sstream>

#define NO_SHLWAPI_STRFCNS
#include <shlwapi.h>

#include "contextmenu.h"
#include "resource.h"
#include "../btrfsioctl.h"

#define NEW_SUBVOL_VERBA "newsubvol"
#define NEW_SUBVOL_VERBW L"newsubvol"
#define SNAPSHOT_VERBA "snapshot"
#define SNAPSHOT_VERBW L"snapshot"
#define REFLINK_VERBA "reflink"
#define REFLINK_VERBW L"reflink"

#define STATUS_SUCCESS          (NTSTATUS)0x00000000

#ifndef FILE_SUPPORTS_BLOCK_REFCOUNTING

typedef struct _DUPLICATE_EXTENTS_DATA {
    HANDLE FileHandle;
    LARGE_INTEGER SourceFileOffset;
    LARGE_INTEGER TargetFileOffset;
    LARGE_INTEGER ByteCount;
} DUPLICATE_EXTENTS_DATA, *PDUPLICATE_EXTENTS_DATA;

#define FSCTL_DUPLICATE_EXTENTS_TO_FILE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 209, METHOD_BUFFERED, FILE_WRITE_ACCESS)

typedef struct _FSCTL_GET_INTEGRITY_INFORMATION_BUFFER {
    WORD ChecksumAlgorithm;
    WORD Reserved;
    DWORD Flags;
    DWORD ChecksumChunkSizeInBytes;
    DWORD ClusterSizeInBytes;
} FSCTL_GET_INTEGRITY_INFORMATION_BUFFER, *PFSCTL_GET_INTEGRITY_INFORMATION_BUFFER;

typedef struct _FSCTL_SET_INTEGRITY_INFORMATION_BUFFER {
    WORD ChecksumAlgorithm;
    WORD Reserved;
    DWORD Flags;
} FSCTL_SET_INTEGRITY_INFORMATION_BUFFER, *PFSCTL_SET_INTEGRITY_INFORMATION_BUFFER;

#define FSCTL_GET_INTEGRITY_INFORMATION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 159, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SET_INTEGRITY_INFORMATION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 160, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#endif

// FIXME - don't assume subvol's top inode is 0x100

HRESULT __stdcall BtrfsContextMenu::QueryInterface(REFIID riid, void **ppObj) {
    if (riid == IID_IUnknown || riid == IID_IContextMenu) {
        *ppObj = static_cast<IContextMenu*>(this); 
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

HRESULT __stdcall BtrfsContextMenu::Initialize(PCIDLIST_ABSOLUTE pidlFolder, IDataObject* pdtobj, HKEY hkeyProgID) {
    HANDLE h;
    IO_STATUS_BLOCK iosb;
    btrfs_get_file_ids bgfi;
    NTSTATUS Status;
    
    if (!pidlFolder) {
        FORMATETC format = { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
        UINT num_files, i;
        WCHAR fn[MAX_PATH];
        HDROP hdrop;
        
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
        
        for (i = 0; i < num_files; i++) {
            if (DragQueryFileW((HDROP)stgm.hGlobal, i, fn, sizeof(fn) / sizeof(WCHAR))) {
                h = CreateFileW(fn, FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    
                if (h != INVALID_HANDLE_VALUE) {
                    Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_FILE_IDS, NULL, 0, &bgfi, sizeof(btrfs_get_file_ids));
                        
                    if (NT_SUCCESS(Status) && bgfi.inode == 0x100 && !bgfi.top) {
                        WCHAR parpath[MAX_PATH];
                        HANDLE h2;
                        
                        StringCchCopyW(parpath, sizeof(parpath) / sizeof(WCHAR), fn);
                        
                        PathRemoveFileSpecW(parpath);
                        
                        h2 = CreateFileW(parpath, FILE_ADD_SUBDIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    
                        if (h2 == INVALID_HANDLE_VALUE) {
                            CloseHandle(h);
                            return E_FAIL;
                        }
                        
                        ignore = FALSE;
                        bg = FALSE;
                        
                        CloseHandle(h2);
                        CloseHandle(h);
                        return S_OK;
                    }
                    
                    CloseHandle(h);
                }
            }
        }
        
        return S_OK;
    }

    if (!SHGetPathFromIDListW(pidlFolder, path))
        return E_FAIL;
    
    // check we have permissions to create new subdirectory
    
    h = CreateFileW(path, FILE_ADD_SUBDIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    
    if (h == INVALID_HANDLE_VALUE)
        return E_FAIL;
    
    // check is Btrfs volume
    
    Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_FILE_IDS, NULL, 0, &bgfi, sizeof(btrfs_get_file_ids));
    
    if (!NT_SUCCESS(Status)) {
        CloseHandle(h);
        return E_FAIL;
    }
    
    CloseHandle(h);
    
    ignore = FALSE;
    bg = TRUE;
    
    return S_OK;
}

HRESULT __stdcall BtrfsContextMenu::QueryContextMenu(HMENU hmenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags) {
    WCHAR str[256];
    ULONG entries = 0;
    
    if (ignore)
        return E_INVALIDARG;
    
    if (uFlags & CMF_DEFAULTONLY)
        return S_OK;
    
    if (!bg) {
        if (LoadStringW(module, IDS_CREATE_SNAPSHOT, str, sizeof(str) / sizeof(WCHAR)) == 0)
            return E_FAIL;

        if (!InsertMenuW(hmenu, indexMenu, MF_BYPOSITION, idCmdFirst, str))
            return E_FAIL;

        return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 1);
    }
    
    if (LoadStringW(module, IDS_NEW_SUBVOL, str, sizeof(str) / sizeof(WCHAR)) == 0)
        return E_FAIL;

    if (!InsertMenuW(hmenu, indexMenu, MF_BYPOSITION, idCmdFirst, str))
        return E_FAIL;
    
    entries = 1;
    
    // FIXME - only show if files are on same volume?
    // FIXME - don't show if FS readonly
    if (idCmdFirst + 1 <= idCmdLast && IsClipboardFormatAvailable(CF_HDROP)) {
        if (LoadStringW(module, IDS_REFLINK_PASTE, str, sizeof(str) / sizeof(WCHAR)) == 0)
            return E_FAIL;

        if (!InsertMenuW(hmenu, indexMenu + 1, MF_BYPOSITION, idCmdFirst + 1, str))
            return E_FAIL;
        
        entries++;
    }

    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, entries);
}

static void create_snapshot(HWND hwnd, WCHAR* fn) {
    HANDLE h;
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    btrfs_get_file_ids bgfi;
    
    h = CreateFileW(fn, FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    
    if (h != INVALID_HANDLE_VALUE) {
        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_FILE_IDS, NULL, 0, &bgfi, sizeof(btrfs_get_file_ids));
            
        if (NT_SUCCESS(Status) && bgfi.inode == 0x100 && !bgfi.top) {
            WCHAR parpath[MAX_PATH], subvolname[MAX_PATH], templ[MAX_PATH], name[MAX_PATH], searchpath[MAX_PATH];
            HANDLE h2, fff;
            btrfs_create_snapshot* bcs;
            ULONG namelen, pathend;
            WIN32_FIND_DATAW wfd;
            SYSTEMTIME time;
            
            StringCchCopyW(parpath, sizeof(parpath) / sizeof(WCHAR), fn);
            PathRemoveFileSpecW(parpath);
            
            StringCchCopyW(subvolname, sizeof(subvolname) / sizeof(WCHAR), fn);
            PathStripPathW(subvolname);
            
            h2 = CreateFileW(parpath, FILE_ADD_SUBDIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

            if (h2 == INVALID_HANDLE_VALUE) {
                ShowError(hwnd, GetLastError());
                CloseHandle(h);
                return;
            }
            
            if (!LoadStringW(module, IDS_SNAPSHOT_FILENAME, templ, MAX_PATH)) {
                ShowError(hwnd, GetLastError());
                CloseHandle(h);
                CloseHandle(h2);
                return;
            }
            
            GetLocalTime(&time);
            
            if (StringCchPrintfW(name, sizeof(name) / sizeof(WCHAR), templ, subvolname, time.wYear, time.wMonth, time.wDay) == STRSAFE_E_INSUFFICIENT_BUFFER) {
                MessageBoxW(hwnd, L"Filename too long.\n", L"Error", MB_ICONERROR);
                CloseHandle(h);
                CloseHandle(h2);
                return;
            }
            
            StringCchCopyW(searchpath, sizeof(searchpath) / sizeof(WCHAR), parpath);
            StringCchCatW(searchpath, sizeof(searchpath) / sizeof(WCHAR), L"\\");
            pathend = wcslen(searchpath);
            
            StringCchCatW(searchpath, sizeof(searchpath) / sizeof(WCHAR), name);
            
            fff = FindFirstFileW(searchpath, &wfd);
            
            if (fff != INVALID_HANDLE_VALUE) {
                ULONG i = wcslen(searchpath), num = 2;
                
                do {
                    FindClose(fff);
                    
                    searchpath[i] = 0;
                    if (StringCchPrintfW(searchpath, sizeof(searchpath) / sizeof(WCHAR), L"%s (%u)", searchpath, num) == STRSAFE_E_INSUFFICIENT_BUFFER) {
                        MessageBoxW(hwnd, L"Filename too long.\n", L"Error", MB_ICONERROR);
                        CloseHandle(h);
                        CloseHandle(h2);
                        return;
                    }

                    fff = FindFirstFileW(searchpath, &wfd);
                    num++;
                } while (fff != INVALID_HANDLE_VALUE);
            }
            
            namelen = wcslen(&searchpath[pathend]) * sizeof(WCHAR);
                        
            bcs = (btrfs_create_snapshot*)malloc(sizeof(btrfs_create_snapshot) - 1 + namelen);
            bcs->subvol = h;
            bcs->namelen = namelen;
            memcpy(bcs->name, &searchpath[pathend], namelen);
            
            Status = NtFsControlFile(h2, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_CREATE_SNAPSHOT, NULL, 0, bcs, sizeof(btrfs_create_snapshot) - 1 + namelen);
        
            if (!NT_SUCCESS(Status))
                ShowNtStatusError(hwnd, Status);
            
            CloseHandle(h2);
        }
        
        CloseHandle(h);
    } else
        ShowError(hwnd, GetLastError());
}

BOOL BtrfsContextMenu::reflink_copy(HWND hwnd, const WCHAR* fn, const WCHAR* dir) {
    HANDLE source, dest;
    WCHAR* name;
    std::wstring dirw, newpath;
    BOOL ret = FALSE;
    FILE_BASIC_INFO fbi;
    FILETIME atime, mtime;
    
    // Thanks to 0xbadfca11, whose version of reflink for Windows provided a few pointers on what
    // to do here - https://github.com/0xbadfca11/reflink

    name = PathFindFileNameW(fn);
    
    dirw = dir;
    
    if (dir[0] != 0 && dir[wcslen(dir) - 1] != '\\')
        dirw += L"\\";
    
    newpath = dirw;
    newpath += name;
    
    // FIXME - check same filesystem
    
    source = CreateFileW(fn, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (source == INVALID_HANDLE_VALUE) {
        ShowError(hwnd, GetLastError());
        return FALSE;
    }
    
    if (!GetFileInformationByHandleEx(source, FileBasicInfo, &fbi, sizeof(FILE_BASIC_INFO))) {
        ShowError(hwnd, GetLastError());
        CloseHandle(source);
        return FALSE;
    }

    if (fbi.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        if (CreateDirectoryExW(fn, newpath.c_str(), NULL))
            dest = CreateFileW(newpath.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        else
            dest = INVALID_HANDLE_VALUE;
    } else
        dest = CreateFileW(newpath.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, 0, NULL, CREATE_NEW, 0, source);

    if (dest == INVALID_HANDLE_VALUE) {
        int num = 2;
        
        if (GetLastError() != ERROR_FILE_EXISTS && GetLastError() != ERROR_ALREADY_EXISTS && wcscmp(fn, newpath.c_str())) {
            ShowError(hwnd, GetLastError());
            CloseHandle(source);
            return FALSE;
        }
        
        do {
            WCHAR* ext;
            std::wstringstream ss;
            
            ext = PathFindExtensionW(fn);

            ss << dirw;
            
            if (*ext == 0) {
                ss << name;
                ss << L" (";
                ss << num;
                ss << L")";
            } else {
                std::wstring namew = name;
                
                ss << namew.substr(0, ext - name);
                ss << L" (";
                ss << num;
                ss << L")";
                ss << ext;
            }

            newpath = ss.str();
            if (fbi.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (CreateDirectoryExW(fn, newpath.c_str(), NULL))
                    dest = CreateFileW(newpath.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
                else
                    dest = INVALID_HANDLE_VALUE;
            } else
                dest = CreateFileW(newpath.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, 0, NULL, CREATE_NEW, 0, source);

            if (dest == INVALID_HANDLE_VALUE) {
                if (GetLastError() != ERROR_FILE_EXISTS && GetLastError() != ERROR_ALREADY_EXISTS) {
                    ShowError(hwnd, GetLastError());
                    CloseHandle(source);
                    return FALSE;
                }
                
                num++;
            } else
                break;
        } while (TRUE);
    }

    if (fbi.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        HANDLE h;
        WIN32_FIND_DATAW fff;
        std::wstring qs;
        
        qs = fn;
        qs += L"\\*";
        
        h = FindFirstFileW(qs.c_str(), &fff);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                std::wstring fn2;

                if (fff.cFileName[0] == '.' && (fff.cFileName[1] == 0 || (fff.cFileName[1] == '.' && fff.cFileName[2] == 0)))
                    continue;
                
                fn2 = fn;
                fn2 += L"\\";
                fn2 += fff.cFileName;

                if (!reflink_copy(hwnd, fn2.c_str(), newpath.c_str()))
                    goto end;
            } while (FindNextFileW(h, &fff));
            
            FindClose(h);
        }
    } else {
        FILE_STANDARD_INFO fsi;
        FILE_END_OF_FILE_INFO feofi;
        FSCTL_GET_INTEGRITY_INFORMATION_BUFFER fgiib;
        FSCTL_SET_INTEGRITY_INFORMATION_BUFFER fsiib;
        DUPLICATE_EXTENTS_DATA ded;
        INT64 offset;
        ULONG bytesret, maxdup;
        
        if (!GetFileInformationByHandleEx(source, FileStandardInfo, &fsi, sizeof(FILE_STANDARD_INFO))) {
            ShowError(hwnd, GetLastError());
            goto end;
        }

        if (!DeviceIoControl(source, FSCTL_GET_INTEGRITY_INFORMATION, NULL, 0, &fgiib, sizeof(FSCTL_GET_INTEGRITY_INFORMATION_BUFFER), &bytesret, NULL)) {
            ShowError(hwnd, GetLastError());
            goto end;
        }

        if (fbi.FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) {
            if (!DeviceIoControl(dest, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &bytesret, NULL)) {
                ShowError(hwnd, GetLastError());
                goto end;
            }
        }

        fsiib.ChecksumAlgorithm = fgiib.ChecksumAlgorithm;
        fsiib.Reserved = 0;
        fsiib.Flags = fgiib.Flags;
        if (!DeviceIoControl(dest, FSCTL_SET_INTEGRITY_INFORMATION, &fsiib, sizeof(FSCTL_SET_INTEGRITY_INFORMATION_BUFFER), NULL, 0, &bytesret, NULL)) {
            ShowError(hwnd, GetLastError());
            goto end;
        }

        feofi.EndOfFile = fsi.EndOfFile;
        if (!SetFileInformationByHandle(dest, FileEndOfFileInfo, &feofi, sizeof(FILE_END_OF_FILE_INFO))){
            ShowError(hwnd, GetLastError());
            goto end;
        }

        ded.FileHandle = source;
        maxdup = 0xffffffff - fgiib.ClusterSizeInBytes + 1;

        offset = 0;
        while (offset < fsi.AllocationSize.QuadPart) {
            ded.SourceFileOffset.QuadPart = ded.TargetFileOffset.QuadPart = offset;
            ded.ByteCount.QuadPart = maxdup < (fsi.AllocationSize.QuadPart - offset) ? maxdup : (fsi.AllocationSize.QuadPart - offset);
            if (!DeviceIoControl(dest, FSCTL_DUPLICATE_EXTENTS_TO_FILE, &ded, sizeof(DUPLICATE_EXTENTS_DATA), NULL, 0, &bytesret, NULL)) {
                ShowError(hwnd, GetLastError());
                goto end;
            }
            
            offset += ded.ByteCount.QuadPart;
        }
    }

    atime.dwLowDateTime = fbi.LastAccessTime.LowPart;
    atime.dwHighDateTime = fbi.LastAccessTime.HighPart;
    mtime.dwLowDateTime = fbi.LastWriteTime.LowPart;
    mtime.dwHighDateTime = fbi.LastWriteTime.HighPart;
    SetFileTime(dest, NULL, &atime, &mtime);
    
    // FIXME - handle subvols (do snapshot instead)
    // FIXME - handle streams
    // FIXME - copy hidden xattrs
    // FIXME - copy inode flags
    // FIXME - check EAs are copied
    
    ret = TRUE;
    
end:
    if (!ret) {
        FILE_DISPOSITION_INFO fdi;

        fdi.DeleteFile = TRUE;
        if (!SetFileInformationByHandle(dest, FileDispositionInfo, &fdi, sizeof(FILE_DISPOSITION_INFO)))
            ShowError(hwnd, GetLastError());
    }
    
    CloseHandle(dest);
    CloseHandle(source);
    
    return ret;
}

HRESULT __stdcall BtrfsContextMenu::InvokeCommand(LPCMINVOKECOMMANDINFO picia) {
    LPCMINVOKECOMMANDINFOEX pici = (LPCMINVOKECOMMANDINFOEX)picia;
    
    if (ignore)
        return E_INVALIDARG;
    
    if (!bg) {
        if ((IS_INTRESOURCE(pici->lpVerb) && pici->lpVerb == 0) || !strcmp(pici->lpVerb, SNAPSHOT_VERBA)) {
            UINT num_files, i;
            WCHAR fn[MAX_PATH];
            
            if (!stgm_set)
                return E_FAIL;
            
            num_files = DragQueryFileW((HDROP)stgm.hGlobal, 0xFFFFFFFF, NULL, 0);
            
            if (num_files == 0)
                return E_FAIL;
            
            for (i = 0; i < num_files; i++) {
                if (DragQueryFileW((HDROP)stgm.hGlobal, i, fn, sizeof(fn) / sizeof(WCHAR))) {
                    create_snapshot(pici->hwnd, fn);
                }
            }

            return S_OK;
        }
        
        return E_FAIL;
    }
    
    if ((IS_INTRESOURCE(pici->lpVerb) && (ULONG_PTR)pici->lpVerb == 0) || (!IS_INTRESOURCE(pici->lpVerb) && !strcmp(pici->lpVerb, NEW_SUBVOL_VERBA))) {
        HANDLE h;
        IO_STATUS_BLOCK iosb;
        NTSTATUS Status;
        ULONG pathlen, searchpathlen, pathend;
        WCHAR name[MAX_PATH], *searchpath;
        HANDLE fff;
        WIN32_FIND_DATAW wfd;
        
        if (!LoadStringW(module, IDS_NEW_SUBVOL_FILENAME, name, MAX_PATH)) {
            ShowError(pici->hwnd, GetLastError());
            return E_FAIL;
        }
        
        h = CreateFileW(path, FILE_ADD_SUBDIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    
        if (h == INVALID_HANDLE_VALUE) {
            ShowError(pici->hwnd, GetLastError());
            return E_FAIL;
        }
        
        pathlen = wcslen(path);
        
        searchpathlen = pathlen + wcslen(name) + 10;
        searchpath = (WCHAR*)malloc(searchpathlen * sizeof(WCHAR));
        
        StringCchCopyW(searchpath, searchpathlen, path);
        StringCchCatW(searchpath, searchpathlen, L"\\");
        pathend = wcslen(searchpath);
        
        StringCchCatW(searchpath, searchpathlen, name);
        
        fff = FindFirstFileW(searchpath, &wfd);
        
        if (fff != INVALID_HANDLE_VALUE) {
            ULONG i = wcslen(searchpath), num = 2;
            
            do {
                FindClose(fff);
                
                searchpath[i] = 0;
                if (StringCchPrintfW(searchpath, searchpathlen, L"%s (%u)", searchpath, num) == STRSAFE_E_INSUFFICIENT_BUFFER) {
                    MessageBoxW(pici->hwnd, L"Filename too long.\n", L"Error", MB_ICONERROR);
                    CloseHandle(h);
                    return E_FAIL;
                }

                fff = FindFirstFileW(searchpath, &wfd);
                num++;
            } while (fff != INVALID_HANDLE_VALUE);
        }
        
        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_CREATE_SUBVOL, NULL, 0, &searchpath[pathend], wcslen(&searchpath[pathend]) * sizeof(WCHAR));
        
        free(searchpath);
        
        if (!NT_SUCCESS(Status)) {
            CloseHandle(h);
            ShowNtStatusError(pici->hwnd, Status);
            return E_FAIL;
        }
        
        CloseHandle(h);
        
        return S_OK;
    } else if ((IS_INTRESOURCE(pici->lpVerb) && (ULONG_PTR)pici->lpVerb == 1) || (!IS_INTRESOURCE(pici->lpVerb) && !strcmp(pici->lpVerb, REFLINK_VERBA))) {
        HDROP hdrop;

        if (!IsClipboardFormatAvailable(CF_HDROP))
            return S_OK;
        
        if (!OpenClipboard(pici->hwnd)) {
            ShowError(pici->hwnd, GetLastError());
            return E_FAIL;
        }
        
        hdrop = (HDROP)GetClipboardData(CF_HDROP);
        
        if (hdrop) {
            HANDLE lh;
            
            lh = GlobalLock(hdrop);
            
            if (lh) {
                ULONG num_files, i;
                WCHAR fn[MAX_PATH];
                
                num_files = DragQueryFileW(hdrop, 0xFFFFFFFF, NULL, 0);
                
                for (i = 0; i < num_files; i++) {
                    if (DragQueryFileW(hdrop, i, fn, sizeof(fn) / sizeof(WCHAR))) {
                        if (!reflink_copy(pici->hwnd, fn, pici->lpDirectoryW)) {
                            GlobalUnlock(lh);
                            CloseClipboard();
                            return E_FAIL;
                        }
                    }
                }
                
                GlobalUnlock(lh);
            }
        }
        
        CloseClipboard();
    }
    
    return E_FAIL;
}

HRESULT __stdcall BtrfsContextMenu::GetCommandString(UINT_PTR idCmd, UINT uFlags, UINT* pwReserved, LPSTR pszName, UINT cchMax) {
    if (ignore)
        return E_INVALIDARG;
    
    if (idCmd != 0)
        return E_INVALIDARG;
    
    if (idCmd == 0) {
        switch (uFlags) {
            case GCS_HELPTEXTA:
                if (LoadStringA(module, bg ? IDS_NEW_SUBVOL_HELP_TEXT : IDS_CREATE_SNAPSHOT_HELP_TEXT, pszName, cchMax))
                    return S_OK;
                else
                    return E_FAIL;
                
            case GCS_HELPTEXTW:
                if (LoadStringW(module, bg ? IDS_NEW_SUBVOL_HELP_TEXT : IDS_CREATE_SNAPSHOT_HELP_TEXT, (LPWSTR)pszName, cchMax))
                    return S_OK;
                else
                    return E_FAIL;
                
            case GCS_VALIDATEA:
            case GCS_VALIDATEW:
                return S_OK;
                
            case GCS_VERBA:
                return StringCchCopyA(pszName, cchMax, bg ? NEW_SUBVOL_VERBA : SNAPSHOT_VERBA);
                
            case GCS_VERBW:
                return StringCchCopyW((STRSAFE_LPWSTR)pszName, cchMax, bg ? NEW_SUBVOL_VERBW : SNAPSHOT_VERBW);
                
            default:
                return E_INVALIDARG;
        }
    } else if (idCmd == 1 && bg) {
        switch (uFlags) {
            case GCS_HELPTEXTA:
                if (LoadStringA(module, IDS_REFLINK_PASTE_HELP, pszName, cchMax))
                    return S_OK;
                else
                    return E_FAIL;
                
            case GCS_HELPTEXTW:
                if (LoadStringW(module, IDS_REFLINK_PASTE_HELP, (LPWSTR)pszName, cchMax))
                    return S_OK;
                else
                    return E_FAIL;
                
            case GCS_VALIDATEA:
            case GCS_VALIDATEW:
                return S_OK;
                
            case GCS_VERBA:
                return StringCchCopyA(pszName, cchMax, REFLINK_VERBA);
                
            case GCS_VERBW:
                return StringCchCopyW((STRSAFE_LPWSTR)pszName, cchMax, REFLINK_VERBW);
                
            default:
                return E_INVALIDARG;
        }
    } else
        return E_INVALIDARG;
}
