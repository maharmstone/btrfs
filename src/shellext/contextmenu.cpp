#include <windows.h>
#include <strsafe.h>
#include <winternl.h>

#include "contextmenu.h"
#include "resource.h"
#include "../btrfsioctl.h"

#define NEW_SUBVOL_VERBA "newsubvol"
#define NEW_SUBVOL_VERBW L"newsubvol"

// FIXME - is there a way to link to the proper header files without breaking everything?
#ifdef __cplusplus
extern "C" {
#endif
NTSYSCALLAPI NTSTATUS NTAPI NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
#ifdef __cplusplus
}
#endif
#define STATUS_SUCCESS 0

typedef ULONG (WINAPI *_RtlNtStatusToDosError)(NTSTATUS Status);

extern HMODULE module;

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

    if (!SHGetPathFromIDListW(pidlFolder, path))
        return E_FAIL;
    
    // check we have permissions to create new subdirectory
    
    h = CreateFileW(path, FILE_ADD_SUBDIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    
    if (h == INVALID_HANDLE_VALUE)
        return E_FAIL;
    
    // check is Btrfs volume
    
    Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_FILE_IDS, NULL, 0, &bgfi, sizeof(btrfs_get_file_ids));
    
    if (Status != STATUS_SUCCESS) {
        CloseHandle(h);
        return E_FAIL;
    }
    
    CloseHandle(h);
    
    ignore = FALSE;
    
    return S_OK;
}

HRESULT __stdcall BtrfsContextMenu::QueryContextMenu(HMENU hmenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags) {
    WCHAR str[256];
    
    if (ignore)
        return E_INVALIDARG;
    
    if (uFlags & CMF_DEFAULTONLY)
        return S_OK;
    
    if (LoadStringW(module, IDS_NEW_SUBVOL, str, sizeof(str) / sizeof(WCHAR)) == 0)
        return E_FAIL;

    if (!InsertMenuW(hmenu, indexMenu, MF_BYPOSITION, idCmdFirst, str))
        return E_FAIL;

    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 1);
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

static void ShowNtStatusError(HWND hwnd, NTSTATUS Status) {
    _RtlNtStatusToDosError RtlNtStatusToDosError;
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    
    if (!ntdll) {
        MessageBoxW(hwnd, L"Error loading ntdll.dll", L"Error", MB_ICONERROR);
        return;
    }
    
    RtlNtStatusToDosError = (_RtlNtStatusToDosError)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    
    if (!ntdll) {
        MessageBoxW(hwnd, L"Error loading RtlNtStatusToDosError in ntdll.dll", L"Error", MB_ICONERROR);
        FreeLibrary(ntdll);
        return;
    }
    
    ShowError(hwnd, RtlNtStatusToDosError(Status));
    
    FreeLibrary(ntdll);
}

HRESULT __stdcall BtrfsContextMenu::InvokeCommand(LPCMINVOKECOMMANDINFO pici) {
    if (ignore)
        return E_INVALIDARG;
    
    if ((IS_INTRESOURCE(pici->lpVerb) && pici->lpVerb == 0) || !strcmp(pici->lpVerb, NEW_SUBVOL_VERBA)) {
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
        
        // FIXME - if already exists, append " (2)" etc.
        
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
                StringCchPrintfW(searchpath, searchpathlen, L"%s (%u)", searchpath, num);

                fff = FindFirstFileW(searchpath, &wfd);
                num++;
            } while (fff != INVALID_HANDLE_VALUE);
        }
        
        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_CREATE_SUBVOL, NULL, 0, &searchpath[pathend], wcslen(&searchpath[pathend]) * sizeof(WCHAR));
        
        free(searchpath);
        
        if (Status != STATUS_SUCCESS) {
            CloseHandle(h);
            ShowNtStatusError(pici->hwnd, Status);
            return E_FAIL;
        }
        
        CloseHandle(h);
        
        return S_OK;
    }
    
    return E_FAIL;
}

HRESULT __stdcall BtrfsContextMenu::GetCommandString(UINT_PTR idCmd, UINT uFlags, UINT* pwReserved, LPSTR pszName, UINT cchMax) {
    if (ignore)
        return E_INVALIDARG;
    
    if (idCmd != 0)
        return E_INVALIDARG;
    
    switch (uFlags) {
        case GCS_HELPTEXTA:
            if (LoadStringA(module, IDS_NEW_SUBVOL_HELP_TEXT, pszName, cchMax))
                return S_OK;
            else
                return E_FAIL;
            
        case GCS_HELPTEXTW:
            if (LoadStringW(module, IDS_NEW_SUBVOL_HELP_TEXT, (LPWSTR)pszName, cchMax))
                return S_OK;
            else
                return E_FAIL;
            
        case GCS_VALIDATEA:
        case GCS_VALIDATEW:
            return S_OK;
            
        case GCS_VERBA:
            return StringCchCopyA(pszName, cchMax, NEW_SUBVOL_VERBA);
            
        case GCS_VERBW:
            return StringCchCopyW((STRSAFE_LPWSTR)pszName, cchMax, NEW_SUBVOL_VERBW);
            
        default:
            return E_INVALIDARG;
    }
}
