#include <windows.h>
#include <strsafe.h>

#include "contextmenu.h"
#include "resource.h"
#include "../btrfsioctl.h"

#define NEW_SUBVOL_VERBA "newsubvol"
#define NEW_SUBVOL_VERBW L"newsubvol"

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  } DUMMYUNIONNAME;
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID
(NTAPI *PIO_APC_ROUTINE)(
  IN PVOID ApcContext,
  IN PIO_STATUS_BLOCK IoStatusBlock,
  IN ULONG Reserved);

#ifdef __cplusplus
extern "C" {
#endif
NTSYSCALLAPI NTSTATUS NTAPI NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
#ifdef __cplusplus
}
#endif
#define STATUS_SUCCESS 0

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
    WCHAR path[MAX_PATH];
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

    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, idCmdFirst + 1);
}

HRESULT __stdcall BtrfsContextMenu::InvokeCommand(LPCMINVOKECOMMANDINFO pici) {
    if (ignore)
        return E_INVALIDARG;
    
    if ((IS_INTRESOURCE(pici->lpVerb) && pici->lpVerb == 0) || !strcmp(pici->lpVerb, NEW_SUBVOL_VERBA)) {
        MessageBoxW(pici->hwnd, L"new subvol", 0, 0);
        
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
