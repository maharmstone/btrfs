#include <windows.h>
#include "iconoverlay.h"
#include "../btrfsioctl.h"

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

HRESULT __stdcall BtrfsIconOverlay::QueryInterface(REFIID riid, void **ppObj) {
    if (riid == IID_IUnknown || riid == IID_IShellIconOverlayIdentifier) {
        *ppObj = static_cast<IShellIconOverlayIdentifier*>(this); 
        AddRef();
        return S_OK;
    }

    *ppObj = NULL;
    return E_NOINTERFACE;
}

HRESULT __stdcall BtrfsIconOverlay::GetOverlayInfo(PWSTR pwszIconFile, int cchMax, int* pIndex, DWORD* pdwFlags) {
    WCHAR dllpath[MAX_PATH];
    
    GetModuleFileNameW(module, dllpath, sizeof(dllpath));
    
    if (cchMax < wcslen(dllpath))
        return E_INVALIDARG;
    
    if (!pIndex)
        return E_INVALIDARG;
    
    if (!pdwFlags)
        return E_INVALIDARG;
    
    wcscpy(pwszIconFile, dllpath);
    *pIndex = 0;
    *pdwFlags = ISIOI_ICONFILE | ISIOI_ICONINDEX;
    
    return S_OK;
}

HRESULT __stdcall BtrfsIconOverlay::GetPriority(int *pPriority) {
    if (!pPriority)
        return E_INVALIDARG;
    
    *pPriority = 0;
    
    return S_OK;
}

HRESULT __stdcall BtrfsIconOverlay::IsMemberOf(PCWSTR pwszPath, DWORD dwAttrib) {
    HANDLE h;
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    btrfs_get_file_ids bgfi;
    
    // FIXME - return S_FALSE for volume root
     
    h = CreateFileW(pwszPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    
    if (h == INVALID_HANDLE_VALUE)
        return S_FALSE;
    
    Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_FILE_IDS, NULL, 0, &bgfi, sizeof(btrfs_get_file_ids));
    
    if (Status != STATUS_SUCCESS) {
        CloseHandle(h);
        return S_FALSE;
    }

    CloseHandle(h);
    
    return (bgfi.inode == 0x100 && !bgfi.top) ? S_OK : S_FALSE;
}
