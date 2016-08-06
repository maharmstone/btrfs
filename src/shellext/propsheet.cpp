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
        h = CreateFileW(fn, FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

        if (h != INVALID_HANDLE_VALUE) {
            Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_INODE_INFO, NULL, 0, &bii, sizeof(btrfs_inode_info));
            CloseHandle(h);
                
            if (Status == STATUS_SUCCESS && !bii.top) {
                ignore = FALSE;
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
            
            return FALSE;
        }
    }
    
    return FALSE;
}

HRESULT __stdcall BtrfsPropSheet::AddPages(LPFNADDPROPSHEETPAGE pfnAddPage, LPARAM lParam) {
    PROPSHEETPAGE psp;
    HPROPSHEETPAGE hPage;
    
    if (ignore)
        return S_OK;
    
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
