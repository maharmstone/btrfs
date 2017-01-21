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
#define STRSAFE_NO_DEPRECATE

#include "shellext.h"
#include "devices.h"
#include "resource.h"
#include "balance.h"
#include <uxtheme.h>
#include <setupapi.h>
#include <strsafe.h>
#include <mountmgr.h>
#include <algorithm>
#include <string>
#include "../btrfs.h"

typedef struct {
    std::wstring pnp_name;
    std::wstring friendly_name;
    std::wstring drive;
    std::wstring fstype;
    ULONG disk_num;
    ULONG part_num;
    UINT64 size;
} device;

DEFINE_GUID(GUID_DEVINTERFACE_HIDDEN_VOLUME, 0x7f108a28L, 0x9833, 0x4b3b, 0xb7, 0x80, 0x2c, 0x6b, 0x5f, 0xa5, 0xc0, 0x62);

void find_devices(HWND hwnd, const GUID* guid, HANDLE mountmgr, std::vector<device>* device_list) {
    HDEVINFO h;
    
    static WCHAR dosdevices[] = L"\\DosDevices\\";

    h = SetupDiGetClassDevs(guid, NULL, 0, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    
    if (h != INVALID_HANDLE_VALUE) {
        DWORD index = 0;
        SP_DEVICE_INTERFACE_DATA did;
        
        did.cbSize = sizeof(did);
        
        if (!SetupDiEnumDeviceInterfaces(h, NULL, guid, index, &did))
            return;

        do {
            SP_DEVINFO_DATA dd;
            SP_DEVICE_INTERFACE_DETAIL_DATA_W* detail;
            DWORD size;
            
            dd.cbSize = sizeof(dd);
                
            SetupDiGetDeviceInterfaceDetailW(h, &did, NULL, 0, &size, NULL);

            detail = (SP_DEVICE_INTERFACE_DETAIL_DATA_W*)malloc(size);
            memset(detail, 0, size);
            
            detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

            if (SetupDiGetDeviceInterfaceDetailW(h, &did, detail, size, &size, &dd)) {
                NTSTATUS Status;
                HANDLE file;
                device dev;
                STORAGE_DEVICE_NUMBER sdn;
                IO_STATUS_BLOCK iosb;
                UNICODE_STRING path;
                OBJECT_ATTRIBUTES attr;
                GET_LENGTH_INFORMATION gli;
                ULONG i;
                UINT8 sb[4096];
                
                path.Buffer = detail->DevicePath;
                path.Length = path.MaximumLength = wcslen(detail->DevicePath) * sizeof(WCHAR);
                
                if (path.Length > 4 * sizeof(WCHAR) && path.Buffer[0] == '\\' && path.Buffer[1] == '\\'  && path.Buffer[2] == '?'  && path.Buffer[3] == '\\')
                    path.Buffer[1] = '?';
                
                InitializeObjectAttributes(&attr, &path, 0, NULL, NULL);
    
                Status = NtOpenFile(&file, FILE_GENERIC_READ, &attr, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_ALERT);
                
                if (!NT_SUCCESS(Status))
                    goto nextitem2;
                
                dev.pnp_name = detail->DevicePath;
                
                Status = NtDeviceIoControlFile(file, NULL, NULL, NULL, &iosb, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &gli, sizeof(GET_LENGTH_INFORMATION));
                if (!NT_SUCCESS(Status))
                    goto nextitem;
                
                dev.size = gli.Length.QuadPart;
                
                Status = NtDeviceIoControlFile(file, NULL, NULL, NULL, &iosb, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &sdn, sizeof(STORAGE_DEVICE_NUMBER));
                if (!NT_SUCCESS(Status)) {
                    dev.disk_num = 0xffffffff;
                    dev.part_num = 0xffffffff;
                } else {
                    // FIXME - exclude floppies etc.
                    dev.disk_num = sdn.DeviceNumber;
                    dev.part_num = sdn.PartitionNumber;
                }
                
                dev.friendly_name = L"";
                dev.drive = L"";
                dev.fstype = L"";
                
                i = 0;
                while (fs_ident[i].name) {
                    if (i == 0 || fs_ident[i].kboff != fs_ident[i-1].kboff) {
                        LARGE_INTEGER off;
                        
                        off.QuadPart = fs_ident[i].kboff * 1024;
                        Status = NtReadFile(file, NULL, NULL, NULL, &iosb, sb, sizeof(sb), &off, NULL);
                    }
                    
                    if (NT_SUCCESS(Status)) {
                        if (RtlCompareMemory(sb + fs_ident[i].sboff, fs_ident[i].magic, fs_ident[i].magiclen) == fs_ident[i].magiclen) {
                            dev.fstype = fs_ident[i].name;
                            break;
                        }
                        // FIXME - Btrfs
                    }
                    
                    i++;
                }
                
                if (RtlCompareMemory(guid, &GUID_DEVINTERFACE_DISK, sizeof(GUID)) == sizeof(GUID)) {
                    STORAGE_PROPERTY_QUERY spq;
                    STORAGE_DEVICE_DESCRIPTOR sdd, *sdd2;
                    
                    spq.PropertyId = StorageDeviceProperty;
                    spq.QueryType = PropertyStandardQuery;
                    spq.AdditionalParameters[0] = 0;
                    
                    Status = NtDeviceIoControlFile(file, NULL, NULL, NULL, &iosb, IOCTL_STORAGE_QUERY_PROPERTY,
                                                   &spq, sizeof(STORAGE_PROPERTY_QUERY), &sdd, sizeof(STORAGE_DEVICE_DESCRIPTOR));
                    
                    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW) {
                        sdd2 = (STORAGE_DEVICE_DESCRIPTOR*)malloc(sdd.Size);
                        
                        Status = NtDeviceIoControlFile(file, NULL, NULL, NULL, &iosb, IOCTL_STORAGE_QUERY_PROPERTY,
                                                    &spq, sizeof(STORAGE_PROPERTY_QUERY), sdd2, sdd.Size);
                        if (NT_SUCCESS(Status)) {
                            std::string desc2;
                            
                            desc2 = "";
                            
                            if (sdd2->VendorIdOffset != 0)
                                desc2 += (char*)((UINT8*)sdd2 + sdd2->VendorIdOffset);
                            
                            if (sdd2->ProductIdOffset != 0) {
                                if (sdd2->VendorIdOffset != 0 && desc2.length() != 0 && desc2[desc2.length() - 1] != ' ')
                                    desc2 += " ";
                                
                                desc2 += (char*)((UINT8*)sdd2 + sdd2->ProductIdOffset);
                            }
                            
                            if (sdd2->VendorIdOffset != 0 || sdd2->ProductIdOffset != 0) {
                                ULONG ss;
                                
                                ss = MultiByteToWideChar(CP_OEMCP, MB_PRECOMPOSED, desc2.c_str(), -1, NULL, 0);
                                
                                if (ss > 0) {
                                    WCHAR* desc3 = (WCHAR*)malloc(ss * sizeof(WCHAR));
                                    
                                    if (MultiByteToWideChar(CP_OEMCP, MB_PRECOMPOSED, desc2.c_str(), -1, desc3, ss * sizeof(WCHAR)))
                                        dev.friendly_name = desc3;
                                    
                                    free(desc3);
                                }
                            }
                        }
                        
                        free(sdd2);
                    }
                } else {
                    ULONG mmpsize;
                    MOUNTMGR_MOUNT_POINT* mmp;
                    MOUNTMGR_MOUNT_POINTS mmps;
                    
                    mmpsize = sizeof(MOUNTMGR_MOUNT_POINT) + path.Length;
 
                    mmp = (MOUNTMGR_MOUNT_POINT*)malloc(mmpsize);

                    RtlZeroMemory(mmp, sizeof(MOUNTMGR_MOUNT_POINT));
                    mmp->DeviceNameOffset = sizeof(MOUNTMGR_MOUNT_POINT);
                    mmp->DeviceNameLength = path.Length;
                    RtlCopyMemory(&mmp[1], path.Buffer, path.Length);

                    Status = NtDeviceIoControlFile(mountmgr, NULL, NULL, NULL, &iosb, IOCTL_MOUNTMGR_QUERY_POINTS,
                                                   mmp, mmpsize, &mmps, sizeof(MOUNTMGR_MOUNT_POINTS));
                    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW) {
                        MOUNTMGR_MOUNT_POINTS* mmps2;

                        mmps2 = (MOUNTMGR_MOUNT_POINTS*)malloc(mmps.Size);
                        
                        Status = NtDeviceIoControlFile(mountmgr, NULL, NULL, NULL, &iosb, IOCTL_MOUNTMGR_QUERY_POINTS,
                                                    mmp, mmpsize, mmps2, mmps.Size);
                        
                        if (NT_SUCCESS(Status)) {
                            ULONG i;
                        
                            for (i = 0; i < mmps2->NumberOfMountPoints; i++) {
                                WCHAR* symlink = (WCHAR*)((UINT8*)mmps2 + mmps2->MountPoints[i].SymbolicLinkNameOffset);
                                
                                if (mmps2->MountPoints[i].SymbolicLinkNameLength == 0x1c &&
                                    RtlCompareMemory(symlink, dosdevices, wcslen(dosdevices) * sizeof(WCHAR)) == wcslen(dosdevices) * sizeof(WCHAR) &&
                                    symlink[13] == ':'
                                ) {
                                    WCHAR dr[3];
                                    
                                    dr[0] = symlink[12];
                                    dr[1] = ':';
                                    dr[2] = 0;
                                    
                                    dev.drive = dr;
                                    break;
                                }
                            }
                        }
                    }
                    
                    free(mmp);
                }
                
                // FIXME - if disk, check for partitions
                // FIXME - exclude Btrfs volumes
                
                device_list->push_back(dev);
                
nextitem:
                NtClose(file);
            }

nextitem2:
            free(detail);
            
            index++;
        } while (SetupDiEnumDeviceInterfaces(h, NULL, guid, index, &did));

        SetupDiDestroyDeviceInfoList(h);
    } else {
        ShowError(hwnd, GetLastError());
        return;
    }
}

static bool sort_devices(device i, device j) {
    if (i.disk_num < j.disk_num)
        return true;
    
    if (i.disk_num == j.disk_num && i.part_num < j.part_num)
        return true;
    
    return false;
}

void BtrfsDeviceAdd::populate_device_tree(HWND tree) {
    HWND hwnd = GetParent(tree);
    std::vector<device> device_list;
    unsigned int i;
    ULONG last_disk_num = 0xffffffff;
    HTREEITEM diskitem;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING us;
    IO_STATUS_BLOCK iosb;
    HANDLE mountmgr;
    
    RtlInitUnicodeString(&us, MOUNTMGR_DEVICE_NAME);
    InitializeObjectAttributes(&attr, &us, 0, NULL, NULL);
    
    Status = NtOpenFile(&mountmgr, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb,
                        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_ALERT);
    if (!NT_SUCCESS(Status)) {
        MessageBoxW(hwnd, L"Could not get handle to mount manager.", L"Error", MB_ICONERROR);
        return;
    }
    
    find_devices(hwnd, &GUID_DEVINTERFACE_DISK, mountmgr, &device_list);
    find_devices(hwnd, &GUID_DEVINTERFACE_VOLUME, mountmgr, &device_list);
    find_devices(hwnd, &GUID_DEVINTERFACE_HIDDEN_VOLUME, mountmgr, &device_list);
    
    NtClose(mountmgr);
    
    std::sort(device_list.begin(), device_list.end(), sort_devices);
    
    for (i = 0; i < device_list.size(); i++) {
        TVINSERTSTRUCTW tis;
        HTREEITEM item;
        std::wstring name;
        WCHAR size[255];
        
        if (device_list[i].disk_num != 0xffffffff && device_list[i].disk_num == last_disk_num)
            tis.hParent = diskitem;
        else
            tis.hParent = TVI_ROOT;
        
        tis.hInsertAfter = TVI_LAST;
        tis.itemex.mask = TVIF_TEXT | TVIF_STATE | TVIF_PARAM;
        tis.itemex.state = TVIS_EXPANDED;
        tis.itemex.stateMask = TVIS_EXPANDED;
        
        if (device_list[i].disk_num != 0xffffffff) {
            WCHAR t[255], u[255];
            
            if (!LoadStringW(module, device_list[i].part_num != 0 ? IDS_PARTITION : IDS_DISK_NUM, t, sizeof(t) / sizeof(WCHAR))) {
                ShowError(hwnd, GetLastError());
                return;
            }
            
            if (StringCchPrintfW(u, sizeof(u) / sizeof(WCHAR), t, device_list[i].part_num != 0 ? device_list[i].part_num : device_list[i].disk_num) == STRSAFE_E_INSUFFICIENT_BUFFER)
                return;
            
            name = u;
        } else
            name = device_list[i].pnp_name;
        
        // FIXME - Btrfs devices
        
        name += L" (";
        
        if (device_list[i].friendly_name != L"") {
            name += device_list[i].friendly_name;
            name += L", ";
        }
        
        if (device_list[i].drive != L"") {
            name += device_list[i].drive;
            name += L", ";
        }
        
        if (device_list[i].fstype != L"") {
            name += device_list[i].fstype;
            name += L", ";
        }
        
        format_size(device_list[i].size, size, sizeof(size) / sizeof(WCHAR), FALSE);
        name += size;
        
        name += L")";
        
        tis.itemex.pszText = (WCHAR*)name.c_str();
        tis.itemex.cchTextMax = name.length();
        tis.itemex.lParam = 0;
        
        item = (HTREEITEM)SendMessageW(tree, TVM_INSERTITEMW, 0, (LPARAM)&tis);
        if (!item) {
            MessageBoxW(hwnd, L"TVM_INSERTITEM failed", L"Error", MB_ICONERROR);
            return;
        }
        
        if (device_list[i].part_num == 0) {
            diskitem = item;
            last_disk_num = device_list[i].disk_num;
        }
    }
}

void BtrfsDeviceAdd::AddDevice(HWND hwndDlg) {
    WCHAR mess[255], title[255];
    NTSTATUS Status;
    UNICODE_STRING vn;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE h, h2;
    
    if (!sel) {
        EndDialog(hwndDlg, 0);
        return;
    }
    
    if (sel->fstype) {
        WCHAR s[255];
        
        if (!LoadStringW(module, IDS_ADD_DEVICE_CONFIRMATION_FS, s, sizeof(s) / sizeof(WCHAR))) {
            ShowError(hwndDlg, GetLastError());
            return;
        }
        
        if (StringCchPrintfW(mess, sizeof(mess) / sizeof(WCHAR), s, sel->fstype) == STRSAFE_E_INSUFFICIENT_BUFFER)
            return;
    } else {
        if (!LoadStringW(module, IDS_ADD_DEVICE_CONFIRMATION, mess, sizeof(mess) / sizeof(WCHAR))) {
            ShowError(hwndDlg, GetLastError());
            return;
        }
    }
        
    if (!LoadStringW(module, IDS_CONFIRMATION_TITLE, title, sizeof(title) / sizeof(WCHAR))) {
        ShowError(hwndDlg, GetLastError());
        return;
    }
    
    if (MessageBoxW(hwndDlg, mess, title, MB_YESNO) != IDYES)
        return;
    
    h = CreateFileW(cmdline, FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    
    if (h == INVALID_HANDLE_VALUE) {
        ShowError(hwndDlg, GetLastError());
        return;
    }
    
    vn.Length = vn.MaximumLength = wcslen(sel->path) * sizeof(WCHAR);
    vn.Buffer = sel->path;

    InitializeObjectAttributes(&attr, &vn, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = NtOpenFile(&h2, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_ALERT);
    if (!NT_SUCCESS(Status)) {
        ShowNtStatusError(hwndDlg, Status);
        CloseHandle(h);
        return;
    }

    Status = NtFsControlFile(h2, NULL, NULL, NULL, &iosb, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0);
    if (!NT_SUCCESS(Status)) {
        ShowNtStatusError(hwndDlg, Status);
        NtClose(h2);
        CloseHandle(h);
        return;
    }

    Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_ADD_DEVICE, &h2, sizeof(HANDLE), NULL, 0);
    if (!NT_SUCCESS(Status)) {
        ShowNtStatusError(hwndDlg, Status);
        NtClose(h2);
        CloseHandle(h);
        return;
    }
    
    Status = NtFsControlFile(h2, NULL, NULL, NULL, &iosb, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0);
    if (!NT_SUCCESS(Status))
        ShowNtStatusError(hwndDlg, Status);
    
    Status = NtFsControlFile(h2, NULL, NULL, NULL, &iosb, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0);
    if (!NT_SUCCESS(Status))
        ShowNtStatusError(hwndDlg, Status);
    
    NtClose(h2);
    CloseHandle(h);
    
    EndDialog(hwndDlg, 0);
}

INT_PTR CALLBACK BtrfsDeviceAdd::DeviceAddDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
        {
            EnableThemeDialogTexture(hwndDlg, ETDT_ENABLETAB);
            populate_device_tree(GetDlgItem(hwndDlg, IDC_DEVICE_TREE));
            EnableWindow(GetDlgItem(hwndDlg, IDOK), FALSE);
            break;
        }
        
        case WM_COMMAND:
            switch (HIWORD(wParam)) {
                case BN_CLICKED:
                    switch (LOWORD(wParam)) {
                        case IDOK:
                            AddDevice(hwndDlg);
                        return TRUE;
                        
                        case IDCANCEL:
                            EndDialog(hwndDlg, 0);
                        return TRUE;
                    }
                break;
            }
        break;
        
        case WM_NOTIFY:
            switch (((LPNMHDR)lParam)->code) {
                case TVN_SELCHANGEDW:
                {
                    NMTREEVIEWW* nmtv = (NMTREEVIEWW*)lParam;
                    TVITEMW tvi;
                    BOOL enable = FALSE;
                    
                    RtlZeroMemory(&tvi, sizeof(TVITEMW));
                    tvi.hItem = nmtv->itemNew.hItem;
                    tvi.mask = TVIF_PARAM | TVIF_HANDLE;
                    
                    if (SendMessageW(GetDlgItem(hwndDlg, IDC_DEVICE_TREE), TVM_GETITEMW, 0, (LPARAM)&tvi))
                        sel = tvi.lParam == 0 ? NULL : &devpaths[tvi.lParam - 1];
                    else
                        sel = NULL;
                    
                    if (sel)
                        enable = !sel->multi_device;
                    
                    EnableWindow(GetDlgItem(hwndDlg, IDOK), enable);
                    break;
                }
            }
        break;
    }
    
    return FALSE;
}

static INT_PTR CALLBACK stub_DeviceAddDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BtrfsDeviceAdd* bda;
    
    if (uMsg == WM_INITDIALOG) {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);
        bda = (BtrfsDeviceAdd*)lParam;
    } else {
        bda = (BtrfsDeviceAdd*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
    }
    
    if (bda)
        return bda->DeviceAddDlgProc(hwndDlg, uMsg, wParam, lParam);
    else
        return FALSE;
}

void BtrfsDeviceAdd::ShowDialog() {
    DialogBoxParamW(module, MAKEINTRESOURCEW(IDD_DEVICE_ADD), hwnd, stub_DeviceAddDlgProc, (LPARAM)this);
}

BtrfsDeviceAdd::BtrfsDeviceAdd(HINSTANCE hinst, HWND hwnd, WCHAR* cmdline) {
    this->hinst = hinst;
    this->hwnd = hwnd;
    this->cmdline = cmdline;
    
    sel = NULL;
}

#ifdef __cplusplus
extern "C" {
#endif

void CALLBACK AddDeviceW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BtrfsDeviceAdd* bda;
    
    set_dpi_aware();
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        ShowError(hwnd, GetLastError());
        return;
    }
    
    if (!LookupPrivilegeValueW(NULL, L"SeManageVolumePrivilege", &luid)) {
        ShowError(hwnd, GetLastError());
        goto end;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        ShowError(hwnd, GetLastError());
        goto end;
    }
    
    bda = new BtrfsDeviceAdd(hinst, hwnd, lpszCmdLine);
    bda->ShowDialog();
    delete bda;
    
end:
    CloseHandle(token);
}

void CALLBACK RemoveDeviceW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) {
    WCHAR *s, *vol, *dev;
    UINT64 devid;
    HANDLE h, token;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    BtrfsBalance* bb;
    
    set_dpi_aware();
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        ShowError(hwnd, GetLastError());
        return;
    }
    
    if (!LookupPrivilegeValueW(NULL, L"SeManageVolumePrivilege", &luid)) {
        ShowError(hwnd, GetLastError());
        goto end;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        ShowError(hwnd, GetLastError());
        goto end;
    }
    
    s = wcsstr(lpszCmdLine, L"|");
    if (!s)
        goto end;
    
    s[0] = 0;
    
    vol = lpszCmdLine;
    dev = &s[1];
    
    devid = _wtoi(dev);
    if (devid == 0)
        goto end;
    
    h = CreateFileW(vol, FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    
    if (h == INVALID_HANDLE_VALUE) {
        ShowError(hwnd, GetLastError());
        goto end;
    }
    
    Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_REMOVE_DEVICE, &devid, sizeof(UINT64), NULL, 0);
    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_CANNOT_DELETE)
            ShowStringError(hwnd, IDS_CANNOT_REMOVE_RAID);
        else
            ShowNtStatusError(hwnd, Status);
        
        CloseHandle(h);
        goto end;
    }
    
    CloseHandle(h);
    
    bb = new BtrfsBalance(vol, TRUE);
    
    bb->ShowBalance(hwnd);
    
    delete bb;
    
end:
    CloseHandle(token);
}

#ifdef __cplusplus
}
#endif
