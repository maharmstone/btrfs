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

#include <windows.h>
#include <winternl.h>
#include <shlobj.h>
#include <vector>

typedef struct {
    WCHAR* path;
} device_info;

class BtrfsDeviceAdd {
public:
    ~BtrfsDeviceAdd() {
        unsigned int i;
        
        for (i = 0; i < devpaths.size(); i++) {
            free(devpaths[i].path);
        }
        
        devpaths.clear();
    }
    
    INT_PTR CALLBACK DeviceAddDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void ShowDialog();
    void AddDevice(HWND hwndDlg);
    BtrfsDeviceAdd(HINSTANCE hinst, HWND hwnd, WCHAR* cmdline);
    
private:
    void populate_device_tree(HWND tree);
    void add_device_to_tree(HWND tree, UNICODE_STRING* us);
    void add_partition_to_tree(HWND tree, HTREEITEM parent, WCHAR* s, UINT32 partnum);
    
    HINSTANCE hinst;
    HWND hwnd;
    WCHAR* cmdline;
    device_info* sel;
    std::vector<device_info> devpaths;
};
