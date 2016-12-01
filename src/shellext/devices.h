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

class BtrfsDeviceAdd {
public:
    INT_PTR CALLBACK DeviceAddDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void ShowDialog();
    void AddDevice(HWND hwndDlg);
    BtrfsDeviceAdd(HINSTANCE hinst, HWND hwnd, WCHAR* cmdline);
    
private:
    HINSTANCE hinst;
    HWND hwnd;
    WCHAR* cmdline;
    WCHAR sel[255];
};
