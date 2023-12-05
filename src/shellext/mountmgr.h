#pragma once

#include <vector>
#include <string>
#include <sstream>
#include <string_view>
#include <iostream>
#include <iomanip>

class mountmgr_point {
public:
    mountmgr_point(std::wstring_view symlink, std::string_view unique_id, std::wstring_view device_name) : symlink(symlink), device_name(device_name), unique_id(unique_id) {
    }

    std::wstring symlink, device_name;
    std::string unique_id;
};

class mountmgr {
public:
    mountmgr();
    ~mountmgr();
    void create_point(std::wstring_view symlink, std::wstring_view device) const;
    void delete_points(std::wstring_view symlink, std::wstring_view unique_id = L"", std::wstring_view device_name = L"") const;
    std::vector<mountmgr_point> query_points(std::wstring_view symlink = L"", std::wstring_view unique_id = L"", std::wstring_view device_name = L"") const;

private:
    HANDLE h;
};
