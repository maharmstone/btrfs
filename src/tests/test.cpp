/* Copyright (c) Mark Harmstone 2021
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

#include "test.h"
#include <wincon.h>
#include <winsvc.h>
#include <functional>

using namespace std;

enum fs_type fstype;

static unsigned int num_tests_run, num_tests_passed;

unique_handle create_file(const u16string_view& path, ACCESS_MASK access, ULONG atts, ULONG share,
                          ULONG dispo, ULONG options, ULONG_PTR exp_info, optional<uint64_t> allocation) {
    NTSTATUS Status;
    HANDLE h;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    LARGE_INTEGER alloc_size;

    oa.Length = sizeof(oa);
    oa.RootDirectory = nullptr; // FIXME - test

    us.Length = us.MaximumLength = path.length() * sizeof(char16_t);
    us.Buffer = (WCHAR*)path.data();
    oa.ObjectName = &us;

    oa.Attributes = OBJ_CASE_INSENSITIVE; // FIXME - test
    oa.SecurityDescriptor = nullptr; // FIXME - test
    oa.SecurityQualityOfService = nullptr; // FIXME - test(?)

    if (allocation)
        alloc_size.QuadPart = allocation.value();

    // FIXME - EaBuffer and EaLength

    iosb.Information = 0xdeadbeef;

    Status = NtCreateFile(&h, access, &oa, &iosb, allocation ? &alloc_size : nullptr,
                          atts, share, dispo, options, nullptr, 0);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != exp_info)
        throw formatted_error("iosb.Information was {}, expected {}", iosb.Information, exp_info);

    return unique_handle(h);
}

void test(const string& msg, const function<void()>& func) {
    string err;
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    num_tests_run++;

    try {
        func();
    } catch (const exception& e) {
        err = e.what();
    } catch (...) {
        err = "Uncaught exception.";
    }

    // FIXME - aligned output?

    fmt::print("{}, ", msg);

    auto col = GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);

    if (col)
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), err.empty() ? FOREGROUND_GREEN : (FOREGROUND_RED | FOREGROUND_INTENSITY));

    fmt::print("{}", err.empty() ? "PASS" : "FAIL");

    if (col)
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), csbi.wAttributes);

    if (!err.empty())
        fmt::print(" ({})", err);
    else
        num_tests_passed++;

    fmt::print("\n");
}

void exp_status(const function<void()>& func, NTSTATUS Status) {
    try {
        func();
    } catch (const ntstatus_error& e) {
        if (e.Status != Status)
            throw formatted_error("Status was {}, expected {}", ntstatus_to_string(e.Status), ntstatus_to_string(Status));
        else
            return;
    }

    if (Status != STATUS_SUCCESS)
        throw formatted_error("Status was STATUS_SUCCESS, expected {}", ntstatus_to_string(Status));
}

u16string query_file_name_information(HANDLE h) {
    IO_STATUS_BLOCK iosb;
    NTSTATUS Status;
    FILE_NAME_INFORMATION fni;

    fni.FileNameLength = 0;

    Status = NtQueryInformationFile(h, &iosb, &fni, sizeof(fni), FileNameInformation);

    if (Status != STATUS_SUCCESS && Status != STATUS_BUFFER_OVERFLOW)
        throw ntstatus_error(Status);

    vector<uint8_t> buf(offsetof(FILE_NAME_INFORMATION, FileName) + fni.FileNameLength);

    auto& fni2 = *reinterpret_cast<FILE_NAME_INFORMATION*>(buf.data());

    fni2.FileNameLength = buf.size() - offsetof(FILE_NAME_INFORMATION, FileName);

    Status = NtQueryInformationFile(h, &iosb, &fni2, buf.size(), FileNameInformation);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != buf.size())
        throw formatted_error("iosb.Information was {}, expected {}", iosb.Information, buf.size());

    u16string ret;

    ret.resize(fni.FileNameLength / sizeof(char16_t));

    memcpy(ret.data(), fni2.FileName, fni.FileNameLength);

    return ret;
}

static unique_handle open_process_token(HANDLE process, ACCESS_MASK access) {
    NTSTATUS Status;
    HANDLE h;

    Status = NtOpenProcessToken(process, access, &h);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    return unique_handle(h);
}

void disable_token_privileges(HANDLE token) {
    NTSTATUS Status;

    Status = NtAdjustPrivilegesToken(token, true, nullptr, 0, nullptr, nullptr);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

static void write_console(const u16string_view& str) {
    WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), str.data(), str.length(), nullptr, nullptr);
}

static void do_tests(const u16string_view& name, const u16string& dir) {
    auto token = open_process_token(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY);

    disable_token_privileges(token.get());

    static const struct {
        u16string_view name;
        function<void()> func;
    } testfuncs[] = {
        { u"create", [&]() { test_create(dir); } },
        { u"supersede", [&]() { test_supersede(dir); } },
        { u"overwrite", [&]() { test_overwrite(dir); } },
        { u"io", [&]() { test_io(token.get(), dir); } },
    };

    bool first = true;
    unsigned int total_tests_run = 0, total_tests_passed = 0;

    for (const auto& tf : testfuncs) {
        if (name == u"all" || tf.name == name) {
            CONSOLE_SCREEN_BUFFER_INFO csbi;

            auto col = GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);

            if (col) {
                SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
                                        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            }

            if (!first)
                write_console(u"\n");

            write_console(u"Running test ");
            write_console(tf.name);
            write_console(u"\n");

            if (col)
                SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), csbi.wAttributes);

            num_tests_run = 0;
            num_tests_passed = 0;

            tf.func();

            total_tests_run += num_tests_run;
            total_tests_passed += num_tests_passed;

            fmt::print("Passed {}/{}\n", num_tests_passed, num_tests_run);

            first = false;

            if (name != u"all")
                break;
        }
    }

    // FIXME - check with case-sensitive flag set

    // FIXME - memory mapping (inc. attempted delete, truncate, etc.)

    // FIXME - reparse points (opening, opening following link, creating, setting, querying tag)

    // FIXME - ADSes (including prohibited names)

    // FIXME - EAs
    // FIXME - FILE_NO_EA_KNOWLEDGE

    // FIXME - renaming (check names before and after)
    // FIXME - moving
    // FIXME - renaming by overwrite (if different case, will be filename be old or new?)
    // FIXME - POSIX renames
    // FIXME - FILE_RENAME_IGNORE_READONLY_ATTRIBUTE
    // FIXME - check invalid names (invalid characters, > 255 UTF-16, > 255 UTF-8, invalid UTF-16)

    // FIXME - deletion (file, empty directory, non-empty directory, opening doomed file, commuting sentence)
    // FIXME - POSIX deletion
    // FIXME - FILE_DELETE_ON_CLOSE
    // FIXME - FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK
    // FIXME - FILE_DISPOSITION_ON_CLOSE
    // FIXME - FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE

    // FIXME - hard links
    // FIXME - linking by overwrite
    // FIXME - POSIX hard links
    // FIXME - FILE_LINK_IGNORE_READONLY_ATTRIBUTE
    // FIXME - check invalid names (invalid characters, > 255 UTF-16, > 255 UTF-8, invalid UTF-16)

    // FIXME - setting file information

    // FIXME - querying SD
    // FIXME - setting SD
    // FIXME - inheriting SD
    // FIXME - open files asking for too many permissions
    // FIXME - MAXIMUM_ALLOWED

    // FIXME - querying directory (inc. specific files)
    // FIXME - directory notifications

    // FIXME - oplocks
    // FIXME - FILE_RESERVE_OPFILTER
    // FIXME - FILE_OPEN_REQUIRING_OPLOCK
    // FIXME - FILE_COMPLETE_IF_OPLOCKED

    // FIXME - IOCTLs and FSCTLs

    // FIXME - querying volume info
    // FIXME - setting volume label

    // FIXME - locking

    // FIXME - traverse checking

    // FIXME - reflink copies
    // FIXME - creating subvols
    // FIXME - snapshots
    // FIXME - sending and receiving(?)
    // FIXME - using mknod etc. to test mapping between Linux and Windows concepts?

    if (name != u"all" && first)
        throw runtime_error("Test not supported.");

    if (name == u"all")
        fmt::print("\nTotal passed {}/{}\n", total_tests_passed, total_tests_run);
}

static u16string to_u16string(time_t n) {
    u16string s;

    while (n > 0) {
        s += (n % 10) + u'0';
        n /= 10;
    }

    return u16string(s.rbegin(), s.rend());
}

static bool fs_driver_path(HANDLE h, const u16string_view& driver) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    vector<uint8_t> buf(offsetof(FILE_FS_DRIVER_PATH_INFORMATION, DriverName) + (driver.size() * sizeof(char16_t)));

    auto& ffdpi = *(FILE_FS_DRIVER_PATH_INFORMATION*)buf.data();

    ffdpi.DriverInPath = false;
    ffdpi.DriverNameLength = driver.size() * sizeof(char16_t);
    memcpy(&ffdpi.DriverName, driver.data(), ffdpi.DriverNameLength);

    Status = NtQueryVolumeInformationFile(h, &iosb, &ffdpi, buf.size(), FileFsDriverPathInformation);

    if (Status == STATUS_OBJECT_NAME_NOT_FOUND) // driver not loaded
        return false;

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    return ffdpi.DriverInPath;
}

class sc_handle_closer {
public:
    typedef SC_HANDLE pointer;

    void operator()(SC_HANDLE h) {
        CloseServiceHandle(h);
    }
};

static optional<u16string> get_environment_variable(const u16string& name) {
   auto len = GetEnvironmentVariableW((WCHAR*)name.c_str(), nullptr, 0);

   if (len == 0) {
       if (GetLastError() == ERROR_ENVVAR_NOT_FOUND)
           return nullopt;

       return u"";
   }

   u16string ret(len, 0);

   if (GetEnvironmentVariableW((WCHAR*)name.c_str(), (WCHAR*)ret.data(), len) == 0)
       throw formatted_error("GetEnvironmentVariable failed (error {})", GetLastError());

   while (!ret.empty() && ret.back() == 0) {
       ret.pop_back();
   }

   return ret;
}

static u16string get_driver_path(const u16string& driver) {
    unique_ptr<SC_HANDLE, sc_handle_closer> sc_manager, service;

    sc_manager.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!sc_manager)
        throw formatted_error("OpenSCManager failed (error {})", GetLastError());

    service.reset(OpenServiceW(sc_manager.get(), (WCHAR*)driver.c_str(), SERVICE_QUERY_CONFIG));
    if (!service)
        throw formatted_error("OpenService failed (error {})", GetLastError());

    vector<uint8_t> buf(sizeof(QUERY_SERVICE_CONFIGW));
    DWORD needed;

    if (!QueryServiceConfigW(service.get(), (QUERY_SERVICE_CONFIGW*)buf.data(), buf.size(), &needed)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            throw formatted_error("QueryServiceConfig failed (error {})", GetLastError());

        buf.resize(needed);

        if (!QueryServiceConfigW(service.get(), (QUERY_SERVICE_CONFIGW*)buf.data(), buf.size(), &needed))
            throw formatted_error("QueryServiceConfig failed (error {})", GetLastError());
    }

    auto& qsc = *(QUERY_SERVICE_CONFIGW*)buf.data();

    u16string path = (char16_t*)qsc.lpBinaryPathName;

    if (path.empty()) // if the bootloader has sorted it out
        path = u"\\SystemRoot\\System32\\drivers\\" + driver + u".sys";

    if (path.substr(0, 12) == u"\\SystemRoot\\") { // FIXME - case-insensitive?
        auto sr = get_environment_variable(u"SystemRoot");

        // FIXME - get from \\SystemRoot symlink instead?

        if (!sr.has_value())
            throw runtime_error("SystemRoot environment variable not set.");

        path = sr.value() + u"\\" + path.substr(12);
    }

    if (path.substr(0, 4) == u"\\??\\")
        path = path.substr(4);

    return path;
}

static string u16string_to_string(const u16string_view& sv) {
    if (sv.empty())
        return "";

    auto len = WideCharToMultiByte(CP_ACP, 0, (WCHAR*)sv.data(), sv.length(), nullptr, 0, nullptr, nullptr);
    if (len == 0)
        throw formatted_error("WideCharToMultiByte failed (error {})", GetLastError());

    string s(len, 0);

    if (WideCharToMultiByte(CP_ACP, 0, (WCHAR*)sv.data(), sv.length(), s.data(), s.length(), nullptr, nullptr) == 0)
        throw formatted_error("WideCharToMultiByte failed (error {})", GetLastError());

    return s;
}

static string driver_string(const u16string& driver) {
    try {
        auto path = get_driver_path(driver);

        // FIXME - print version of driver

        return u16string_to_string(path);
    } catch (const exception& e) {
        return e.what();
    }
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        fmt::print(stderr, "Usage: test.exe <dir>\n       test.exe <test> <dir>");
        return 1;
    }

    try {
        u16string_view dirarg = (char16_t*)(argc < 3 ? argv[1] : argv[2]);

        u16string ntdir = u"\\??\\"s + u16string(dirarg);
        ntdir += u"\\" + to_u16string(time(nullptr));

        unique_handle dirh;

        try {
            dirh = create_file(ntdir, GENERIC_WRITE, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
        } catch (const exception& e) {
            throw runtime_error("Error creating directory: "s + e.what());
        }

        bool type_lookup_failed = false;

        fstype = fs_type::unknown;

        try {
            /* See lie_about_fs_type() for why we can't use FileFsAttributeInformation. */

            if (fs_driver_path(dirh.get(), u"\\FileSystem\\NTFS"))
                fstype = fs_type::ntfs;
            else if (fs_driver_path(dirh.get(), u"\\Driver\\btrfs"))
                fstype = fs_type::btrfs;
        } catch (const exception& e) {
            fmt::print(stderr, "Error getting filesystem type: {}\n", e.what());
            type_lookup_failed = true;
        }

        dirh.reset();

        if (!type_lookup_failed) {
            switch (fstype) {
                case fs_type::ntfs:
                    fmt::print("Testing on NTFS ({}).\n", driver_string(u"ntfs"));
                    break;

                case fs_type::btrfs:
                    fmt::print("Testing on Btrfs.\n", driver_string(u"btrfs"));
                    break;

                default:
                    fmt::print("Testing on unknown filesystem.\n");
                    break;
            }
        }

        u16string_view testarg = argc < 3 ? u"all" : (char16_t*)argv[1];

        do_tests(testarg, ntdir);
    } catch (const exception& e) {
        fmt::print(stderr, "{}\n", e.what());
        return 1;
    }

    return 0;
}
