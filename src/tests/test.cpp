#include "test.h"
#include <functional>

using namespace std;

static unique_handle create_file(const u16string_view& path, ACCESS_MASK access, ULONG atts, ULONG share,
                                 ULONG dispo, ULONG options, ULONG_PTR exp_info) {
    NTSTATUS Status;
    HANDLE h;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;

    oa.Length = sizeof(oa);
    oa.RootDirectory = nullptr; // FIXME - test

    us.Length = us.MaximumLength = path.length() * sizeof(char16_t);
    us.Buffer = (WCHAR*)path.data();
    oa.ObjectName = &us;

    oa.Attributes = OBJ_CASE_INSENSITIVE; // FIXME - test
    oa.SecurityDescriptor = nullptr; // FIXME - test
    oa.SecurityQualityOfService = nullptr; // FIXME - test(?)

    // FIXME - AllocationSize
    // FIXME - EaBuffer and EaLength

    iosb.Information = 0xdeadbeef;

    Status = NtCreateFile(&h, access, &oa, &iosb, nullptr, atts, share,
                          dispo, options, nullptr, 0);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != exp_info)
        throw formatted_error("iosb.Information was {}, expected {}", iosb.Information, exp_info);

    return unique_handle(h);
}

static void test(const string& msg, const function<void()>& func) {
    string err;

    try {
        func();
    } catch (const exception& e) {
        err = e.what();
    } catch (...) {
        err = "Uncaught exception.";
    }

    // FIXME - coloured and aligned output

    if (err.empty())
        fmt::print("{}, PASS\n", msg);
    else
        fmt::print("{}, FAIL ({})\n", msg, err);
}

static void exp_status(const function<void()>& func, NTSTATUS Status) {
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

static void test_create_file(const u16string& dir) {
    unique_handle h;

    test("Create file", [&]() {
        h = create_file(dir + u"\\file", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create duplicate file", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\file", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        test("Create file differing in case", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\FILE", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        h.reset();
    }
}

static u16string to_u16string(time_t n) {
    u16string s;

    while (n > 0) {
        s += (n % 10) + u'0';
        n /= 10;
    }

    return u16string(s.rbegin(), s.rend());
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        fmt::print(stderr, "Usage: test.exe dir\n");
        return 1;
    }

    u16string ntdir = u"\\??\\"s + u16string((char16_t*)argv[1]);
    ntdir += u"\\" + to_u16string(time(nullptr));

    create_file(ntdir, GENERIC_WRITE, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);

    test_create_file(ntdir);

    return 0;
}
