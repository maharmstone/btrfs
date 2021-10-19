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

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        fmt::print(stderr, "Usage: test.exe dir\n");
        return 1;
    }

    u16string ntdir = u"\\??\\"s + u16string((char16_t*)argv[1]);

    test("Opening dir", [&]() {
        create_file(ntdir, 0, 0, 0, 0, 0, FILE_OPENED);
    });

    return 0;
}
