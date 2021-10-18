#include "test.h"

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

static void try_create_file(const string& msg, const u16string_view& path, ACCESS_MASK access, ULONG atts,
                            ULONG share, ULONG dispo, ULONG options, ULONG_PTR exp_info, NTSTATUS exp_status) {
    NTSTATUS Status = STATUS_SUCCESS;
    string error;

    try {
        create_file(path, access, atts, share, dispo, options, exp_info);
    } catch (const ntstatus_error& e) {
        Status = e.Status;
    } catch (const exception& e) {
        error = e.what();
    }

    if (error.empty() && exp_status != Status)
        error = fmt::format("Expected {}, received {}", ntstatus_to_string(exp_status), ntstatus_to_string(Status));

    // FIXME - coloured and aligned output

    if (error.empty())
        fmt::print("{}, PASS\n", msg);
    else
        fmt::print("{}, FAIL ({})\n", msg, error);
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        fmt::print(stderr, "Usage: test.exe dir\n");
        return 1;
    }

    u16string ntdir = u"\\??\\"s + u16string((char16_t*)argv[1]);

    try_create_file("Opening dir", ntdir, 0, 0, 0, 0, 0, FILE_OPENED, STATUS_SUCCESS);

    return 0;
}
