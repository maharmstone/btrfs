#include "test.h"

using namespace std;

static unique_handle create_file(const u16string_view& path, ACCESS_MASK access, ULONG atts, ULONG share,
                                 ULONG dispo, ULONG options) {
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

    Status = NtCreateFile(&h, access, &oa, &iosb, nullptr, atts, share,
                          dispo, options, nullptr, 0);

    // FIXME

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    // FIXME - check iosb

    return unique_handle(h);
}

int main() {
    try {
        // FIXME
        create_file(u"\\??\\C:", 0, 0, 0, 0, 0);
    } catch (const exception& e) {
        fmt::print(stderr, "{}\n", e.what());
    }

    return 0;
}
