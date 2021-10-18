#include "test.h"

using namespace std;

static unique_handle create_file(ACCESS_MASK access, ULONG atts, ULONG share, ULONG dispo,
                                 ULONG options) {
    NTSTATUS Status;
    HANDLE h;
    IO_STATUS_BLOCK iosb;

    // FIXME - ObjectAttributes
    // FIXME - AllocationSize
    // FIXME - EaBuffer and EaLength

    Status = NtCreateFile(&h, access, nullptr, &iosb, nullptr, atts, share,
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
        create_file(0, 0, 0, 0, 0);
    } catch (const exception& e) {
        fmt::print(stderr, "{}\n", e.what());
    }

    return 0;
}
