#include <windef.h>
#include <winbase.h>
#include <winternl.h>
#include <devioctl.h>
#include <ntdddisk.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stringapiset.h>
#include <ntstatus.h>
#include <memory>
#include <stdexcept>
#include <fmt/format.h>

using namespace std;

class handle_closer {
public:
    typedef HANDLE pointer;

    void operator()(HANDLE h) {
        if (h == INVALID_HANDLE_VALUE)
            return;

        CloseHandle(h);
    }
};

typedef unique_ptr<HANDLE, handle_closer> unique_handle;

class ntstatus_error : public exception {
public:
    ntstatus_error(NTSTATUS Status) : Status(Status) {
        msg = fmt::format("Status {:08x}", (uint32_t)Status);
    }

    const char* what() const noexcept override {
        return msg.c_str();
    }

    NTSTATUS Status;
    string msg;
};

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
