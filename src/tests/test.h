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
#include <string>
#include <fmt/format.h>

class handle_closer {
public:
    typedef HANDLE pointer;

    void operator()(HANDLE h) {
        if (h == INVALID_HANDLE_VALUE)
            return;

        CloseHandle(h);
    }
};

typedef std::unique_ptr<HANDLE, handle_closer> unique_handle;

class ntstatus_error : public std::exception {
public:
    ntstatus_error(NTSTATUS Status) : Status(Status) {
        msg = fmt::format("Status {:08x}", (uint32_t)Status);
    }

    const char* what() const noexcept override {
        return msg.c_str();
    }

    NTSTATUS Status;
    std::string msg;
};
