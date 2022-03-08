#include "test.h"
#include <thread>

using namespace std;

#define FSCTL_REQUEST_OPLOCK_LEVEL_1 CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_REQUEST_OPLOCK_LEVEL_2 CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_REQUEST_BATCH_OPLOCK CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_OPLOCK_BREAK_ACKNOWLEDGE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_REQUEST_FILTER_OPLOCK CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 23, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_REQUEST_OPLOCK CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 144, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define FILE_OPLOCK_BROKEN_TO_LEVEL_2       0x00000007
#define FILE_OPLOCK_BROKEN_TO_NONE          0x00000008

#define OPLOCK_LEVEL_CACHE_READ         0x00000001
#define OPLOCK_LEVEL_CACHE_HANDLE       0x00000002
#define OPLOCK_LEVEL_CACHE_WRITE        0x00000004

#define REQUEST_OPLOCK_INPUT_FLAG_REQUEST               0x00000001
#define REQUEST_OPLOCK_INPUT_FLAG_ACK                   0x00000002
#define REQUEST_OPLOCK_INPUT_FLAG_COMPLETE_ACK_ON_CLOSE 0x00000004

#define REQUEST_OPLOCK_CURRENT_VERSION          1

enum oplock_type {
    level1,
    level2,
    batch,
    filter,
    read_oplock,
    read_handle,
    read_write,
    read_write_handle
};

static unique_handle req_oplock(HANDLE h, IO_STATUS_BLOCK& iosb, enum oplock_type type) {
    NTSTATUS Status;
    HANDLE ev;

    iosb.Information = 0;

    Status = NtCreateEvent(&ev, MAXIMUM_ALLOWED, nullptr, NotificationEvent, false);
    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    switch (type) {
        case oplock_type::level1:
            Status = NtFsControlFile(h, ev, nullptr, nullptr, &iosb,
                                     FSCTL_REQUEST_OPLOCK_LEVEL_1,
                                     nullptr, 0, nullptr, 0);
        break;

        case oplock_type::level2:
            Status = NtFsControlFile(h, ev, nullptr, nullptr, &iosb,
                                     FSCTL_REQUEST_OPLOCK_LEVEL_2,
                                     nullptr, 0, nullptr, 0);
        break;

        case oplock_type::batch:
            Status = NtFsControlFile(h, ev, nullptr, nullptr, &iosb,
                                     FSCTL_REQUEST_BATCH_OPLOCK,
                                     nullptr, 0, nullptr, 0);
        break;

        case oplock_type::filter:
            Status = NtFsControlFile(h, ev, nullptr, nullptr, &iosb,
                                     FSCTL_REQUEST_FILTER_OPLOCK,
                                     nullptr, 0, nullptr, 0);
        break;

        default:
            throw runtime_error("Invalid oplock type for function.");
    }

    if (Status != STATUS_PENDING)
        throw ntstatus_error(Status);

    return unique_handle(ev);
}

static unique_handle req_oplock_win7(HANDLE h, IO_STATUS_BLOCK& iosb, enum oplock_type type,
                                     REQUEST_OPLOCK_OUTPUT_BUFFER& roob) {
    REQUEST_OPLOCK_INPUT_BUFFER roib;
    NTSTATUS Status;
    HANDLE ev;

    iosb.Information = 0;

    Status = NtCreateEvent(&ev, MAXIMUM_ALLOWED, nullptr, NotificationEvent, false);
    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    roib.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    roib.StructureLength = sizeof(roib);
    roib.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;

    switch (type) {
        case oplock_type::read_oplock:
            roib.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ;
        break;

        case oplock_type::read_handle:
            roib.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
        break;

        case oplock_type::read_write:
            roib.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE;
        break;

        case oplock_type::read_write_handle:
            roib.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE;
        break;

        default:
            throw runtime_error("Invalid oplock type for function.");
    }

    roob.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    roob.StructureLength = sizeof(roob);

    Status = NtFsControlFile(h, ev, nullptr, nullptr, &iosb,
                             FSCTL_REQUEST_OPLOCK, &roib, sizeof(roib),
                             &roob, sizeof(roob));

    if (Status != STATUS_PENDING)
        throw ntstatus_error(Status);

    return unique_handle(ev);
}

static bool check_event(HANDLE h) {
    NTSTATUS Status;
    EVENT_BASIC_INFORMATION ebi;

    Status = NtQueryEvent(h, EventBasicInformation, &ebi, sizeof(ebi), nullptr);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    return ebi.EventState;
}

static void lock_file_wait(HANDLE h, uint64_t offset, uint64_t length, bool exclusive) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offli, lenli;

    offli.QuadPart = offset;
    lenli.QuadPart = length;

    auto event = create_event();

    Status = NtLockFile(h, event.get(), nullptr, nullptr, &iosb, &offli, &lenli,
                        0, false, exclusive);

    if (Status == STATUS_PENDING) {
        Status = NtWaitForSingleObject(event.get(), false, nullptr);
        if (Status != STATUS_SUCCESS)
            throw ntstatus_error(Status);

        Status = iosb.Status;
    }

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

static void unlock_file(HANDLE h, uint64_t offset, uint64_t length) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offli, lenli;

    offli.QuadPart = offset;
    lenli.QuadPart = length;

    Status = NtUnlockFile(h, &iosb, &offli, &lenli, 0);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

void test_oplocks_ii(HANDLE token, const u16string& dir) {
    unique_handle h, h2;
    IO_STATUS_BLOCK iosb;
    auto data = random_data(4096);

    // needed to set valid data length
    test("Add SeManageVolumePrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_MANAGE_VOLUME_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockii1", FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\oplockii1", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        unique_handle ev;

        test("Get level 2 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level2);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplockii1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Check oplock still not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            h2.reset();

            test("Try to open second handle (FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK)", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\oplockii1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK, FILE_OPENED);
                }, STATUS_CANNOT_BREAK_OPLOCK);
            });

            test("Try to open second handle (FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED)", [&]() {
                create_file(dir + u"\\oplockii1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED, FILE_OPENED);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_SUPERSEDE)", [&]() {
                h2 = create_file(dir + u"\\oplockii1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_SUPERSEDE, 0, FILE_SUPERSEDED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();

            test("Get level 2 oplock", [&]() {
                ev = req_oplock(h.get(), iosb, oplock_type::level2);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OVERWRITE)", [&]() {
                h2 = create_file(dir + u"\\oplockii1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();

            test("Try to open second handle with FILE_RESERVE_OPFILTER", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\oplockii1", FILE_READ_ATTRIBUTES, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN, FILE_RESERVE_OPFILTER, FILE_OPENED);
                }, STATUS_OPLOCK_NOT_GRANTED);
            });

            test("Get level 2 oplock", [&]() {
                ev = req_oplock(h.get(), iosb, oplock_type::level2);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OVERWRITE_IF)", [&]() {
                h2 = create_file(dir + u"\\oplockii1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE_IF, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();

            test("Write to file", [&]() {
                write_file_wait(h.get(), data, 0);
            });

            test("Get level 2 oplock", [&]() {
                ev = req_oplock(h.get(), iosb, oplock_type::level2);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplockii1", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Read from second handle", [&]() {
                read_file_wait(h2.get(), 4096, 0);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Write to first handle", [&]() {
                write_file_wait(h.get(), data, 0);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            test("Get level 2 oplock", [&]() {
                ev = req_oplock(h.get(), iosb, oplock_type::level2);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Write to second handle", [&]() {
                write_file_wait(h2.get(), data, 0);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplockii1", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Get level 2 oplock", [&]() {
                ev = req_oplock(h.get(), iosb, oplock_type::level2);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Lock file", [&]() {
                lock_file_wait(h2.get(), 0, 4096, false);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplockii1", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA | DELETE, 0,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, FILE_OPENED);
            });

            test("Get level 2 oplock", [&]() {
                ev = req_oplock(h.get(), iosb, oplock_type::level2);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Set end of file", [&]() {
                set_end_of_file(h2.get(), 4096);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            test("Get level 2 oplock", [&]() {
                ev = req_oplock(h.get(), iosb, oplock_type::level2);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Set allocation", [&]() {
                set_allocation(h2.get(), 4096);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            test("Get level 2 oplock", [&]() {
                ev = req_oplock(h.get(), iosb, oplock_type::level2);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Set valid data length", [&]() {
                set_valid_data_length(h2.get(), 4096);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            test("Get level 2 oplock", [&]() {
                ev = req_oplock(h.get(), iosb, oplock_type::level2);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Rename file", [&]() {
                set_rename_information(h2.get(), false, nullptr, dir + u"\\oplockii1a");
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Create hardlink", [&]() {
                set_link_information(h2.get(), false, nullptr, dir + u"\\oplockii1b");
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Set zero data", [&]() {
                set_zero_data(h2.get(), 0, 100);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            test("Get level 2 oplock", [&]() {
                ev = req_oplock(h.get(), iosb, oplock_type::level2);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Set disposition information", [&]() {
                set_disposition_information(h2.get(), true);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockii2", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Try to get level 2 oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb, oplock_type::level2);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        h.reset();
    }

    test("Create file with FILE_SYNCHRONOUS_IO_NONALERT", [&]() {
        h = create_file(dir + u"\\oplockii3", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Try to get level 2 oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb, oplock_type::level2);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\oplockii4", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Try to get level 2 oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb, oplock_type::level2);
            }, STATUS_INVALID_PARAMETER);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockii5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Get level 2 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level2);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Open second handle on file", [&]() {
            h2 = create_file(dir + u"\\oplockii5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        if (h2) {
            unique_handle ev2;
            IO_STATUS_BLOCK iosb2;

            test("Get level 2 oplock on second handle", [&]() {
                ev2 = req_oplock(h2.get(), iosb2, oplock_type::level2);
            });

            test("Check first oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Check second oplock not broken", [&]() {
                if (check_event(ev2.get()))
                    throw runtime_error("Oplock is broken");
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockii6", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;

        test("Get read oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Open second handle on file", [&]() {
            h2 = create_file(dir + u"\\oplockii6", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        if (h2) {
            unique_handle ev2;
            IO_STATUS_BLOCK iosb2;

            test("Get level 2 oplock on second handle", [&]() {
                ev2 = req_oplock(h2.get(), iosb2, oplock_type::level2);
            });

            test("Check first oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Check second oplock not broken", [&]() {
                if (check_event(ev2.get()))
                    throw runtime_error("Oplock is broken");
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockii7", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Open second handle on file", [&]() {
            h2 = create_file(dir + u"\\oplockii7", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        if (h2) {
            test("Try to get level 2 oplock on second handle", [&]() {
                IO_STATUS_BLOCK iosb2;

                exp_status([&]() {
                    req_oplock(h2.get(), iosb2, oplock_type::level2);
                }, STATUS_OPLOCK_NOT_GRANTED);
            });

            test("Check first oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockii8", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get level 2 oplock", [&]() {
            IO_STATUS_BLOCK iosb2;

            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::level2);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockii9", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get level 2 oplock", [&]() {
            IO_STATUS_BLOCK iosb2;

            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::level2);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockii10", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get level 2 oplock", [&]() {
            IO_STATUS_BLOCK iosb2;

            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::level2);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockii11", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get level 2 oplock", [&]() {
            IO_STATUS_BLOCK iosb2;

            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::level2);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockii12", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get level 2 oplock", [&]() {
            IO_STATUS_BLOCK iosb2;

            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::level2);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    disable_token_privileges(token);
}

void test_oplocks_r(HANDLE token, const u16string& dir) {
    unique_handle h, h2;
    IO_STATUS_BLOCK iosb;
    REQUEST_OPLOCK_OUTPUT_BUFFER roob;
    auto data = random_data(4096);

    // needed to set valid data length
    test("Add SeManageVolumePrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_MANAGE_VOLUME_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockr1", FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\oplockr1", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        unique_handle ev;

        test("Get read oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK)", [&]() {
                create_file(dir + u"\\oplockr1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK, FILE_OPENED);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplockr1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Check oplock still not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            h2.reset();

            test("Try to open second handle with FILE_RESERVE_OPFILTER", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\oplockr1", FILE_READ_ATTRIBUTES, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN, FILE_RESERVE_OPFILTER, FILE_OPENED);
                }, STATUS_OPLOCK_NOT_GRANTED);
            });

            test("Try to open second handle (FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED)", [&]() {
                create_file(dir + u"\\oplockr1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED, FILE_OPENED);
            });

            test("Check oplock is broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            test("Get read oplock", [&]() {
                ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_SUPERSEDE)", [&]() {
                h2 = create_file(dir + u"\\oplockr1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_SUPERSEDE, 0, FILE_SUPERSEDED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();

            test("Get read oplock", [&]() {
                ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OVERWRITE)", [&]() {
                h2 = create_file(dir + u"\\oplockr1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();

            test("Get read oplock", [&]() {
                ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OVERWRITE_IF)", [&]() {
                h2 = create_file(dir + u"\\oplockr1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE_IF, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();

            test("Write to file", [&]() {
                write_file_wait(h.get(), data, 0);
            });

            test("Get read oplock", [&]() {
                ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplockr1", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Read from second handle", [&]() {
                read_file_wait(h2.get(), 4096, 0);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Write to first handle", [&]() {
                write_file_wait(h.get(), data, 0);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Write to second handle", [&]() {
                write_file_wait(h2.get(), data, 0);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplockr1", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Get read oplock", [&]() {
                ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Lock file", [&]() {
                lock_file_wait(h2.get(), 0, 4096, false);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplockr1", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA | DELETE, 0,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, FILE_OPENED);
            });

            test("Get read oplock", [&]() {
                ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Set end of file", [&]() {
                set_end_of_file(h2.get(), 4096);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            test("Get read oplock", [&]() {
                ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Set allocation", [&]() {
                set_allocation(h2.get(), 4096);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            test("Get read oplock", [&]() {
                ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Set valid data length", [&]() {
                set_valid_data_length(h2.get(), 4096);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            test("Get read oplock", [&]() {
                ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Rename file", [&]() {
                set_rename_information(h2.get(), false, nullptr, dir + u"\\oplockr1a");
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Create hardlink", [&]() {
                set_link_information(h2.get(), false, nullptr, dir + u"\\oplockr1b");
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Set zero data", [&]() {
                set_zero_data(h2.get(), 0, 100);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            test("Get read oplock", [&]() {
                ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Set disposition information", [&]() {
                set_disposition_information(h2.get(), true);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockr2", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Try to get read oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        h.reset();
    }

    test("Create file with FILE_SYNCHRONOUS_IO_NONALERT", [&]() {
        h = create_file(dir + u"\\oplockr3", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Try to get read oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\oplockr4", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        // Succeeds on Windows 8 and above (see https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
        test("Get read oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Create file in directory", [&]() {
                create_file(dir + u"\\oplockr4\\file", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockr5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Get level 2 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level2);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Open second handle on file", [&]() {
            h2 = create_file(dir + u"\\oplockr5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        if (h2) {
            unique_handle ev2;
            IO_STATUS_BLOCK iosb2;

            test("Get read oplock on second handle", [&]() {
                ev2 = req_oplock_win7(h2.get(), iosb2, oplock_type::read_oplock, roob);
            });

            test("Check first oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Check second oplock not broken", [&]() {
                if (check_event(ev2.get()))
                    throw runtime_error("Oplock is broken");
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockr6", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Get read oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Open second handle on file", [&]() {
            h2 = create_file(dir + u"\\oplockr6", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        if (h2) {
            unique_handle ev2;
            IO_STATUS_BLOCK iosb2;
            REQUEST_OPLOCK_OUTPUT_BUFFER roob2;

            test("Get read oplock on second handle", [&]() {
                ev2 = req_oplock_win7(h2.get(), iosb2, oplock_type::read_oplock, roob2);
            });

            test("Check first oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Check second oplock not broken", [&]() {
                if (check_event(ev2.get()))
                    throw runtime_error("Oplock is broken");
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockr7", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Open second handle on file", [&]() {
            h2 = create_file(dir + u"\\oplockr7", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        if (h2) {
            unique_handle ev2;

            test("Get read oplock on second handle", [&]() {
                IO_STATUS_BLOCK iosb2;
                REQUEST_OPLOCK_OUTPUT_BUFFER roob2;

                ev2 = req_oplock_win7(h2.get(), iosb2, oplock_type::read_oplock, roob2);
            });

            test("Check first oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Check second oplock not broken", [&]() {
                if (check_event(ev2.get()))
                    throw runtime_error("Oplock is broken");
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockr8", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read oplock", [&]() {
            IO_STATUS_BLOCK iosb2;

            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_oplock, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockr9", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read oplock", [&]() {
            IO_STATUS_BLOCK iosb2;

            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_oplock, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockr10", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read oplock", [&]() {
            IO_STATUS_BLOCK iosb2;

            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_oplock, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockr11", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read oplock", [&]() {
            IO_STATUS_BLOCK iosb2;
            REQUEST_OPLOCK_OUTPUT_BUFFER roob2;

            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_oplock, roob2);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockr12", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read oplock", [&]() {
            IO_STATUS_BLOCK iosb2;
            REQUEST_OPLOCK_OUTPUT_BUFFER roob2;

            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_oplock, roob2);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    disable_token_privileges(token);
}

static DWORD __stdcall wait_and_acknowledge(void* param) {
    IO_STATUS_BLOCK iosb;
    auto ctx = reinterpret_cast<HANDLE*>(param);
    auto ev = ctx[0];
    auto h = ctx[1];

    NtWaitForSingleObject(ev, false, nullptr);

    NtFsControlFile(h, nullptr, nullptr, nullptr, &iosb,
                    FSCTL_OPLOCK_BREAK_ACKNOWLEDGE,
                    nullptr, 0, nullptr, 0);

    delete[] ctx;

    return 0;
}

static void ack_oplock(HANDLE event, HANDLE h) {
    HANDLE thread;
    auto ctx = new HANDLE[2];

    ctx[0] = event;
    ctx[1] = h;

    thread = CreateThread(nullptr, 0, wait_and_acknowledge, ctx, 0, nullptr);

    if (!thread) {
        delete[] ctx;
        throw runtime_error("Could not create thread.");
    }

    NtClose(thread);
}

static DWORD __stdcall wait_and_acknowledge_win7(void* param) {
    IO_STATUS_BLOCK iosb;
    REQUEST_OPLOCK_INPUT_BUFFER roib;
    REQUEST_OPLOCK_OUTPUT_BUFFER roob;
    auto ctx = reinterpret_cast<HANDLE*>(param);
    auto ev = ctx[0];
    auto h = ctx[1];

    NtWaitForSingleObject(ev, false, nullptr);

    roib.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    roib.StructureLength = sizeof(roib);
    roib.RequestedOplockLevel = 0;
    roib.Flags = REQUEST_OPLOCK_INPUT_FLAG_ACK;

    roob.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    roob.StructureLength = sizeof(roob);

    NtFsControlFile(h, nullptr, nullptr, nullptr, &iosb,
                    FSCTL_REQUEST_OPLOCK, &roib, sizeof(roib),
                    &roob, sizeof(roob));

    delete[] ctx;

    return 0;
}

static void ack_oplock_win7(HANDLE event, HANDLE h) {
    HANDLE thread;
    auto ctx = new HANDLE[2];

    ctx[0] = event;
    ctx[1] = h;

    thread = CreateThread(nullptr, 0, wait_and_acknowledge_win7, ctx, 0, nullptr);

    if (!thread) {
        delete[] ctx;
        throw runtime_error("Could not create thread.");
    }

    NtClose(thread);
}

void test_oplocks_i(HANDLE token, const u16string& dir) {
    unique_handle h, h2;
    IO_STATUS_BLOCK iosb;
    auto data = random_data(4096);

    // needed to set valid data length
    test("Add SeManageVolumePrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_MANAGE_VOLUME_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplocki1", FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\oplocki1", FILE_READ_DATA | FILE_WRITE_DATA | DELETE, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        unique_handle ev;

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Try to open second handle (FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK)", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\oplocki1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK, FILE_OPENED);
                }, STATUS_CANNOT_BREAK_OPLOCK);
            });

            ack_oplock(ev.get(), h.get());

            test("Try to open second handle (FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED)", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\oplocki1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED, FILE_OPENED);
                }, STATUS_OPLOCK_BREAK_IN_PROGRESS);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_LEVEL_2)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_LEVEL_2", iosb.Information);
            });
        }

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\oplocki1", FILE_READ_DATA | FILE_WRITE_DATA | DELETE, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        unique_handle ev;

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        if (ev) {
            ack_oplock(ev.get(), h.get());

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplocki1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_LEVEL_2)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_LEVEL_2", iosb.Information);
            });

            h2.reset();
        }

        test("Try to open second handle with FILE_RESERVE_OPFILTER", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\oplocki1", FILE_READ_ATTRIBUTES, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_OPEN, FILE_RESERVE_OPFILTER, FILE_OPENED);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock(ev.get(), h.get());

            test("Open second handle (FILE_SUPERSEDE)", [&]() {
                h2 = create_file(dir + u"\\oplocki1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_SUPERSEDE, 0, FILE_SUPERSEDED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();
        }

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock(ev.get(), h.get());

            test("Open second handle (FILE_OVERWRITE)", [&]() {
                h2 = create_file(dir + u"\\oplocki1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();
        }

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock(ev.get(), h.get());

            test("Open second handle (FILE_OVERWRITE_IF)", [&]() {
                h2 = create_file(dir + u"\\oplocki1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE_IF, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();
        }

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Read from file", [&]() {
            read_file_wait(h.get(), 4096, 0);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Unlock file", [&]() {
            unlock_file(h.get(), 0, 4096);
        });

        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set allocation", [&]() {
            set_allocation(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set valid data length", [&]() {
            set_valid_data_length(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Rename file", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\oplocki1a");
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Create hardlink", [&]() {
            set_link_information(h.get(), false, nullptr, dir + u"\\oplocki1b");
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set zero data", [&]() {
            set_zero_data(h.get(), 0, 100);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set disposition information", [&]() {
            set_disposition_information(h.get(), true);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplocki2", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file with FILE_SYNCHRONOUS_IO_NONALERT", [&]() {
        h = create_file(dir + u"\\oplocki3", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Try to get level 1 oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb, oplock_type::level1);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\oplocki4", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Try to get level 1 oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb, oplock_type::level1);
            }, STATUS_INVALID_PARAMETER);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplocki5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Open second handle on file", [&]() {
            h2 = create_file(dir + u"\\oplocki5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        if (h2) {
            test("Try to get level 1 oplock with two handles open", [&]() {
                exp_status([&]() {
                    req_oplock(h2.get(), iosb, oplock_type::level1);
                }, STATUS_OPLOCK_NOT_GRANTED);
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplocki6", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev, ev2;
        IO_STATUS_BLOCK iosb2;

        test("Get level 2 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level2);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Get level 1 oplock", [&]() {
            ev2 = req_oplock(h.get(), iosb2, oplock_type::level1);
        });

        test("Check first oplock broken", [&]() {
            if (!check_event(ev.get()))
                throw runtime_error("Oplock is not broken");

            if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
        });

        test("Check second oplock not broken", [&]() {
            if (check_event(ev2.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplocki7", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;
        IO_STATUS_BLOCK iosb2;

        test("Get read oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get level 1 oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::level1);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplocki8", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;
        IO_STATUS_BLOCK iosb2;

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get level 1 oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::level1);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplocki9", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;
        IO_STATUS_BLOCK iosb2;

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get level 1 oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::level1);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplocki10", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;
        IO_STATUS_BLOCK iosb2;

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get level 1 oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::level1);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplocki11", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get level 1 oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::level1);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplocki12", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get level 1 oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::level1);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplocki13", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get level 1 oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::level1);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    disable_token_privileges(token);
}

void test_oplocks_rw(HANDLE token, const u16string& dir) {
    unique_handle h, h2;
    IO_STATUS_BLOCK iosb;
    REQUEST_OPLOCK_OUTPUT_BUFFER roob;
    auto data = random_data(4096);

    // needed to set valid data length
    test("Add SeManageVolumePrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_MANAGE_VOLUME_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrw1", FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\oplockrw1", FILE_READ_DATA | FILE_WRITE_DATA | DELETE, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        unique_handle ev;

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock_win7(ev.get(), h.get());

            test("Try to open second handle (FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK)", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\oplockrw1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK, FILE_OPENED);
                }, STATUS_CANNOT_BREAK_OPLOCK);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplockrw1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != OPLOCK_LEVEL_CACHE_READ)
                    throw formatted_error("NewOplockLevel was {}, expected OPLOCK_LEVEL_CACHE_READ", roob.NewOplockLevel);
            });

            h2.reset();
        }

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        if (ev) {
            ack_oplock_win7(ev.get(), h.get());

            test("Try to open second handle with FILE_RESERVE_OPFILTER", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\oplockrw1", FILE_READ_ATTRIBUTES, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN, FILE_RESERVE_OPFILTER, FILE_OPENED);
                }, STATUS_OPLOCK_NOT_GRANTED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });
        }

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        if (ev) {
            ack_oplock_win7(ev.get(), h.get());

            test("Try to open second handle (FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED)", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\oplockrw1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED, FILE_OPENED);
                }, STATUS_OPLOCK_BREAK_IN_PROGRESS);
            });

            test("Check oplock is broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != OPLOCK_LEVEL_CACHE_READ)
                    throw formatted_error("NewOplockLevel was {}, expected OPLOCK_LEVEL_CACHE_READ", roob.NewOplockLevel);
            });
        }

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock_win7(ev.get(), h.get());

            test("Open second handle (FILE_SUPERSEDE)", [&]() {
                h2 = create_file(dir + u"\\oplockrw1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_SUPERSEDE, 0, FILE_SUPERSEDED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();
        }

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock_win7(ev.get(), h.get());

            test("Open second handle (FILE_OVERWRITE)", [&]() {
                h2 = create_file(dir + u"\\oplockrw1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();
        }

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock_win7(ev.get(), h.get());

            test("Open second handle (FILE_OVERWRITE_IF)", [&]() {
                h2 = create_file(dir + u"\\oplockrw1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE_IF, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();
        }

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Read from file", [&]() {
            read_file_wait(h.get(), 4096, 0);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Unlock file", [&]() {
            unlock_file(h.get(), 0, 4096);
        });

        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set allocation", [&]() {
            set_allocation(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set valid data length", [&]() {
            set_valid_data_length(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Rename file", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\oplockrw1a");
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Create hardlink", [&]() {
            set_link_information(h.get(), false, nullptr, dir + u"\\oplockrw1b");
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set zero data", [&]() {
            set_zero_data(h.get(), 0, 100);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set disposition information", [&]() {
            set_disposition_information(h.get(), true);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrw2", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file with FILE_SYNCHRONOUS_IO_NONALERT", [&]() {
        h = create_file(dir + u"\\oplockrw3", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Try to get read-write oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\oplockrw4", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Try to get read-write oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
            }, STATUS_INVALID_PARAMETER);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrw5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Open second handle on file", [&]() {
            h2 = create_file(dir + u"\\oplockrw5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        if (h2) {
            test("Try to get read-write oplock with two handles open", [&]() {
                exp_status([&]() {
                    req_oplock_win7(h2.get(), iosb, oplock_type::read_write, roob);
                }, STATUS_OPLOCK_NOT_GRANTED);
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrw6", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get level 2 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level2);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-write oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_write, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrw7", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev, ev2;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob2;
        IO_STATUS_BLOCK iosb2;

        test("Get read oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Get read-write oplock", [&]() {
            ev2 = req_oplock_win7(h.get(), iosb2, oplock_type::read_write, roob2);
        });

        test("Check first oplock broken", [&]() {
            if (!check_event(ev.get()))
                throw runtime_error("Oplock is not broken");

            if (roob.NewOplockLevel != (OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE))
                throw formatted_error("NewOplockLevel was {}, expected OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE", roob.NewOplockLevel);
        });

        test("Check second oplock not broken", [&]() {
            if (check_event(ev2.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrw8", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob2;
        IO_STATUS_BLOCK iosb2;

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-write oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_write, roob2);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrw9", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev, ev2;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob2;
        IO_STATUS_BLOCK iosb2;

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Get read-write oplock", [&]() {
            ev2 = req_oplock_win7(h.get(), iosb2, oplock_type::read_write, roob2);
        });

        test("Check first oplock broken", [&]() {
            if (!check_event(ev.get()))
                throw runtime_error("Oplock is not broken");

            if (roob.NewOplockLevel != (OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE))
                throw formatted_error("NewOplockLevel was {}, expected OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE", roob.NewOplockLevel);
        });

        test("Check second oplock not broken", [&]() {
            if (check_event(ev2.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrw10", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob2;
        IO_STATUS_BLOCK iosb2;

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-write oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_write, roob2);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrw11", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-write oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_write, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrw12", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-write oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_write, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrw13", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-write oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_write, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    disable_token_privileges(token);
}

void test_oplocks_batch(HANDLE token, const u16string& dir) {
    unique_handle h, h2;
    IO_STATUS_BLOCK iosb;
    auto data = random_data(4096);

    // needed to set valid data length
    test("Add SeManageVolumePrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_MANAGE_VOLUME_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockb1", FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\oplockb1", FILE_READ_DATA | FILE_WRITE_DATA | DELETE, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        unique_handle ev;

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock(ev.get(), h.get());

            test("Try to open second handle (FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK)", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\oplockb1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK, FILE_OPENED);
                }, STATUS_CANNOT_BREAK_OPLOCK);
            });

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplockb1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_LEVEL_2)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_LEVEL_2", iosb.Information);
            });

            h2.reset();
        }

        test("Try to open second handle with FILE_RESERVE_OPFILTER", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\oplockb1", FILE_READ_ATTRIBUTES, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_OPEN, FILE_RESERVE_OPFILTER, FILE_OPENED);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Try to open second handle (FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED)", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\oplockb1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED, FILE_OPENED);
                }, STATUS_OPLOCK_BREAK_IN_PROGRESS);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_LEVEL_2)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_LEVEL_2", iosb.Information);
            });
        }

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\oplockb1", FILE_READ_DATA | FILE_WRITE_DATA | DELETE, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        unique_handle ev;

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        if (ev) {
            ack_oplock(ev.get(), h.get());

            test("Open second handle (FILE_SUPERSEDE)", [&]() {
                h2 = create_file(dir + u"\\oplockb1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_SUPERSEDE, 0, FILE_SUPERSEDED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();
        }

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock(ev.get(), h.get());

            test("Open second handle (FILE_OVERWRITE)", [&]() {
                h2 = create_file(dir + u"\\oplockb1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();
        }

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock(ev.get(), h.get());

            test("Open second handle (FILE_OVERWRITE_IF)", [&]() {
                h2 = create_file(dir + u"\\oplockb1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE_IF, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();
        }

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Read from file", [&]() {
            read_file_wait(h.get(), 4096, 0);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Unlock file", [&]() {
            unlock_file(h.get(), 0, 4096);
        });

        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set allocation", [&]() {
            set_allocation(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set valid data length", [&]() {
            set_valid_data_length(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Rename file", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\oplockb1a");
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Create hardlink", [&]() {
            set_link_information(h.get(), false, nullptr, dir + u"\\oplockb1b");
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set zero data", [&]() {
            set_zero_data(h.get(), 0, 100);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set disposition information", [&]() {
            set_disposition_information(h.get(), true);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockb2", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file with FILE_SYNCHRONOUS_IO_NONALERT", [&]() {
        h = create_file(dir + u"\\oplockb3", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Try to get batch oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb, oplock_type::batch);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\oplockb4", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Try to get batch oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb, oplock_type::batch);
            }, STATUS_INVALID_PARAMETER);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockb5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Open second handle on file", [&]() {
            h2 = create_file(dir + u"\\oplockb5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        if (h2) {
            test("Try to get batch oplock with two handles open", [&]() {
                exp_status([&]() {
                    req_oplock(h2.get(), iosb, oplock_type::batch);
                }, STATUS_OPLOCK_NOT_GRANTED);
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockb6", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev, ev2;
        IO_STATUS_BLOCK iosb2;

        test("Get level 2 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level2);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Get batch oplock", [&]() {
            ev2 = req_oplock(h.get(), iosb2, oplock_type::batch);
        });

        test("Check first oplock broken", [&]() {
            if (!check_event(ev.get()))
                throw runtime_error("Oplock is not broken");

            if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
        });

        test("Check second oplock not broken", [&]() {
            if (check_event(ev2.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockb7", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;
        IO_STATUS_BLOCK iosb2;

        test("Get read oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get batch oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::batch);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockb8", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;
        IO_STATUS_BLOCK iosb2;

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get batch oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::batch);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockb9", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;
        IO_STATUS_BLOCK iosb2;

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get batch oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::batch);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockb10", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;
        IO_STATUS_BLOCK iosb2;

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get batch oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::batch);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockb11", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get batch oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::batch);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockb12", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get batch oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::batch);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockb13", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get batch oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::batch);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    disable_token_privileges(token);
}

void test_oplocks_rwh(HANDLE token, const u16string& dir) {
    unique_handle h, h2;
    IO_STATUS_BLOCK iosb;
    REQUEST_OPLOCK_OUTPUT_BUFFER roob;
    auto data = random_data(4096);

    // needed to set valid data length
    test("Add SeManageVolumePrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_MANAGE_VOLUME_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrwh1", FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\oplockrwh1", FILE_READ_DATA | FILE_WRITE_DATA | DELETE, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        unique_handle ev;

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock_win7(ev.get(), h.get());

            test("Open second handle (FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK)", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\oplockrwh1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK, FILE_OPENED);
                }, STATUS_CANNOT_BREAK_OPLOCK);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplockrwh1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != (OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE))
                    throw formatted_error("NewOplockLevel was {}, expected OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE", roob.NewOplockLevel);
            });

            h2.reset();
        }

        test("Try to open second handle with FILE_RESERVE_OPFILTER", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\oplockrwh1", FILE_READ_ATTRIBUTES, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_OPEN, FILE_RESERVE_OPFILTER, FILE_OPENED);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        if (ev) {
            ack_oplock_win7(ev.get(), h.get());

            test("Try to open second handle (FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED)", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\oplockrwh1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED, FILE_OPENED);
                }, STATUS_OPLOCK_BREAK_IN_PROGRESS);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != (OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE))
                    throw formatted_error("NewOplockLevel was {}, expected OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE", roob.NewOplockLevel);
            });
        }

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock_win7(ev.get(), h.get());

            test("Open second handle (FILE_SUPERSEDE)", [&]() {
                h2 = create_file(dir + u"\\oplockrwh1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_SUPERSEDE, 0, FILE_SUPERSEDED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();
        }

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock_win7(ev.get(), h.get());

            test("Open second handle (FILE_OVERWRITE)", [&]() {
                h2 = create_file(dir + u"\\oplockrwh1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();
        }

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock_win7(ev.get(), h.get());

            test("Open second handle (FILE_OVERWRITE_IF)", [&]() {
                h2 = create_file(dir + u"\\oplockrwh1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE_IF, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();
        }

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Read from file", [&]() {
            read_file_wait(h.get(), 4096, 0);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Unlock file", [&]() {
            unlock_file(h.get(), 0, 4096);
        });

        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set allocation", [&]() {
            set_allocation(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set valid data length", [&]() {
            set_valid_data_length(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Rename file", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\oplockrwh1a");
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Create hardlink", [&]() {
            set_link_information(h.get(), false, nullptr, dir + u"\\oplockrwh1b");
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set zero data", [&]() {
            set_zero_data(h.get(), 0, 100);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set disposition information", [&]() {
            set_disposition_information(h.get(), true);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrwh2", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file with FILE_SYNCHRONOUS_IO_NONALERT", [&]() {
        h = create_file(dir + u"\\oplockrwh3", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Try to get read-write-handle oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\oplockrwh4", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Try to get read-write-handle oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
            }, STATUS_INVALID_PARAMETER);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrwh5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Open second handle on file", [&]() {
            h2 = create_file(dir + u"\\oplockrwh5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        if (h2) {
            test("Try to get read-write-handle oplock with two handles open", [&]() {
                exp_status([&]() {
                    req_oplock_win7(h2.get(), iosb, oplock_type::read_write_handle, roob);
                }, STATUS_OPLOCK_NOT_GRANTED);
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrwh6", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get level 2 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level2);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-write-handle oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_write_handle, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrwh7", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev, ev2;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob2;
        IO_STATUS_BLOCK iosb2;

        test("Get read oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Get read-write-handle oplock", [&]() {
            ev2 = req_oplock_win7(h.get(), iosb2, oplock_type::read_write_handle, roob2);
        });

        test("Check first oplock broken", [&]() {
            if (!check_event(ev.get()))
                throw runtime_error("Oplock is not broken");

            if (roob.NewOplockLevel != (OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE))
                throw formatted_error("NewOplockLevel was {}, expected OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE", roob.NewOplockLevel);
        });

        test("Check second oplock not broken", [&]() {
            if (check_event(ev2.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrwh8", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev, ev2;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob2;
        IO_STATUS_BLOCK iosb2;

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Get read-write-handle oplock", [&]() {
            ev2 = req_oplock_win7(h.get(), iosb2, oplock_type::read_write_handle, roob2);
        });

        test("Check first oplock broken", [&]() {
            if (!check_event(ev.get()))
                throw runtime_error("Oplock is not broken");

            if (roob.NewOplockLevel != (OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE))
                throw formatted_error("NewOplockLevel was {}, expected OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE", roob.NewOplockLevel);
        });

        test("Check second oplock not broken", [&]() {
            if (check_event(ev2.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrwh9", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev, ev2;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob2;
        IO_STATUS_BLOCK iosb2;

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Get read-write-handle oplock", [&]() {
            ev2 = req_oplock_win7(h.get(), iosb2, oplock_type::read_write_handle, roob2);
        });

        test("Check first oplock broken", [&]() {
            if (!check_event(ev.get()))
                throw runtime_error("Oplock is not broken");

            if (roob.NewOplockLevel != (OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE))
                throw formatted_error("NewOplockLevel was {}, expected OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE", roob.NewOplockLevel);
        });

        test("Check second oplock not broken", [&]() {
            if (check_event(ev2.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrwh10", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev, ev2;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob2;
        IO_STATUS_BLOCK iosb2;

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Get read-write-handle oplock", [&]() {
            ev2 = req_oplock_win7(h.get(), iosb2, oplock_type::read_write_handle, roob2);
        });

        test("Check first oplock broken", [&]() {
            if (!check_event(ev.get()))
                throw runtime_error("Oplock is not broken");

            if (roob.NewOplockLevel != (OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE))
                throw formatted_error("NewOplockLevel was {}, expected OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE", roob.NewOplockLevel);
        });

        test("Check second oplock not broken", [&]() {
            if (check_event(ev2.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrwh11", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-write-handle oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_write_handle, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrwh12", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-write-handle oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_write_handle, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrwh13", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get batch oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_write_handle, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    disable_token_privileges(token);
}

void test_oplocks_filter(HANDLE token, const u16string& dir) {
    unique_handle h, h2;
    IO_STATUS_BLOCK iosb;
    auto data = random_data(4096);

    // needed to set valid data length
    test("Add SeManageVolumePrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_MANAGE_VOLUME_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockf1", FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\oplockf1", FILE_READ_DATA | FILE_WRITE_DATA | DELETE, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        unique_handle ev;

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock(ev.get(), h.get());

            test("Try to open second handle (FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK)", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\oplockf1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK, FILE_OPENED);
                }, STATUS_CANNOT_BREAK_OPLOCK);
            });

            test("Open second handle (FILE_OPEN, FILE_READ_DATA)", [&]() {
                h2 = create_file(dir + u"\\oplockf1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OPEN, FILE_WRITE_DATA)", [&]() {
                h2 = create_file(dir + u"\\oplockf1", FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();
        }

        test("Try to open second handle with FILE_RESERVE_OPFILTER", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\oplockf1", FILE_READ_ATTRIBUTES, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_OPEN, FILE_RESERVE_OPFILTER, FILE_OPENED);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED)", [&]() {
                create_file(dir + u"\\oplockf1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED, FILE_OPENED);
            });

            ack_oplock(ev.get(), h.get());

            test("Open second handle (FILE_SUPERSEDE)", [&]() {
                h2 = create_file(dir + u"\\oplockf1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_SUPERSEDE, 0, FILE_SUPERSEDED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();
        }

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock(ev.get(), h.get());

            test("Open second handle (FILE_OVERWRITE)", [&]() {
                h2 = create_file(dir + u"\\oplockf1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();
        }

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock(ev.get(), h.get());

            test("Open second handle (FILE_OVERWRITE_IF)", [&]() {
                h2 = create_file(dir + u"\\oplockf1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE_IF, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();
        }

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Read from file", [&]() {
            read_file_wait(h.get(), 4096, 0);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Unlock file", [&]() {
            unlock_file(h.get(), 0, 4096);
        });

        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set allocation", [&]() {
            set_allocation(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set valid data length", [&]() {
            set_valid_data_length(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Rename file", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\oplockf1a");
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Create hardlink", [&]() {
            set_link_information(h.get(), false, nullptr, dir + u"\\oplockf1b");
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set zero data", [&]() {
            set_zero_data(h.get(), 0, 100);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set disposition information", [&]() {
            set_disposition_information(h.get(), true);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockf2", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file with FILE_SYNCHRONOUS_IO_NONALERT", [&]() {
        h = create_file(dir + u"\\oplockf3", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Try to get filter oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb, oplock_type::filter);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\oplockf4", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Try to get filter oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb, oplock_type::filter);
            }, STATUS_INVALID_PARAMETER);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockf5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Open second handle on file", [&]() {
            h2 = create_file(dir + u"\\oplockf5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        if (h2) {
            test("Try to get filter oplock with two handles open", [&]() {
                exp_status([&]() {
                    req_oplock(h2.get(), iosb, oplock_type::batch);
                }, STATUS_OPLOCK_NOT_GRANTED);
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockf6", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev, ev2;
        IO_STATUS_BLOCK iosb2;

        test("Get level 2 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level2);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Get filter oplock", [&]() {
            ev2 = req_oplock(h.get(), iosb2, oplock_type::filter);
        });

        test("Check first oplock broken", [&]() {
            if (!check_event(ev.get()))
                throw runtime_error("Oplock is not broken");

            if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
        });

        test("Check second oplock not broken", [&]() {
            if (check_event(ev2.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockf7", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;
        IO_STATUS_BLOCK iosb2;

        test("Get read oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get filter oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::filter);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockf8", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;
        IO_STATUS_BLOCK iosb2;

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get filter oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::filter);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockf9", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;
        IO_STATUS_BLOCK iosb2;

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get filter oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::filter);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockf10", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob;
        IO_STATUS_BLOCK iosb2;

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get filter oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::filter);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockf11", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get filter oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::filter);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockf12", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get filter oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::filter);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockf13", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get filter oplock", [&]() {
            exp_status([&]() {
                req_oplock(h.get(), iosb2, oplock_type::filter);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    disable_token_privileges(token);
}

void test_oplocks_rh(HANDLE token, const u16string& dir) {
    unique_handle h, h2;
    IO_STATUS_BLOCK iosb;
    REQUEST_OPLOCK_OUTPUT_BUFFER roob;
    auto data = random_data(4096);

    // needed to set valid data length
    test("Add SeManageVolumePrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_MANAGE_VOLUME_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrh1", FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\oplockrh1", FILE_READ_DATA | FILE_WRITE_DATA | DELETE, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        unique_handle ev;

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock_win7(ev.get(), h.get());

            test("Open second handle (FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK)", [&]() {
                create_file(dir + u"\\oplockrh1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_OPEN, FILE_OPEN_REQUIRING_OPLOCK, FILE_OPENED);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplockrh1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");
            });

            h2.reset();
        }

        test("Try to open second handle with FILE_RESERVE_OPFILTER", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\oplockrh1", FILE_READ_ATTRIBUTES, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_OPEN, FILE_RESERVE_OPFILTER, FILE_OPENED);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        if (ev) {
            ack_oplock_win7(ev.get(), h.get());

            test("Try to open second handle (FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED)", [&]() {
                create_file(dir + u"\\oplockrh1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_OPEN, FILE_COMPLETE_IF_OPLOCKED, FILE_OPENED);
            });

            test("Check oplock is not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });
        }

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock_win7(ev.get(), h.get());

            test("Open second handle (FILE_SUPERSEDE)", [&]() {
                h2 = create_file(dir + u"\\oplockrh1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_SUPERSEDE, 0, FILE_SUPERSEDED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();
        }

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock_win7(ev.get(), h.get());

            test("Open second handle (FILE_OVERWRITE)", [&]() {
                h2 = create_file(dir + u"\\oplockrh1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();
        }

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            ack_oplock_win7(ev.get(), h.get());

            test("Open second handle (FILE_OVERWRITE_IF)", [&]() {
                h2 = create_file(dir + u"\\oplockrh1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE_IF, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });

            h2.reset();
        }

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Read from file", [&]() {
            read_file_wait(h.get(), 4096, 0);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Unlock file", [&]() {
            unlock_file(h.get(), 0, 4096);
        });

        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set allocation", [&]() {
            set_allocation(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set valid data length", [&]() {
            set_valid_data_length(h.get(), 4096);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Rename file", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\oplockrh1a");
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Create hardlink", [&]() {
            set_link_information(h.get(), false, nullptr, dir + u"\\oplockrh1b");
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set zero data", [&]() {
            set_zero_data(h.get(), 0, 100);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Set disposition information", [&]() {
            set_disposition_information(h.get(), true);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrh2", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Lock file", [&]() {
            lock_file_wait(h.get(), 0, 4096, false);
        });

        test("Try to get read-handle oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        h.reset();
    }

    test("Create file with FILE_SYNCHRONOUS_IO_NONALERT", [&]() {
        h = create_file(dir + u"\\oplockrh3", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Try to get read-handle oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\oplockrh4", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;

        // Succeeds on Windows 8 and above (see https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Create file in directory", [&]() {
                create_file(dir + u"\\oplockrh4\\file", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (roob.NewOplockLevel != 0)
                    throw formatted_error("NewOplockLevel was {}, expected 0", roob.NewOplockLevel);
            });
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrh5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Open second handle on file", [&]() {
            h2 = create_file(dir + u"\\oplockrh5", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        if (h2) {
            unique_handle ev;

            test("Get read-handle oplock with two handles open", [&]() {
                ev = req_oplock_win7(h2.get(), iosb, oplock_type::read_handle, roob);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrh6", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get level 2 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level2);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-handle oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_handle, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrh7", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev, ev2;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob2;
        IO_STATUS_BLOCK iosb2;

        test("Get read oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_oplock, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Get read-handle oplock", [&]() {
            ev2 = req_oplock_win7(h.get(), iosb2, oplock_type::read_write_handle, roob2);
        });

        test("Check first oplock broken", [&]() {
            if (!check_event(ev.get()))
                throw runtime_error("Oplock is not broken");

            if (roob.NewOplockLevel != (OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE))
                throw formatted_error("NewOplockLevel was {}, expected OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE", roob.NewOplockLevel);
        });

        test("Check second oplock not broken", [&]() {
            if (check_event(ev2.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrh8", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev, ev2;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob2;
        IO_STATUS_BLOCK iosb2;

        test("Get read-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Get read-handle oplock", [&]() {
            ev2 = req_oplock_win7(h.get(), iosb2, oplock_type::read_handle, roob2);
        });

        test("Check first oplock broken", [&]() {
            if (!check_event(ev.get()))
                throw runtime_error("Oplock is not broken");

            if (roob.NewOplockLevel != (OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE))
                throw formatted_error("NewOplockLevel was {}, expected OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE", roob.NewOplockLevel);
        });

        test("Check second oplock not broken", [&]() {
            if (check_event(ev2.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrh9", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob2;
        IO_STATUS_BLOCK iosb2;

        test("Get read-write oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-handle oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_handle, roob2);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrh10", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        REQUEST_OPLOCK_OUTPUT_BUFFER roob2;
        IO_STATUS_BLOCK iosb2;

        test("Get read-write-handle oplock", [&]() {
            ev = req_oplock_win7(h.get(), iosb, oplock_type::read_write_handle, roob);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-handle oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_handle, roob2);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrh11", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get level 1 oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::level1);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-handle oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_handle, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrh12", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get filter oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::filter);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get read-handle oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_handle, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplockrh13", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle ev;
        IO_STATUS_BLOCK iosb2;

        test("Get batch oplock", [&]() {
            ev = req_oplock(h.get(), iosb, oplock_type::batch);
        });

        test("Check oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        test("Try to get batch oplock", [&]() {
            exp_status([&]() {
                req_oplock_win7(h.get(), iosb2, oplock_type::read_handle, roob);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        test("Check first oplock not broken", [&]() {
            if (check_event(ev.get()))
                throw runtime_error("Oplock is broken");
        });

        h.reset();
    }

    // FIXME - FSCTL_OPLOCK_BREAK_ACK_NO_2
    // FIXME - FSCTL_OPBATCH_ACK_CLOSE_PENDING
    // FIXME - FSCTL_OPLOCK_BREAK_NOTIFY

    disable_token_privileges(token);
}
