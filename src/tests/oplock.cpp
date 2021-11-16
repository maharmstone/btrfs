#include "test.h"

using namespace std;

#define FSCTL_REQUEST_OPLOCK_LEVEL_2 CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define FILE_OPLOCK_BROKEN_TO_LEVEL_2       0x00000007
#define FILE_OPLOCK_BROKEN_TO_NONE          0x00000008

static unique_handle req_oplock_level2(HANDLE h, IO_STATUS_BLOCK& iosb) {
    NTSTATUS Status;
    HANDLE ev;

    iosb.Information = 0;

    Status = NtCreateEvent(&ev, MAXIMUM_ALLOWED, nullptr, NotificationEvent, false);
    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    Status = NtFsControlFile(h, ev, nullptr, nullptr, &iosb,
                             FSCTL_REQUEST_OPLOCK_LEVEL_2,
                             nullptr, 0, nullptr, 0);

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

void test_oplocks(HANDLE token, const u16string& dir) {
    unique_handle h, h2;
    IO_STATUS_BLOCK iosb;
    auto data = random_data(4096);

    // needed to set valid data length
    test("Add SeManageVolumePrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_MANAGE_VOLUME_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, array{ laa });
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplock1", FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\oplock1", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        unique_handle ev;

        test("Get level 2 oplock", [&]() {
            ev = req_oplock_level2(h.get(), iosb);
        });

        if (ev) {
            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplock1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Check oplock still not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            h2.reset();

            // FIXME - test level 2 oplock broken if file reopened with FILE_RESERVE_OPFILTER

            test("Open second handle (FILE_SUPERSEDE)", [&]() {
                h2 = create_file(dir + u"\\oplock1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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
                ev = req_oplock_level2(h.get(), iosb);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OVERWRITE)", [&]() {
                h2 = create_file(dir + u"\\oplock1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OVERWRITE, 0, FILE_OVERWRITTEN);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();

            test("Get level 2 oplock", [&]() {
                ev = req_oplock_level2(h.get(), iosb);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OVERWRITE_IF)", [&]() {
                h2 = create_file(dir + u"\\oplock1", FILE_READ_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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
                ev = req_oplock_level2(h.get(), iosb);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplock1", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Read from second handle", [&]() {
                read_file_wait(h2.get(), 4096, 0);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Write to second handle", [&]() {
                write_file_wait(h.get(), data, 0);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplock1", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Get level 2 oplock", [&]() {
                ev = req_oplock_level2(h.get(), iosb);
            });

            test("Check oplock not broken", [&]() {
                if (check_event(ev.get()))
                    throw runtime_error("Oplock is broken");
            });

            test("Lock file", [&]() {
                lock_file(h2.get(), 0, 4096, false);
            });

            test("Check oplock broken", [&]() {
                if (!check_event(ev.get()))
                    throw runtime_error("Oplock is not broken");

                if (iosb.Information != FILE_OPLOCK_BROKEN_TO_NONE)
                    throw formatted_error("iosb.Information was {}, expected FILE_OPLOCK_BROKEN_TO_NONE", iosb.Information);
            });

            h2.reset();

            test("Open second handle (FILE_OPEN)", [&]() {
                h2 = create_file(dir + u"\\oplock1", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, 0, FILE_OPENED);
            });

            test("Get level 2 oplock", [&]() {
                ev = req_oplock_level2(h.get(), iosb);
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
                ev = req_oplock_level2(h.get(), iosb);
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
                ev = req_oplock_level2(h.get(), iosb);
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

            // FIXME - FileRenameInformation
            // FIXME - FileLinkInformation
            // FIXME - FileDispositionInformation
            // FIXME - FSCTL_SET_ZERO_DATA

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\oplock2", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Lock file", [&]() {
            lock_file(h.get(), 0, 4096, false);
        });

        test("Try to get level 2 oplock", [&]() {
            exp_status([&]() {
                req_oplock_level2(h.get(), iosb);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        h.reset();
    }

    test("Create file with FILE_SYNCHRONOUS_IO_NONALERT", [&]() {
        h = create_file(dir + u"\\oplock3", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Try to get level 2 oplock", [&]() {
            exp_status([&]() {
                req_oplock_level2(h.get(), iosb);
            }, STATUS_OPLOCK_NOT_GRANTED);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\oplock4", FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Try to get level 2 oplock", [&]() {
            exp_status([&]() {
                req_oplock_level2(h.get(), iosb);
            }, STATUS_INVALID_PARAMETER);
        });

        h.reset();
    }

    // FIXME - test granted if level 2 / read oplocks already there
    // FIXME - test not granted (STATUS_OPLOCK_NOT_GRANTED) if any other sort of oplock there

    // FIXME - level 1 oplocks
    // FIXME - batch oplocks
    // FIXME - filter oplocks
    // FIXME - read oplocks
    // FIXME - read-handle oplocks
    // FIXME - read-write oplocks
    // FIXME - read-write-handle oplocks

    // FIXME - FSCTL_OPLOCK_BREAK_ACKNOWLEDGE
    // FIXME - FSCTL_OPLOCK_BREAK_ACK_NO_2
    // FIXME - FSCTL_OPBATCH_ACK_CLOSE_PENDING
    // FIXME - FSCTL_OPLOCK_BREAK_NOTIFY
    // FIXME - FSCTL_REQUEST_OPLOCK (request and ack)

    // FIXME - FILE_RESERVE_OPFILTER
    // FIXME - FILE_OPEN_REQUIRING_OPLOCK
    // FIXME - FILE_COMPLETE_IF_OPLOCKED

    disable_token_privileges(token);
}
