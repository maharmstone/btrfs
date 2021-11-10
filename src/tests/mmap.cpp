#include "test.h"

using namespace std;

static unique_handle create_section(ACCESS_MASK access, optional<uint64_t> max_size, ULONG prot,
                                    ULONG atts, HANDLE file) {
    NTSTATUS Status;
    HANDLE h;
    LARGE_INTEGER li;

    if (max_size)
        li.QuadPart = max_size.value();

    Status = NtCreateSection(&h, access, nullptr, max_size ? &li : nullptr, prot, atts, file);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    return unique_handle(h);
}

static void* map_view(HANDLE sect, uint64_t off, uint64_t len, ULONG prot) {
    NTSTATUS Status;
    void* addr = nullptr;
    LARGE_INTEGER li;
    SIZE_T size = len;

    li.QuadPart = off;

    Status = NtMapViewOfSection(sect, NtCurrentProcess(), &addr, 0, 0, &li, &size,
                                ViewUnmap, 0, prot);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (!addr)
        throw runtime_error("NtMapViewOfSection returned address of 0.");

    return addr;
}

static void lock_file(HANDLE h, uint64_t offset, uint64_t length, bool exclusive) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offli, lenli;

    offli.QuadPart = offset;
    lenli.QuadPart = length;

    Status = NtLockFile(h, nullptr, nullptr, nullptr, &iosb, &offli, &lenli,
                        0, false, exclusive);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

void set_disposition_information(HANDLE h, bool delete_file) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    FILE_DISPOSITION_INFORMATION fdi;

    fdi.DoDeleteFile = delete_file;

    iosb.Information = 0xdeadbeef;

    Status = NtSetInformationFile(h, &iosb, &fdi, sizeof(fdi), FileDispositionInformation);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != 0)
        throw formatted_error("iosb.Information was {}, expected 0", iosb.Information);
}

void test_mmap(const u16string& dir) {
    unique_handle h;

    test("Create empty file", [&]() {
        h = create_file(dir + u"\\mmapempty", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try to create section on empty file", [&]() {
            exp_status([&]() {
                auto sect = create_section(SECTION_ALL_ACCESS, nullopt, PAGE_READONLY, SEC_COMMIT, h.get());
            }, STATUS_MAPPED_FILE_SIZE_ZERO);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\mmapdir", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Try to create section on directory", [&]() {
            exp_status([&]() {
                auto sect = create_section(SECTION_ALL_ACCESS, nullopt, PAGE_READONLY, SEC_COMMIT, h.get());
            }, STATUS_INVALID_FILE_FOR_SECTION);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\mmap1", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        auto data = random_data(4096);

        test("Write to file", [&]() {
            write_file(h.get(), data);
        });

        unique_handle sect;

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, nullopt, PAGE_READONLY, SEC_COMMIT, h.get());
        });

        void* addr = nullptr;

        test("Map view", [&]() {
            addr = map_view(sect.get(), 0, data.size(), PAGE_READONLY);
        });

        if (addr) {
            test("Check data in mapping", [&]() {
                if (memcmp(addr, data.data(), data.size()))
                    throw runtime_error("Data in mapping did not match was written.");
            });

            uint32_t num = 0xdeadbeef;

            test("Write to file", [&]() {
                write_file(h.get(), span<uint8_t>((uint8_t*)&num, sizeof(uint32_t)), 0);
            });

            test("Check data in mapping again", [&]() {
                if (*(uint32_t*)addr != num)
                    throw runtime_error("Data in mapping did not match was written.");
            });
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\mmap2", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        test("Try to create section larger than file", [&]() {
            exp_status([&]() {
                create_section(SECTION_ALL_ACCESS, 8192, PAGE_READONLY, SEC_COMMIT, h.get());
            }, STATUS_SECTION_TOO_BIG);
        });
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\mmap3", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        h.reset();

        test("Reopen file without FILE_WRITE_DATA", [&]() {
            h = create_file(dir + u"\\mmap3", SYNCHRONIZE | FILE_READ_DATA, 0, 0,
                            FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, FILE_OPENED);
        });

        test("Try to create RW section on RO file", [&]() {
            exp_status([&]() {
                create_section(SECTION_ALL_ACCESS, 4096, PAGE_READWRITE, SEC_COMMIT, h.get());
            }, STATUS_ACCESS_DENIED);
        });
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\mmap4", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        auto data = random_data(4096);

        test("Write to file", [&]() {
            write_file(h.get(), data);
        });

        unique_handle sect;

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, nullopt, PAGE_READWRITE, SEC_COMMIT, h.get());
        });

        void* addr = nullptr;

        test("Map view", [&]() {
            addr = map_view(sect.get(), 0, data.size(), PAGE_READWRITE);
        });

        if (addr) {
            test("Check data in mapping", [&]() {
                if (memcmp(addr, data.data(), data.size()))
                    throw runtime_error("Data in mapping did not match was written.");
            });

            *(uint32_t*)addr = 0xdeadbeef;

            test("Read from file", [&]() {
                auto buf = read_file(h.get(), sizeof(uint32_t), 0);

                if (buf.size() != sizeof(uint32_t))
                    throw formatted_error("Read {} bytes, expected {}.", buf.size(), sizeof(uint32_t));

                auto& num = *(uint32_t*)buf.data();

                if (num != 0xdeadbeef)
                    throw runtime_error("Data read did not match was written to mapping.");
            });
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\mmap5", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        test("Lock file", [&]() {
            lock_file(h.get(), 0, 4096, true);
        });

        unique_handle sect;

        test("Create section on locked file", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, 4096, PAGE_READWRITE, SEC_COMMIT, h.get());
        });

        test("Map view", [&]() {
            map_view(sect.get(), 0, 4096, PAGE_READWRITE);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\mmap6", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        unique_handle sect;

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, 4096, PAGE_READWRITE, SEC_COMMIT, h.get());
        });

        test("Extend file", [&]() {
            set_end_of_file(h.get(), 8192);
        });

        test("Try clearing file", [&]() {
            exp_status([&]() {
                set_end_of_file(h.get(), 0);
            }, STATUS_USER_MAPPED_FILE);
        });

        test("Try setting file to original size", [&]() {
            exp_status([&]() {
                set_end_of_file(h.get(), 4096);
            }, STATUS_USER_MAPPED_FILE);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\mmap7", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA | DELETE,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        unique_handle sect;

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, 4096, PAGE_READWRITE, SEC_COMMIT, h.get());
        });

        test("Try deleting file", [&]() {
            exp_status([&]() {
                set_disposition_information(h.get(), true);
            }, STATUS_CANNOT_DELETE);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\mmap8", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA | DELETE,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        unique_handle sect;

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, 4096, PAGE_READWRITE, SEC_COMMIT, h.get());
        });

        if (sect) {
            test("Map view", [&]() {
                map_view(sect.get(), 0, 4096, PAGE_READWRITE);
            });
        }

        h.reset();

        test("Create file 2", [&]() {
            h = create_file(dir + u"\\mmap8a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        if (h) {
            test("Overwrite mapped file", [&]() {
                set_rename_information(h.get(), true, nullptr, dir + u"\\mmap8");
            });
        }
    }
}
