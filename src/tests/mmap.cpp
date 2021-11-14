#include "test.h"

using namespace std;

unique_handle create_section(ACCESS_MASK access, optional<uint64_t> max_size, ULONG prot,
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

    if (Status != STATUS_SUCCESS && Status != STATUS_IMAGE_NOT_AT_BASE)
        throw ntstatus_error(Status);

    if (!addr)
        throw runtime_error("NtMapViewOfSection returned address of 0.");

    return addr;
}

static void unmap_view(void* addr) {
    NTSTATUS Status;

    Status = NtUnmapViewOfSection(NtCurrentProcess(), addr);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
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

static constexpr unsigned int align(unsigned int x, unsigned int a) {
    return (x + a - 1) & ~(a - 1);
}

vector<uint8_t> pe_image(span<const std::byte> data) {
    static const char stub[] = "\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n\x24\x00\x00\x00\x00\x00\x00\x00";
    static const unsigned int SECTION_ALIGNMENT = 0x1000;
    static const unsigned int FILE_ALIGNMENT = 0x200;
    static constexpr unsigned int header_size = align(sizeof(IMAGE_DOS_HEADER) + sizeof(stub) - 1 + sizeof(IMAGE_NT_HEADERS32) + sizeof(IMAGE_SECTION_HEADER),
                                                      FILE_ALIGNMENT);

    vector<uint8_t> buf(header_size + align(data.size(), FILE_ALIGNMENT));
    memset(buf.data(), 0, buf.size());

    auto& h = *(IMAGE_DOS_HEADER*)buf.data();
    h.e_magic = IMAGE_DOS_SIGNATURE;
    h.e_cblp = 0x90;
    h.e_cp = 0x3;
    h.e_cparhdr = 0x4;
    h.e_maxalloc = 0xffff;
    h.e_sp = 0xb8;
    h.e_lfarlc = 0x40;
    h.e_lfanew = sizeof(h) + sizeof(stub) - 1;

    memcpy(buf.data() + sizeof(h), stub, sizeof(stub) - 1);

    auto& nth = *(IMAGE_NT_HEADERS32*)(buf.data() + h.e_lfanew);

    nth.Signature = IMAGE_NT_SIGNATURE;
    nth.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    nth.FileHeader.NumberOfSections = 1;
    nth.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    nth.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;

    nth.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    nth.OptionalHeader.MajorLinkerVersion = 0x2;
    nth.OptionalHeader.MinorLinkerVersion = 0x23;
    nth.OptionalHeader.SizeOfCode = 0;
    nth.OptionalHeader.SizeOfInitializedData = align(data.size(), SECTION_ALIGNMENT);
    nth.OptionalHeader.SizeOfUninitializedData = 0;
    nth.OptionalHeader.AddressOfEntryPoint = 0;
    nth.OptionalHeader.BaseOfCode = 0x1000;
    nth.OptionalHeader.BaseOfData = 0x1000;
    nth.OptionalHeader.ImageBase = 0x10000000;
    nth.OptionalHeader.SectionAlignment = SECTION_ALIGNMENT;
    nth.OptionalHeader.FileAlignment = FILE_ALIGNMENT;
    nth.OptionalHeader.MajorOperatingSystemVersion = 4;
    nth.OptionalHeader.MinorOperatingSystemVersion = 0;
    nth.OptionalHeader.MajorImageVersion = 0;
    nth.OptionalHeader.MinorImageVersion = 0;
    nth.OptionalHeader.MajorSubsystemVersion = 5;
    nth.OptionalHeader.MinorSubsystemVersion = 2;
    nth.OptionalHeader.Win32VersionValue = 0;
    nth.OptionalHeader.SizeOfImage = align(header_size, SECTION_ALIGNMENT) + align(data.size(), SECTION_ALIGNMENT);
    nth.OptionalHeader.SizeOfHeaders = header_size;
    nth.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    nth.OptionalHeader.DllCharacteristics = 0;
    nth.OptionalHeader.SizeOfStackReserve = 0x100000;
    nth.OptionalHeader.SizeOfStackCommit = 0x1000;
    nth.OptionalHeader.SizeOfHeapReserve = 0x100000;
    nth.OptionalHeader.SizeOfHeapCommit = 0x1000;
    nth.OptionalHeader.LoaderFlags = 0;
    nth.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    auto& sect = *(IMAGE_SECTION_HEADER*)(&nth + 1);
    memcpy(sect.Name, ".data\0\0\0", 8);
    sect.Misc.VirtualSize = align(data.size(), SECTION_ALIGNMENT);
    sect.VirtualAddress = align(header_size, SECTION_ALIGNMENT);
    sect.SizeOfRawData = align(data.size(), FILE_ALIGNMENT);
    sect.PointerToRawData = header_size;
    sect.PointerToRelocations = 0;
    sect.PointerToLinenumbers = 0;
    sect.NumberOfRelocations = 0;
    sect.NumberOfLinenumbers = 0;
    sect.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

    memcpy(buf.data() + header_size, data.data(), data.size());

    return buf;
}

void test_mmap(const u16string& dir) {
    unique_handle h, h2;

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

            test("Unmap view", [&]() {
                unmap_view(addr);
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

            test("Unmap view", [&]() {
                unmap_view(addr);
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

        void* addr = nullptr;

        test("Map view", [&]() {
            addr = map_view(sect.get(), 0, 4096, PAGE_READWRITE);
        });

        if (addr) {
            test("Unmap view", [&]() {
                unmap_view(addr);
            });
        }

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
        void* addr = nullptr;

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, 4096, PAGE_READWRITE, SEC_COMMIT, h.get());
        });

        if (sect) {
            test("Map view", [&]() {
                addr = map_view(sect.get(), 0, 4096, PAGE_READWRITE);
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

        if (addr) {
            test("Unmap view", [&]() {
                unmap_view(addr);
            });
        }
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\mmap9", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA | DELETE,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        test("Mark file for deletion", [&]() {
            set_disposition_information(h.get(), true);
        });

        unique_handle sect;

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, 4096, PAGE_READWRITE, SEC_COMMIT, h.get());
        });

        if (sect) {
            void* addr = nullptr;

            test("Map view", [&]() {
                addr = map_view(sect.get(), 0, 4096, PAGE_READWRITE);
            });

            if (addr) {
                test("Unmap view", [&]() {
                    unmap_view(addr);
                });
            }
        }

        h.reset();
    }

    auto imgdata = as_bytes(span("hello"));
    auto img = pe_image(imgdata);

    test("Create image file", [&]() {
        h = create_file(dir + u"\\mmap10", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        unique_handle sect;

        test("Write to file", [&]() {
            write_file(h.get(), img);
        });

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, nullopt, PAGE_READWRITE, SEC_IMAGE, h.get());
        });

        if (sect) {
            void* pe = nullptr;

            test("Map view", [&]() {
                pe = map_view(sect.get(), 0, 0, PAGE_READWRITE);

                if (!pe)
                    throw runtime_error("Address returned was NULL.");
            });

            if (pe) {
                test("Check mapped data", [&]() {
                    if (memcmp((uint8_t*)pe + 0x1000, imgdata.data(), imgdata.size()))
                        throw runtime_error("Data mapped did not match data written.");
                });

                test("Unmap view", [&]() {
                    unmap_view(pe);
                });
            }
        }

        h.reset();
    }

    test("Create image file", [&]() {
        h = create_file(dir + u"\\mmap11", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        unique_handle sect;

        test("Write to file", [&]() {
            write_file(h.get(), img);
        });

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, nullopt, PAGE_READWRITE, SEC_IMAGE, h.get());
        });

        if (sect) {
            void* pe = nullptr;

            test("Map view", [&]() {
                pe = map_view(sect.get(), 0, 0, PAGE_READWRITE);

                if (!pe)
                    throw runtime_error("Address returned was NULL.");
            });

            if (pe) {
                test("Try to truncate file", [&]() {
                    exp_status([&]() {
                        set_end_of_file(h.get(), 0);
                    }, STATUS_USER_MAPPED_FILE);
                });

                test("Extend file", [&]() {
                    set_end_of_file(h.get(), 8192);
                });

                test("Try to truncate file again", [&]() {
                    exp_status([&]() {
                        set_end_of_file(h.get(), 4096);
                    }, STATUS_USER_MAPPED_FILE);
                });

                test("Unmap view", [&]() {
                    unmap_view(pe);
                });
            }
        }

        h.reset();
    }

    test("Create image file", [&]() {
        h = create_file(dir + u"\\mmap12", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
                        0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        unique_handle sect;

        test("Write to file", [&]() {
            write_file(h.get(), img);
        });

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, nullopt, PAGE_READWRITE, SEC_IMAGE, h.get());
        });

        h.reset();

        if (sect) {
            test("Try overwriting mapped image file", [&]() {
                exp_status([&]() {
                    create_file(dir + u"\\mmap12", MAXIMUM_ALLOWED, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OVERWRITE, 0, FILE_OVERWRITTEN);
                }, STATUS_SHARING_VIOLATION);
            });
        }
    }

    test("Create image file", [&]() {
        h = create_file(dir + u"\\mmap13a", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    test("Create file", [&]() {
        h2 = create_file(dir + u"\\mmap13b", MAXIMUM_ALLOWED,
                         0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle sect;

        test("Write to file", [&]() {
            write_file(h.get(), img);
        });

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, nullopt, PAGE_READWRITE, SEC_IMAGE, h.get());
        });

        h.reset();

        if (sect) {
            test("Try overwriting mapped image file by rename", [&]() {
                exp_status([&]() {
                    set_rename_information(h2.get(), true, nullptr, dir + u"\\mmap13a");
                }, STATUS_ACCESS_DENIED);
            });
        }

        h2.reset();
    }

    test("Create image file", [&]() {
        h = create_file(dir + u"\\mmap14", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA | DELETE,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        unique_handle sect;

        test("Write to file", [&]() {
            write_file(h.get(), img);
        });

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, nullopt, PAGE_READWRITE, SEC_IMAGE, h.get());
        });

        if (sect) {
            test("Try deleting mapped image file", [&]() {
                exp_status([&]() {
                    set_disposition_information(h.get(), true);
                }, STATUS_CANNOT_DELETE);
            });
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\mmap15", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA | DELETE,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Set end of file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        unique_handle sect;
        void* addr = nullptr;

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, 4096, PAGE_READWRITE, SEC_COMMIT, h.get());
        });

        if (sect) {
            test("Map view", [&]() {
                addr = map_view(sect.get(), 0, 4096, PAGE_READWRITE);
            });
        }

        h.reset();

        test("Create file 2", [&]() {
            h = create_file(dir + u"\\mmap15a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        if (h) {
            test("Overwrite mapped file by linking", [&]() {
                set_link_information(h.get(), true, nullptr, dir + u"\\mmap15");
            });
        }

        if (addr) {
            test("Unmap view", [&]() {
                unmap_view(addr);
            });
        }
    }

    test("Create image file", [&]() {
        h = create_file(dir + u"\\mmap16a", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    test("Create file", [&]() {
        h2 = create_file(dir + u"\\mmap16b", MAXIMUM_ALLOWED,
                         0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle sect;

        test("Write to file", [&]() {
            write_file(h.get(), img);
        });

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, nullopt, PAGE_READWRITE, SEC_IMAGE, h.get());
        });

        h.reset();

        if (sect) {
            test("Try overwriting mapped image file by linking", [&]() {
                exp_status([&]() {
                    set_link_information(h2.get(), true, nullptr, dir + u"\\mmap16a");
                }, STATUS_ACCESS_DENIED);
            });
        }

        h2.reset();
    }
}
