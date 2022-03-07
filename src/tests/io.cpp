#include "test.h"
#include <random>
#include <span>
#include <array>

using namespace std;

#define FSCTL_SET_ZERO_DATA CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 50, METHOD_BUFFERED, FILE_WRITE_DATA)

void adjust_token_privileges(HANDLE token, const LUID_AND_ATTRIBUTES& priv) {
    NTSTATUS Status;
    array<uint8_t, offsetof(TOKEN_PRIVILEGES, Privileges) + sizeof(LUID_AND_ATTRIBUTES)> buf;
    auto& tp = *(TOKEN_PRIVILEGES*)buf.data();

    tp.PrivilegeCount = 1;
    tp.Privileges[0] = priv;

    Status = NtAdjustPrivilegesToken(token, false, &tp, 0, nullptr, nullptr);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

void set_allocation(HANDLE h, uint64_t alloc) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    FILE_ALLOCATION_INFORMATION fai;

    fai.AllocationSize.QuadPart = alloc;

    Status = NtSetInformationFile(h, &iosb, &fai, sizeof(fai), FileAllocationInformation);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != 0)
        throw formatted_error("iosb.Information was {}, expected 0", iosb.Information);
}

vector<uint8_t> random_data(size_t len) {
    vector<uint8_t> random(len);

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint32_t> distrib(0, 0xffffffff);

    for (auto& s : span((uint32_t*)random.data(), random.size() / sizeof(uint32_t))) {
        s = distrib(gen);
    }

    return random;
}

void write_file(HANDLE h, span<const uint8_t> data, optional<uint64_t> offset) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER off;

    if (offset)
        off.QuadPart = *offset;

    Status = NtWriteFile(h, nullptr, nullptr, nullptr, &iosb, (void*)data.data(),
                         data.size(), offset ? &off : nullptr,
                         nullptr);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != data.size())
        throw formatted_error("iosb.Information was {}, expected {}", iosb.Information, data.size());
}

unique_handle create_event() {
    NTSTATUS Status;
    HANDLE h;

    Status = NtCreateEvent(&h, EVENT_ALL_ACCESS, nullptr, NotificationEvent, false);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    return unique_handle(h);
}

void write_file_wait(HANDLE h, span<const uint8_t> data, optional<uint64_t> offset) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER off;

    if (offset)
        off.QuadPart = *offset;

    auto event = create_event();

    Status = NtWriteFile(h, event.get(), nullptr, nullptr, &iosb, (void*)data.data(),
                         data.size(), offset ? &off : nullptr,
                         nullptr);

    if (Status == STATUS_PENDING) {
        Status = NtWaitForSingleObject(event.get(), false, nullptr);
        if (Status != STATUS_SUCCESS)
            throw ntstatus_error(Status);

        Status = iosb.Status;
    }

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != data.size())
        throw formatted_error("iosb.Information was {}, expected {}", iosb.Information, data.size());
}

vector<uint8_t> read_file(HANDLE h, ULONG len, optional<uint64_t> offset) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    vector<uint8_t> buf(len);
    LARGE_INTEGER off;

    if (offset)
        off.QuadPart = *offset;

    buf.resize(len);

    Status = NtReadFile(h, nullptr, nullptr, nullptr, &iosb,
                        buf.data(), len, offset ? &off : nullptr,
                        nullptr);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information > len)
        throw formatted_error("iosb.Information was {}, expected maximum of {}", iosb.Information, len);

    buf.resize(iosb.Information);

    return buf;
}

vector<uint8_t> read_file_wait(HANDLE h, ULONG len, optional<uint64_t> offset) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    vector<uint8_t> buf(len);
    LARGE_INTEGER off;

    if (offset)
        off.QuadPart = *offset;

    buf.resize(len);

    auto event = create_event();

    Status = NtReadFile(h, event.get(), nullptr, nullptr, &iosb,
                        buf.data(), len, offset ? &off : nullptr,
                        nullptr);

    if (Status == STATUS_PENDING) {
        Status = NtWaitForSingleObject(event.get(), false, nullptr);
        if (Status != STATUS_SUCCESS)
            throw ntstatus_error(Status);

        Status = iosb.Status;
    }

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information > len)
        throw formatted_error("iosb.Information was {}, expected maximum of {}", iosb.Information, len);

    buf.resize(iosb.Information);

    return buf;
}

static void set_position(HANDLE h, uint64_t pos) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    FILE_POSITION_INFORMATION fpi;

    fpi.CurrentByteOffset.QuadPart = pos;

    iosb.Information = 0xdeadbeef;

    Status = NtSetInformationFile(h, &iosb, &fpi, sizeof(fpi), FilePositionInformation);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != 0)
        throw formatted_error("iosb.Information was {}, expected 0", iosb.Information);
}

void set_valid_data_length(HANDLE h, uint64_t vdl) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    FILE_VALID_DATA_LENGTH_INFORMATION fvdli;

    fvdli.ValidDataLength.QuadPart = vdl;

    Status = NtSetInformationFile(h, &iosb, &fvdli, sizeof(fvdli), FileValidDataLengthInformation);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != 0)
        throw formatted_error("iosb.Information was {}, expected 0", iosb.Information);
}

void set_end_of_file(HANDLE h, uint64_t eof) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    FILE_END_OF_FILE_INFORMATION feofi;

    feofi.EndOfFile.QuadPart = eof;

    Status = NtSetInformationFile(h, &iosb, &feofi, sizeof(feofi), FileEndOfFileInformation);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != 0)
        throw formatted_error("iosb.Information was {}, expected 0", iosb.Information);
}

void set_zero_data(HANDLE h, uint64_t start, uint64_t end) {
    NTSTATUS Status;
    FILE_ZERO_DATA_INFORMATION fzdi;
    IO_STATUS_BLOCK iosb;

    fzdi.FileOffset.QuadPart = start;
    fzdi.BeyondFinalZero.QuadPart = end;

    auto ev = create_event();

    Status = NtFsControlFile(h, ev.get(), nullptr, nullptr, &iosb,
                             FSCTL_SET_ZERO_DATA, &fzdi, sizeof(fzdi),
                             nullptr, 0);

    if (Status == STATUS_PENDING) {
        Status = NtWaitForSingleObject(ev.get(), false, nullptr);
        if (Status != STATUS_SUCCESS)
            throw ntstatus_error(Status);

        Status = iosb.Status;
    }

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

void test_io(HANDLE token, const u16string& dir) {
    unique_handle h;

    // needed to set VDL
    test("Add SeManageVolumePrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_MANAGE_VOLUME_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    auto write_check = [&](uint64_t multiple, bool sector_align) {
        auto random = random_data(multiple * 2);

        test("Write file", [&]() {
            write_file(h.get(), random);
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != random.size()) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, random.size());
            }
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if ((uint64_t)fsi.AllocationSize.QuadPart < random.size()) {
                throw formatted_error("AllocationSize was {}, expected at least {}",
                                      fsi.AllocationSize.QuadPart, random.size());
            }

            if ((uint64_t)fsi.EndOfFile.QuadPart != random.size()) {
                throw formatted_error("EndOfFile was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, random.size());
            }
        });

        test("Check compression information", [&]() {
            auto fci = query_information<FILE_COMPRESSION_INFORMATION>(h.get());

            if ((size_t)fci.CompressedFileSize.QuadPart != random.size())
                throw formatted_error("CompressedFileSize was {}, expected {}", fci.CompressedFileSize.QuadPart, random.size());
        });

        test("Read file at end", [&]() {
            exp_status([&]() {
                read_file(h.get(), sector_align ? multiple : 100);
            }, STATUS_END_OF_FILE);
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != random.size()) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, random.size());
            }
        });

        if (sector_align) {
            test("Set position", [&]() {
                set_position(h.get(), random.size() + multiple);
            });

            test("Check position", [&]() {
                auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

                if ((uint64_t)fpi.CurrentByteOffset.QuadPart != random.size() + multiple) {
                    throw formatted_error("CurrentByteOffset was {}, expected {}",
                                          fpi.CurrentByteOffset.QuadPart, random.size() + multiple);
                }
            });

            test("Read file after end", [&]() {
                exp_status([&]() {
                    read_file(h.get(), multiple);
                }, STATUS_END_OF_FILE);
            });

            test("Check position", [&]() {
                auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

                if ((uint64_t)fpi.CurrentByteOffset.QuadPart != random.size() + multiple) {
                    throw formatted_error("CurrentByteOffset was {}, expected {}",
                                          fpi.CurrentByteOffset.QuadPart, random.size() + multiple);
                }
            });
        } else {
            test("Set position", [&]() {
                set_position(h.get(), random.size() + 100);
            });

            test("Check position", [&]() {
                auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

                if ((uint64_t)fpi.CurrentByteOffset.QuadPart != random.size() + 100) {
                    throw formatted_error("CurrentByteOffset was {}, expected {}",
                                        fpi.CurrentByteOffset.QuadPart, random.size() + 100);
                }
            });

            test("Read file after end", [&]() {
                exp_status([&]() {
                    read_file(h.get(), 100);
                }, STATUS_END_OF_FILE);
            });

            test("Check position", [&]() {
                auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

                if ((uint64_t)fpi.CurrentByteOffset.QuadPart != random.size() + 100) {
                    throw formatted_error("CurrentByteOffset was {}, expected {}",
                                        fpi.CurrentByteOffset.QuadPart, random.size() + 100);
                }
            });
        }

        test("Set negative position", [&]() {
            exp_status([&]() {
                set_position(h.get(), -100);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Set position to start", [&]() {
            set_position(h.get(), 0);
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 0) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 0);
            }
        });

        test("Read whole file", [&]() {
            auto ret = read_file(h.get(), random.size());

            if (ret.size() != random.size())
                throw formatted_error("{} bytes read, expected {}", ret.size(), random.size());

            if (memcmp(ret.data(), random.data(), random.size()))
                throw runtime_error("Data read did not match data written");
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != random.size()) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, random.size());
            }
        });

        test("Set position to start", [&]() {
            set_position(h.get(), 0);
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 0) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 0);
            }
        });

        if (sector_align) {
            test("Try reading 100 bytes", [&]() {
                exp_status([&]() {
                    read_file(h.get(), 100);
                }, STATUS_INVALID_PARAMETER);
            });

            test("Try seting position to odd value near end", [&]() {
                exp_status([&]() {
                    set_position(h.get(), random.size() - 100);
                }, STATUS_INVALID_PARAMETER);
            });

            test("Set position to near end", [&]() {
                set_position(h.get(), random.size() - multiple);
            });

            test("Read past end of file", [&]() {
                auto ret = read_file(h.get(), multiple * 2);

                if (ret.size() != multiple)
                    throw formatted_error("{} bytes read, expected {}", ret.size(), multiple);

                if (memcmp(ret.data(), random.data() + random.size() - multiple, multiple))
                    throw runtime_error("Data read did not match data written");
            });
        } else {
            test("Read 100 bytes", [&]() {
                auto ret = read_file(h.get(), 100);

                if (ret.size() != 100)
                    throw formatted_error("{} bytes read, expected {}", ret.size(), 100);

                if (memcmp(ret.data(), random.data(), 100))
                    throw runtime_error("Data read did not match data written");
            });

            test("Check position", [&]() {
                auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

                if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 100) {
                    throw formatted_error("CurrentByteOffset was {}, expected {}",
                                        fpi.CurrentByteOffset.QuadPart, 100);
                }
            });

            test("Set position to near end", [&]() {
                set_position(h.get(), random.size() - 100);
            });

            test("Check position", [&]() {
                auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

                if ((uint64_t)fpi.CurrentByteOffset.QuadPart != random.size() - 100) {
                    throw formatted_error("CurrentByteOffset was {}, expected {}",
                                        fpi.CurrentByteOffset.QuadPart, random.size() - 100);
                }
            });

            test("Read past end of file", [&]() {
                auto ret = read_file(h.get(), 200);

                if (ret.size() != 100)
                    throw formatted_error("{} bytes read, expected {}", ret.size(), 100);

                if (memcmp(ret.data(), random.data() + random.size() - 100, 100))
                    throw runtime_error("Data read did not match data written");
            });

            test("Check position", [&]() {
                auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

                if ((uint64_t)fpi.CurrentByteOffset.QuadPart != random.size()) {
                    throw formatted_error("CurrentByteOffset was {}, expected {}",
                                        fpi.CurrentByteOffset.QuadPart, random.size());
                }
            });
        }


        test("Extend file", [&]() {
            set_end_of_file(h.get(), multiple * 3);
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if ((uint64_t)fsi.EndOfFile.QuadPart != multiple * 3) {
                throw formatted_error("EndOfFile was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, random.size());
            }
        });

        test("Read new end of file", [&]() {
            auto ret = read_file(h.get(), multiple * 2);

            if (ret.size() != multiple)
                throw formatted_error("{} bytes read, expected {}", ret.size(), multiple);

            auto it = ranges::find_if(ret, [](uint8_t c) {
                return c != 0;
            });

            if (it != ret.end())
                throw runtime_error("End of file not zeroed");
        });

        test("Try setting valid data length to 0", [&]() {
            exp_status([&]() {
                set_valid_data_length(h.get(), 0);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Set valid data length to end of file", [&]() {
            set_valid_data_length(h.get(), multiple * 3);
        });

        test("Try setting valid data length to after end of file", [&]() {
            exp_status([&]() {
                set_valid_data_length(h.get(), multiple * 4);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Truncate file", [&]() {
            set_end_of_file(h.get(), multiple);
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if ((uint64_t)fsi.EndOfFile.QuadPart != multiple) {
                throw formatted_error("EndOfFile was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, multiple);
            }
        });

        test("Set position to start", [&]() {
            set_position(h.get(), 0);
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 0) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 0);
            }
        });

        test("Read whole file", [&]() {
            auto ret = read_file(h.get(), random.size());

            if (ret.size() != multiple)
                throw formatted_error("{} bytes read, expected {}", ret.size(), multiple);

            if (memcmp(ret.data(), random.data(), multiple))
                throw runtime_error("Data read did not match data written");
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != multiple) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, random.size());
            }
        });
    };

    test("Create file (long)", [&]() {
        h = create_file(dir + u"\\io", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                        FILE_CREATED);
    });

    if (h) {
        write_check(4096, false);

        h.reset();
    }

    test("Create file (short)", [&]() {
        h = create_file(dir + u"\\ioshort", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                        FILE_CREATED);
    });

    if (h) {
        write_check(200, false);

        h.reset();
    }

    disable_token_privileges(token);

    test("Create file", [&]() {
        h = create_file(dir + u"\\io2", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                        FILE_CREATED);
    });

    if (h) {
        test("Extend file", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        test("Try setting valid data length without privilege", [&]() {
            exp_status([&]() {
                set_valid_data_length(h.get(), 4096);
            }, STATUS_PRIVILEGE_NOT_HELD);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\ioalloc", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                        FILE_CREATED);
    });

    if (h) {
        test("Set allocation to 4096", [&]() {
            set_allocation(h.get(), 4096);
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if ((uint64_t)fsi.AllocationSize.QuadPart != 4096) {
                throw formatted_error("AllocationSize was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 4096);
            }

            if ((uint64_t)fsi.EndOfFile.QuadPart != 0) {
                throw formatted_error("EndOfFile was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 0);
            }
        });

        auto random = random_data(4096);

        test("Write data", [&]() {
            write_file(h.get(), random);
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if ((uint64_t)fsi.AllocationSize.QuadPart != 4096) {
                throw formatted_error("AllocationSize was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 4096);
            }

            if ((uint64_t)fsi.EndOfFile.QuadPart != 4096) {
                throw formatted_error("EndOfFile was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 4096);
            }
        });

        test("Set allocation to 0", [&]() {
            set_allocation(h.get(), 0);
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if ((uint64_t)fsi.AllocationSize.QuadPart != 0) {
                throw formatted_error("AllocationSize was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 0);
            }

            if ((uint64_t)fsi.EndOfFile.QuadPart != 0) {
                throw formatted_error("EndOfFile was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 0);
            }
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\iodir", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                        FILE_CREATED);
    });

    if (h) {
        test("Try setting end of file", [&]() {
            exp_status([&]() {
                set_end_of_file(h.get(), 0);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Try setting allocation", [&]() {
            exp_status([&]() {
                set_allocation(h.get(), 0);
            }, STATUS_INVALID_PARAMETER);
        });

        h.reset();
    }

    test("Create preallocated file", [&]() {
        h = create_file(dir + u"\\ioprealloc", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                        FILE_CREATED, 4096);
    });

    if (h) {
        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if ((uint64_t)fsi.AllocationSize.QuadPart != 4096) {
                throw formatted_error("AllocationSize was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 4096);
            }

            if ((uint64_t)fsi.EndOfFile.QuadPart != 0) {
                throw formatted_error("EndOfFile was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 0);
            }
        });

        auto random = random_data(4096);

        test("Write data", [&]() {
            write_file(h.get(), random);
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if ((uint64_t)fsi.AllocationSize.QuadPart != 4096) {
                throw formatted_error("AllocationSize was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 4096);
            }

            if ((uint64_t)fsi.EndOfFile.QuadPart != 4096) {
                throw formatted_error("EndOfFile was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 4096);
            }
        });

        test("Set allocation to 0", [&]() {
            set_allocation(h.get(), 0);
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if ((uint64_t)fsi.AllocationSize.QuadPart != 0) {
                throw formatted_error("AllocationSize was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 0);
            }

            if ((uint64_t)fsi.EndOfFile.QuadPart != 0) {
                throw formatted_error("EndOfFile was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 0);
            }
        });

        h.reset();
    }

    test("Create preallocated directory", [&]() {
        h = create_file(dir + u"\\iopreallocdir", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                        FILE_CREATED, 4096);
    });

    if (h) {
        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if ((uint64_t)fsi.AllocationSize.QuadPart != 0) {
                throw formatted_error("AllocationSize was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 0);
            }

            if ((uint64_t)fsi.EndOfFile.QuadPart != 0) {
                throw formatted_error("EndOfFile was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 0);
            }
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\io3", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                        FILE_CREATED);
    });

    if (h) {
        vector<uint8_t> data = {'a','b','c','d','e','f'};

        test("Write to file", [&]() {
            write_file(h.get(), data);
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != data.size()) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, data.size());
            }
        });

        test("Read from file specifying offset", [&]() {
            auto buf = read_file(h.get(), 2, 0);

            if (buf.size() != 2)
                throw formatted_error("Read {} bytes, expected {}", buf.size(), 2);

            if (buf[0] != data[0] || buf[1] != data[1])
                throw runtime_error("Data read did not match data written");
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 2) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 2);
            }
        });

        test("Read from file specifying offset as FILE_USE_FILE_POINTER_POSITION", [&]() {
            LARGE_INTEGER li;

            li.HighPart = -1;
            li.LowPart = FILE_USE_FILE_POINTER_POSITION;

            auto buf = read_file(h.get(), 2, li.QuadPart);

            if (buf.size() != 2)
                throw formatted_error("Read {} bytes, expected {}", buf.size(), 2);

            if (buf[0] != data[2] || buf[1] != data[3])
                throw runtime_error("Data read did not match data written");
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 4) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 4);
            }
        });

        vector<uint8_t> data2 = {'g','h'};

        test("Write to file specifying offset as FILE_USE_FILE_POINTER_POSITION", [&]() {
            LARGE_INTEGER li;

            li.HighPart = -1;
            li.LowPart = FILE_USE_FILE_POINTER_POSITION;

            write_file(h.get(), data2, li.QuadPart);
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 6) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 6);
            }
        });

        test("Set position to 0", [&]() {
            set_position(h.get(), 0);
        });

        vector<uint8_t> data3 = {'i','j'};

        test("Write to file specifying offset as FILE_WRITE_TO_END_OF_FILE", [&]() {
            LARGE_INTEGER li;

            li.HighPart = -1;
            li.LowPart = FILE_WRITE_TO_END_OF_FILE;

            write_file(h.get(), data3, li.QuadPart);
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 8) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 8);
            }
        });

        test("Try reading from file specifying offset as FILE_WRITE_TO_END_OF_FILE", [&]() {
            LARGE_INTEGER li;

            li.HighPart = -1;
            li.LowPart = FILE_WRITE_TO_END_OF_FILE;

            exp_status([&]() {
                read_file(h.get(), 2, li.QuadPart);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Set position to 0", [&]() {
            set_position(h.get(), 0);
        });

        test("Check file contents", [&]() {
            auto buf = read_file(h.get(), 8);

            if (buf.size() != 8)
                throw formatted_error("Read {} bytes, expected {}", buf.size(), 8);

            if (buf[0] != data[0] || buf[1] != data[1] || buf[2] != data[2] || buf[3] != data[3] ||
                buf[4] != data2[0] || buf[5] != data2[1] || buf[6] != data3[0] || buf[7] != data3[1]) {
                throw runtime_error("Data read did not match data written");
            }
        });
    }

    test("Create file without file pointer", [&]() {
        h = create_file(dir + u"\\io4", FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        vector<uint8_t> data = {'a','b','c','d','e','f'};

        test("Try writing to file with no offset specified", [&]() {
            exp_status([&]() {
                write_file_wait(h.get(), data);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Write to file at 0", [&]() {
            write_file_wait(h.get(), data, 0);
        });

        test("Check position hasn't moved", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 0) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 0);
            }
        });

        test("Set position", [&]() {
            set_position(h.get(), data.size());
        });

        test("Check position has now moved", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != data.size()) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, data.size());
            }
        });

        test("Read from file specifying offset", [&]() {
            auto buf = read_file_wait(h.get(), 2, 0);

            if (buf.size() != 2)
                throw formatted_error("Read {} bytes, expected {}", buf.size(), 2);

            if (buf[0] != data[0] || buf[1] != data[1])
                throw runtime_error("Data read did not match data written");
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != data.size()) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, data.size());
            }
        });

        test("Read from file specifying offset as FILE_USE_FILE_POINTER_POSITION", [&]() {
            LARGE_INTEGER li;

            li.HighPart = -1;
            li.LowPart = FILE_USE_FILE_POINTER_POSITION;

            exp_status([&]() {
                read_file_wait(h.get(), 2, li.QuadPart);
            }, STATUS_INVALID_PARAMETER);
        });

        vector<uint8_t> data2 = {'g','h'};

        test("Write to file specifying offset as FILE_USE_FILE_POINTER_POSITION", [&]() {
            LARGE_INTEGER li;

            li.HighPart = -1;
            li.LowPart = FILE_USE_FILE_POINTER_POSITION;

            exp_status([&]() {
                write_file_wait(h.get(), data2, li.QuadPart);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Set position to 0", [&]() {
            set_position(h.get(), 0);
        });

        vector<uint8_t> data3 = {'i','j'};

        test("Write to file specifying offset as FILE_WRITE_TO_END_OF_FILE", [&]() {
            LARGE_INTEGER li;

            li.HighPart = -1;
            li.LowPart = FILE_WRITE_TO_END_OF_FILE;

            write_file_wait(h.get(), data3, li.QuadPart);
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 0) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 0);
            }
        });

        test("Try reading from file specifying offset as FILE_WRITE_TO_END_OF_FILE", [&]() {
            LARGE_INTEGER li;

            li.HighPart = -1;
            li.LowPart = FILE_WRITE_TO_END_OF_FILE;

            exp_status([&]() {
                read_file_wait(h.get(), 2, li.QuadPart);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Check file contents", [&]() {
            auto buf = read_file_wait(h.get(), 8, 0);

            if (buf.size() != 8)
                throw formatted_error("Read {} bytes, expected {}", buf.size(), 8);

            if (buf[0] != data[0] || buf[1] != data[1] || buf[2] != data[2] || buf[3] != data[3] ||
                buf[4] != data[4] || buf[5] != data[5] || buf[6] != data3[0] || buf[7] != data3[1]) {
                throw runtime_error("Data read did not match data written");
            }
        });
    }

    test("Create file for FILE_APPEND_DATA", [&]() {
        h = create_file(dir + u"\\io5", SYNCHRONIZE | FILE_READ_DATA | FILE_APPEND_DATA, 0, 0,
                        FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                        FILE_CREATED);
    });

    if (h) {
        vector<uint8_t> data = {'a','b','c','d','e','f'};

        test("Write to file", [&]() {
            write_file(h.get(), data);
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != data.size()) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, data.size());
            }
        });

        test("Read from file specifying offset", [&]() {
            auto buf = read_file(h.get(), 2, 0);

            if (buf.size() != 2)
                throw formatted_error("Read {} bytes, expected {}", buf.size(), 2);

            if (buf[0] != data[0] || buf[1] != data[1])
                throw runtime_error("Data read did not match data written");
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 2) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 2);
            }
        });

        test("Read from file specifying offset as FILE_USE_FILE_POINTER_POSITION", [&]() {
            LARGE_INTEGER li;

            li.HighPart = -1;
            li.LowPart = FILE_USE_FILE_POINTER_POSITION;

            auto buf = read_file(h.get(), 2, li.QuadPart);

            if (buf.size() != 2)
                throw formatted_error("Read {} bytes, expected {}", buf.size(), 2);

            if (buf[0] != data[2] || buf[1] != data[3])
                throw runtime_error("Data read did not match data written");
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 4) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 4);
            }
        });

        vector<uint8_t> data2 = {'g','h'};

        test("Write to file specifying offset as FILE_USE_FILE_POINTER_POSITION", [&]() {
            LARGE_INTEGER li;

            li.HighPart = -1;
            li.LowPart = FILE_USE_FILE_POINTER_POSITION;

            write_file(h.get(), data2, li.QuadPart);
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 8) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 8);
            }
        });

        test("Set position to 0", [&]() {
            set_position(h.get(), 0);
        });

        vector<uint8_t> data3 = {'i','j'};

        test("Write to file specifying offset as 0", [&]() {
            write_file(h.get(), data3, 0);
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 10) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 10);
            }
        });

        test("Write to file specifying offset as FILE_WRITE_TO_END_OF_FILE", [&]() {
            LARGE_INTEGER li;

            li.HighPart = -1;
            li.LowPart = FILE_WRITE_TO_END_OF_FILE;

            write_file(h.get(), data3, li.QuadPart);
        });

        test("Check position", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if ((uint64_t)fpi.CurrentByteOffset.QuadPart != 12) {
                throw formatted_error("CurrentByteOffset was {}, expected {}",
                                      fpi.CurrentByteOffset.QuadPart, 12);
            }
        });

        test("Try reading from file specifying offset as FILE_WRITE_TO_END_OF_FILE", [&]() {
            LARGE_INTEGER li;

            li.HighPart = -1;
            li.LowPart = FILE_WRITE_TO_END_OF_FILE;

            exp_status([&]() {
                read_file(h.get(), 2, li.QuadPart);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Set position to 0", [&]() {
            set_position(h.get(), 0);
        });

        test("Check file contents", [&]() {
            auto buf = read_file(h.get(), 12);

            if (buf.size() != 12)
                throw formatted_error("Read {} bytes, expected {}", buf.size(), 12);

            if (buf[0] != data[0] || buf[1] != data[1] || buf[2] != data[2] || buf[3] != data[3] ||
                buf[4] != data[4] || buf[5] != data[5] || buf[6] != data2[0] || buf[7] != data2[1] ||
                buf[8] != data3[0] || buf[9] != data3[1] || buf[10] != data3[0] || buf[11] != data3[1]) {
                throw runtime_error("Data read did not match data written");
            }
        });
    }

    test("Add SeManageVolumePrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_MANAGE_VOLUME_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Create file with FILE_NO_INTERMEDIATE_BUFFERING", [&]() {
        h = create_file(dir + u"\\io6", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING,
                        FILE_CREATED);
    });

    if (h) {
        write_check(4096, true);

        auto random = random_data(100);

        test("Try writing less than sector", [&]() {
            exp_status([&]() {
                write_file(h.get(), random);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Try setting position to odd value", [&]() {
            exp_status([&]() {
                set_position(h.get(), 100);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Set position to 0", [&]() {
            set_position(h.get(), 0);
        });

        test("Try reading less than sector", [&]() {
            exp_status([&]() {
                read_file(h.get(), 100);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Set length to odd value", [&]() {
            set_end_of_file(h.get(), 100);
        });

        test("Set length to sector", [&]() {
            set_end_of_file(h.get(), 4096);
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if ((uint64_t)fsi.EndOfFile.QuadPart != 4096) {
                throw formatted_error("EndOfFile was {}, expected {}",
                                      fsi.EndOfFile.QuadPart, 4096);
            }
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\io7", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                        FILE_CREATED);
    });

    if (h) {
        auto random = random_data(150);

        test("Write file", [&]() {
            write_file(h.get(), random);
        });

        test("Set zero data", [&]() {
            set_zero_data(h.get(), 25, 125);
        });

        test("Read file", [&]() {
            auto ret = read_file(h.get(), random.size(), 0);
            auto exp = random;

            memset(exp.data() + 25, 0, 100);

            if (memcmp(ret.data(), exp.data(), exp.size()))
                throw runtime_error("Data read did not match data written");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\io8", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0,
                        FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                        FILE_CREATED);
    });

    if (h) {
        auto random = random_data(4096 * 3);

        test("Write file", [&]() {
            write_file(h.get(), random);
        });

        test("Set zero data", [&]() {
            set_zero_data(h.get(), 4096, 4096 * 2);
        });

        test("Read file", [&]() {
            auto ret = read_file(h.get(), random.size(), 0);
            auto exp = random;

            memset(exp.data() + 4096, 0, 4096);

            if (memcmp(ret.data(), exp.data(), exp.size()))
                throw runtime_error("Data read did not match data written");
        });

        h.reset();
    }

    // FIXME - DASD I/O
}
