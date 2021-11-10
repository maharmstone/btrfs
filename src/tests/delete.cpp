#include "test.h"

using namespace std;

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

void test_delete(const u16string& dir) {
    unique_handle h, h2;

    test("Create file", [&]() {
        h = create_file(dir + u"\\deletefile1", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Check directory entry", [&]() {
            u16string_view name = u"deletefile1";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Set disposition", [&]() {
            set_disposition_information(h.get(), true);
        });

        test("Check directory entry still there", [&]() {
            u16string_view name = u"deletefile1";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check standard information again", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        h.reset();

        test("Check directory entry gone after close", [&]() {
            u16string_view name = u"deletefile1";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\deletedir2", DELETE, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Check directory entry", [&]() {
            u16string_view name = u"deletedir2";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Set disposition", [&]() {
            set_disposition_information(h.get(), true);
        });

        test("Check directory entry still there", [&]() {
            u16string_view name = u"deletedir2";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check standard information again", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        h.reset();

        test("Check directory entry gone after close", [&]() {
            u16string_view name = u"deletedir2";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\deletedir3", DELETE, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create file", [&]() {
        h2 = create_file(dir + u"\\deletedir3\\file", DELETE, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h && h2) {
        test("Try to set disposition on directory", [&]() {
            exp_status([&]() {
                set_disposition_information(h.get(), true);
            }, STATUS_DIRECTORY_NOT_EMPTY);
        });

        test("Set disposition on file", [&]() {
            set_disposition_information(h2.get(), true);
        });

        test("Try to set disposition on directory again", [&]() {
            exp_status([&]() {
                set_disposition_information(h.get(), true);
            }, STATUS_DIRECTORY_NOT_EMPTY);
        });

        h2.reset();

        test("Set disposition on directory now empty", [&]() {
            set_disposition_information(h.get(), true);
        });

        h.reset();

        test("Check directory entry gone after close", [&]() {
            u16string_view name = u"deletedir3";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    // FIXME - deletion (opening doomed file, commuting sentence)
    // FIXME - permissions
    // FIXME - what happens if ADS still open?
    // FIXME - FILE_SHARE_DELETE
    // FIXME - POSIX deletion
    // FIXME - FILE_DELETE_ON_CLOSE
    // FIXME - FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK
    // FIXME - FILE_DISPOSITION_ON_CLOSE
    // FIXME - FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE
}
