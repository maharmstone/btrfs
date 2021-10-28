#include "test.h"

using namespace std;

void test_supersede(const u16string& dir) {
    unique_handle h;

    test("Create file by FILE_SUPERSEDE", [&]() {
        h = create_file(dir + u"\\supersede", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_READONLY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_SUPERSEDE, 0, FILE_CREATED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE)) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE",
                                      fbi.FileAttributes);
            }
        });

        test("Try superseding open file", [&]() {
            create_file(dir + u"\\supersede", MAXIMUM_ALLOWED, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_SUPERSEDE, 0, FILE_SUPERSEDED);
        });

        h.reset();
    }

    test("Supersede file", [&]() {
        h = create_file(dir + u"\\supersede", MAXIMUM_ALLOWED, 0, 0, FILE_SUPERSEDE,
                        0, FILE_SUPERSEDED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_ARCHIVE) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_ARCHIVE",
                                      fbi.FileAttributes);
            }
        });

        h.reset();
    }

    test("Supersede adding hidden flag", [&]() {
        create_file(dir + u"\\supersede", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_HIDDEN, 0,
                    FILE_SUPERSEDE, 0, FILE_SUPERSEDED);
    });

    test("Try superseding while clearing hidden flag", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\supersede", MAXIMUM_ALLOWED, 0, 0, FILE_SUPERSEDE,
                        0, FILE_SUPERSEDED);
        }, STATUS_ACCESS_DENIED);
    });

    test("Supersede adding system flag", [&]() {
        create_file(dir + u"\\supersede", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, 0,
                    FILE_SUPERSEDE, 0, FILE_SUPERSEDED);
    });

    test("Try superseding while clearing system flag", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\supersede", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_HIDDEN, 0,
                        FILE_SUPERSEDE, 0, FILE_SUPERSEDED);
        }, STATUS_ACCESS_DENIED);
    });

    test("Try creating directory by FILE_SUPERSEDE", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\supersededir", MAXIMUM_ALLOWED, 0, 0, FILE_SUPERSEDE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
        }, STATUS_INVALID_PARAMETER);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\supersede2", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        h.reset();

        test("Supersede file with different case", [&]() {
            h = create_file(dir + u"\\SUPERSEDE2", MAXIMUM_ALLOWED, 0, 0, FILE_SUPERSEDE,
                            0, FILE_SUPERSEDED);
        });

        if (h) {
            test("Check name", [&]() {
                auto fn = query_file_name_information(h.get());

                static const u16string_view ends_with = u"\\supersede2";

                if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                    throw runtime_error("Name did not end with \"\\supersede2\".");
            });
        }
    }
}
