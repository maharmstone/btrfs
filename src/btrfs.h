/* btrfs.h
 * Generic btrfs header file. Thanks to whoever it was who wrote
 * https://btrfs.wiki.kernel.org/index.php/On-disk_Format - you saved me a lot of time!
 *
 * I release this file, and this file only, into the public domain - do whatever
 * you want with it. You don't have to, but I'd appreciate if you let me know if you
 * use it anything cool - mark@harmstone.com. */

#pragma once

#include <stdint.h>
#include <assert.h>

static const uint64_t superblock_addrs[] = { 0x10000, 0x4000000, 0x4000000000, 0 };

#define BTRFS_MAGIC         0x4d5f53665248425f
#define BTRFS_LABEL_SIZE    0x100
#define BTRFS_FIRST_FREE_OBJECTID   0x100
#define BTRFS_LAST_FREE_OBJECTID    0xffffffffffffff00

#define BTRFS_INODE_ITEM_KEY            0x01
#define BTRFS_INODE_REF_KEY             0x0C
#define BTRFS_INODE_EXTREF_KEY          0x0D
#define BTRFS_XATTR_ITEM_KEY            0x18
#define BTRFS_ORPHAN_ITEM_KEY           0x30
#define BTRFS_DIR_ITEM_KEY              0x54
#define BTRFS_DIR_INDEX_KEY             0x60
#define BTRFS_EXTENT_DATA_KEY           0x6C
#define BTRFS_EXTENT_CSUM_KEY           0x80
#define BTRFS_ROOT_ITEM_KEY             0x84
#define BTRFS_ROOT_BACKREF_KEY          0x90
#define BTRFS_ROOT_REF_KEY              0x9C
#define BTRFS_EXTENT_ITEM_KEY           0xA8
#define BTRFS_METADATA_ITEM_KEY         0xA9
#define BTRFS_TREE_BLOCK_REF_KEY        0xB0
#define BTRFS_EXTENT_DATA_REF_KEY       0xB2
#define BTRFS_SHARED_BLOCK_REF_KEY      0xB6
#define BTRFS_SHARED_DATA_REF_KEY       0xB8
#define BTRFS_BLOCK_GROUP_ITEM_KEY      0xC0
#define BTRFS_FREE_SPACE_INFO_KEY       0xC6
#define BTRFS_FREE_SPACE_EXTENT_KEY     0xC7
#define BTRFS_FREE_SPACE_BITMAP_KEY     0xC8
#define BTRFS_DEV_EXTENT_KEY            0xCC
#define BTRFS_DEV_ITEM_KEY              0xD8
#define BTRFS_CHUNK_ITEM_KEY            0xE4
#define BTRFS_TEMPORARY_ITEM_KEY        0xF8
#define BTRFS_PERSISTENT_ITEM_KEY       0xF9
#define BTRFS_UUID_KEY_SUBVOL           0xFB
#define BTRFS_UUID_KEY_RECEIVED_SUBVOL  0xFC

#define BTRFS_ROOT_TREE_OBJECTID         1
#define BTRFS_EXTENT_TREE_OBJECTID       2
#define BTRFS_CHUNK_TREE_OBJECTID        3
#define BTRFS_DEV_TREE_OBJECTID          4
#define BTRFS_FS_TREE_OBJECTID           5
#define BTRFS_ROOT_TREE_DIR_OBJECTID     6
#define BTRFS_CSUM_TREE_OBJECTID         7
#define BTRFS_UUID_TREE_OBJECTID         9
#define BTRFS_FREE_SPACE_TREE_OBJECTID   0xa
#define BTRFS_BLOCK_GROUP_TREE_OBJECTID  0xb
#define BTRFS_RAID_STRIPE_TREE_OBJECTID  0xc
#define BTRFS_FREE_SPACE_OBJECTID        0xFFFFFFFFFFFFFFF5
#define BTRFS_EXTENT_CSUM_OBJECTID       0xFFFFFFFFFFFFFFF6
#define BTRFS_DATA_RELOC_TREE_OBJECTID   0xFFFFFFFFFFFFFFF7
#define BTRFS_ORPHAN_OBJECTID            0xFFFFFFFFFFFFFFFB
#define BTRFS_BALANCE_OBJECTID           0xFFFFFFFFFFFFFFFC

#define BTRFS_COMPRESS_NONE  0
#define BTRFS_COMPRESS_ZLIB  1
#define BTRFS_COMPRESS_LZO   2
#define BTRFS_COMPRESS_ZSTD  3

#define BTRFS_FILE_EXTENT_INLINE      0
#define BTRFS_FILE_EXTENT_REG         1
#define BTRFS_FILE_EXTENT_PREALLOC    2

#define BTRFS_BLOCK_GROUP_DATA         0x001
#define BTRFS_BLOCK_GROUP_SYSTEM       0x002
#define BTRFS_BLOCK_GROUP_METADATA     0x004
#define BTRFS_BLOCK_GROUP_RAID0        0x008
#define BTRFS_BLOCK_GROUP_RAID1        0x010
#define BTRFS_BLOCK_GROUP_DUP          0x020
#define BTRFS_BLOCK_GROUP_RAID10       0x040
#define BTRFS_BLOCK_GROUP_RAID5        0x080
#define BTRFS_BLOCK_GROUP_RAID6        0x100
#define BTRFS_BLOCK_GROUP_RAID1C3      0x200
#define BTRFS_BLOCK_GROUP_RAID1C4      0x400

#define BTRFS_INODE_NODATASUM   0x001
#define BTRFS_INODE_NODATACOW   0x002
#define BTRFS_INODE_READONLY    0x004
#define BTRFS_INODE_NOCOMPRESS  0x008
#define BTRFS_INODE_PREALLOC    0x010
#define BTRFS_INODE_SYNC        0x020
#define BTRFS_INODE_IMMUTABLE   0x040
#define BTRFS_INODE_APPEND      0x080
#define BTRFS_INODE_NODUMP      0x100
#define BTRFS_INODE_NOATIME     0x200
#define BTRFS_INODE_DIRSYNC     0x400
#define BTRFS_INODE_COMPRESS    0x800

#define BTRFS_INODE_RO_VERITY   0x1

#define BTRFS_INODE_ROOT_ITEM_INIT (1U << 31)

#define BTRFS_ROOT_SUBVOL_RDONLY   0x1

#define BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE           0x1
#define BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE_VALID     0x2
#define BTRFS_FEATURE_COMPAT_RO_VERITY                    0x4
#define BTRFS_FEATURE_COMPAT_RO_BLOCK_GROUP_TREE          0x8

#define BTRFS_FEATURE_INCOMPAT_MIXED_BACKREF      0x0001
#define BTRFS_FEATURE_INCOMPAT_DEFAULT_SUBVOL     0x0002
#define BTRFS_FEATURE_INCOMPAT_MIXED_GROUPS       0x0004
#define BTRFS_FEATURE_INCOMPAT_COMPRESS_LZO       0x0008
#define BTRFS_FEATURE_INCOMPAT_COMPRESS_ZSTD      0x0010
#define BTRFS_FEATURE_INCOMPAT_BIG_METADATA       0x0020
#define BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF      0x0040
#define BTRFS_FEATURE_INCOMPAT_RAID56             0x0080
#define BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA    0x0100
#define BTRFS_FEATURE_INCOMPAT_NO_HOLES           0x0200
#define BTRFS_FEATURE_INCOMPAT_METADATA_UUID      0x0400
#define BTRFS_FEATURE_INCOMPAT_RAID1C34           0x0800
#define BTRFS_FEATURE_INCOMPAT_ZONED              0x1000
#define BTRFS_FEATURE_INCOMPAT_EXTENT_TREE_V2     0x2000
#define BTRFS_FEATURE_INCOMPAT_RAID_STRIPE_TREE   0x4000
#define BTRFS_FEATURE_INCOMPAT_SIMPLE_QUOTA       0x10000

#define BTRFS_SUPER_FLAG_SEEDING   0x100000000

#define BTRFS_CSUM_TYPE_CRC32         0
#define BTRFS_CSUM_TYPE_XXHASH        1
#define BTRFS_CSUM_TYPE_SHA256        2
#define BTRFS_CSUM_TYPE_BLAKE2        3

#define BTRFS_UUID_SIZE 16

#define BTRFS_FREE_SPACE_BITMAP_SIZE 256

#pragma pack(push, 1)

struct btrfs_key {
    uint64_t objectid;
    uint8_t type;
    uint64_t offset;
};

#define BTRFS_HEADER_FLAG_WRITTEN         0x000000000000001
#define BTRFS_HEADER_FLAG_RELOC           0x000000000000002

#define BTRFS_MIXED_BACKREF_REV           ((uint64_t)1)
#define BTRFS_BACKREF_REV_SHIFT           56
#define BTRFS_BACKREF_REV_MASK            0xff00000000000000

struct btrfs_header {
    uint8_t csum[32];
    uint8_t fsid[BTRFS_UUID_SIZE];
    uint64_t bytenr;
    uint64_t flags;
    uint8_t chunk_tree_uuid[BTRFS_UUID_SIZE];
    uint64_t generation;
    uint64_t owner;
    uint32_t nritems;
    uint8_t level;
};

struct btrfs_item {
    struct btrfs_key key;
    uint32_t offset;
    uint32_t size;
};

struct btrfs_key_ptr {
    struct btrfs_key key;
    uint64_t blockptr;
    uint64_t generation;
};

struct btrfs_dev_item {
    uint64_t devid;
    uint64_t total_bytes;
    uint64_t bytes_used;
    uint32_t io_align;
    uint32_t io_width;
    uint32_t sector_size;
    uint64_t type;
    uint64_t generation;
    uint64_t start_offset;
    uint32_t dev_group;
    uint8_t seek_speed;
    uint8_t bandwidth;
    uint8_t uuid[BTRFS_UUID_SIZE];
    uint8_t fsid[BTRFS_UUID_SIZE];
};

#define BTRFS_SYSTEM_CHUNK_ARRAY_SIZE 0x800
#define BTRFS_NUM_BACKUP_ROOTS 4

struct btrfs_root_backup {
    uint64_t tree_root;
    uint64_t tree_root_gen;
    uint64_t chunk_root;
    uint64_t chunk_root_gen;
    uint64_t extent_root;
    uint64_t extent_root_gen;
    uint64_t fs_root;
    uint64_t fs_root_gen;
    uint64_t dev_root;
    uint64_t dev_root_gen;
    uint64_t csum_root;
    uint64_t csum_root_gen;
    uint64_t total_bytes;
    uint64_t bytes_used;
    uint64_t num_devices;
    uint64_t unused_64[4];
    uint8_t tree_root_level;
    uint8_t chunk_root_level;
    uint8_t extent_root_level;
    uint8_t fs_root_level;
    uint8_t dev_root_level;
    uint8_t csum_root_level;
    uint8_t unused_8[10];
};

struct btrfs_super_block {
    uint8_t csum[32];
    uint8_t fsid[BTRFS_UUID_SIZE];
    uint64_t bytenr;
    uint64_t flags;
    uint64_t magic;
    uint64_t generation;
    uint64_t root;
    uint64_t chunk_root;
    uint64_t log_root;
    uint64_t __unused_log_root_transid;
    uint64_t total_bytes;
    uint64_t bytes_used;
    uint64_t root_dir_objectid;
    uint64_t num_devices;
    uint32_t sectorsize;
    uint32_t nodesize;
    uint32_t __unused_leafsize;
    uint32_t stripesize;
    uint32_t sys_chunk_array_size;
    uint64_t chunk_root_generation;
    uint64_t compat_flags;
    uint64_t compat_ro_flags;
    uint64_t incompat_flags;
    uint16_t csum_type;
    uint8_t root_level;
    uint8_t chunk_root_level;
    uint8_t log_root_level;
    struct btrfs_dev_item dev_item;
    char label[BTRFS_LABEL_SIZE];
    uint64_t cache_generation;
    uint64_t uuid_tree_generation;
    uint8_t metadata_uuid[BTRFS_UUID_SIZE];
    uint64_t nr_global_roots;
    uint64_t remap_root;
    uint64_t remap_root_generation;
    uint8_t remap_root_level;
    uint8_t reserved[199];
    uint8_t sys_chunk_array[BTRFS_SYSTEM_CHUNK_ARRAY_SIZE];
    struct btrfs_root_backup super_roots[BTRFS_NUM_BACKUP_ROOTS];
    uint8_t padding[565];
};

#define BTRFS_FT_UNKNOWN    0
#define BTRFS_FT_REG_FILE   1
#define BTRFS_FT_DIR        2
#define BTRFS_FT_CHRDEV     3
#define BTRFS_FT_BLKDEV     4
#define BTRFS_FT_FIFO       5
#define BTRFS_FT_SOCK       6
#define BTRFS_FT_SYMLINK    7
#define BTRFS_FT_XATTR      8

struct btrfs_dir_item {
    struct btrfs_key location;
    uint64_t transid;
    uint16_t data_len;
    uint16_t name_len;
    uint8_t type;
};

struct btrfs_timespec {
    uint64_t sec;
    uint32_t nsec;
};

struct btrfs_inode_item {
    uint64_t generation;
    uint64_t transid;
    uint64_t size;
    uint64_t nbytes;
    uint64_t block_group;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint32_t mode;
    uint64_t rdev;
    uint64_t flags;
    uint64_t sequence;
    uint64_t reserved[4];
    struct btrfs_timespec atime;
    struct btrfs_timespec ctime;
    struct btrfs_timespec mtime;
    struct btrfs_timespec otime;
};

static_assert(sizeof(struct btrfs_inode_item) == 0xa0, "btrfs_inode_item has wrong size");

struct btrfs_root_item {
    struct btrfs_inode_item inode;
    uint64_t generation;
    uint64_t root_dirid;
    uint64_t bytenr;
    uint64_t byte_limit;
    uint64_t bytes_used;
    uint64_t last_snapshot;
    uint64_t flags;
    uint32_t refs;
    struct btrfs_key drop_progress;
    uint8_t drop_level;
    uint8_t level;
    uint64_t generation_v2;
    uint8_t uuid[BTRFS_UUID_SIZE];
    uint8_t parent_uuid[BTRFS_UUID_SIZE];
    uint8_t received_uuid[BTRFS_UUID_SIZE];
    uint64_t ctransid;
    uint64_t otransid;
    uint64_t stransid;
    uint64_t rtransid;
    struct btrfs_timespec ctime;
    struct btrfs_timespec otime;
    struct btrfs_timespec stime;
    struct btrfs_timespec rtime;
    uint64_t reserved[8];
};

struct btrfs_stripe {
    uint64_t devid;
    uint64_t offset;
    uint8_t dev_uuid[BTRFS_UUID_SIZE];
};

struct btrfs_chunk {
    uint64_t length;
    uint64_t owner;
    uint64_t stripe_len;
    uint64_t type;
    uint32_t io_align;
    uint32_t io_width;
    uint32_t sector_size;
    uint16_t num_stripes;
    uint16_t sub_stripes;
    struct btrfs_stripe stripe[1];
};

struct btrfs_file_extent_item {
    uint64_t generation;
    uint64_t ram_bytes;
    uint8_t compression;
    uint8_t encryption;
    uint16_t other_encoding;
    uint8_t type;
    uint64_t disk_bytenr;
    uint64_t disk_num_bytes;
    uint64_t offset;
    uint64_t num_bytes;
};

struct btrfs_inode_ref {
    uint64_t index;
    uint16_t name_len;
};

struct btrfs_inode_extref {
    uint64_t parent_objectid;
    uint64_t index;
    uint16_t name_len;
    uint8_t name[];
};

#define BTRFS_EXTENT_FLAG_DATA            0x001
#define BTRFS_EXTENT_FLAG_TREE_BLOCK      0x002
#define BTRFS_BLOCK_FLAG_FULL_BACKREF     0x100

struct btrfs_extent_item {
    uint64_t refs;
    uint64_t generation;
    uint64_t flags;
};

struct btrfs_tree_block_info {
    struct btrfs_key key;
    uint8_t level;
};

struct btrfs_extent_item_v0 {
    uint32_t refs;
};

struct btrfs_extent_inline_ref {
    uint8_t type;
    uint64_t offset;
};

struct btrfs_extent_data_ref {
    uint64_t root;
    uint64_t objectid;
    uint64_t offset;
    uint32_t count;
};

struct btrfs_block_group_item {
    uint64_t used;
    uint64_t chunk_objectid;
    uint64_t flags;
};

struct btrfs_shared_data_ref {
    uint32_t count;
};

#define BTRFS_FREE_SPACE_EXTENT 1
#define BTRFS_FREE_SPACE_BITMAP 2

struct btrfs_free_space_entry {
    uint64_t offset;
    uint64_t bytes;
    uint8_t type;
};

struct btrfs_free_space_header {
    struct btrfs_key location;
    uint64_t generation;
    uint64_t num_entries;
    uint64_t num_bitmaps;
};

struct btrfs_root_ref {
    uint64_t dirid;
    uint64_t sequence;
    uint16_t name_len;
};

struct btrfs_dev_extent {
    uint64_t chunk_tree;
    uint64_t chunk_objectid;
    uint64_t chunk_offset;
    uint64_t length;
    uint8_t chunk_tree_uuid[BTRFS_UUID_SIZE];
};

#define BTRFS_BALANCE_DATA          0x1
#define BTRFS_BALANCE_SYSTEM        0x2
#define BTRFS_BALANCE_METADATA      0x4

#define BTRFS_BALANCE_ARGS_PROFILES         0x001
#define BTRFS_BALANCE_ARGS_USAGE            0x002
#define BTRFS_BALANCE_ARGS_DEVID            0x004
#define BTRFS_BALANCE_ARGS_DRANGE           0x008
#define BTRFS_BALANCE_ARGS_VRANGE           0x010
#define BTRFS_BALANCE_ARGS_LIMIT            0x020
#define BTRFS_BALANCE_ARGS_LIMIT_RANGE      0x040
#define BTRFS_BALANCE_ARGS_STRIPES_RANGE    0x080
#define BTRFS_BALANCE_ARGS_CONVERT          0x100
#define BTRFS_BALANCE_ARGS_SOFT             0x200
#define BTRFS_BALANCE_ARGS_USAGE_RANGE      0x400

struct btrfs_disk_balance_args {
    uint64_t profiles;

    union {
        uint64_t usage;
        struct {
            uint32_t usage_min;
            uint32_t usage_max;
        };
    };

    uint64_t devid;
    uint64_t pstart;
    uint64_t pend;
    uint64_t vstart;
    uint64_t vend;
    uint64_t target;
    uint64_t flags;

    union {
        uint64_t limit;
        struct {
            uint32_t limit_min;
            uint32_t limit_max;
        };
    };

    uint32_t stripes_min;
    uint32_t stripes_max;
    uint64_t unused[6];
};

struct btrfs_balance_item {
    uint64_t flags;
    struct btrfs_disk_balance_args data;
    struct btrfs_disk_balance_args meta;
    struct btrfs_disk_balance_args sys;
    uint64_t unused[4];
};

#define BTRFS_FREE_SPACE_USING_BITMAPS      1

struct btrfs_free_space_info {
    uint32_t extent_count;
    uint32_t flags;
};

#define BTRFS_DEV_STAT_WRITE_ERRS          0
#define BTRFS_DEV_STAT_READ_ERRS           1
#define BTRFS_DEV_STAT_FLUSH_ERRS          2
#define BTRFS_DEV_STAT_CORRUPTION_ERRS     3
#define BTRFS_DEV_STAT_GENERATION_ERRS     4

#define BTRFS_SEND_C_SUBVOL          1
#define BTRFS_SEND_C_SNAPSHOT        2
#define BTRFS_SEND_C_MKFILE          3
#define BTRFS_SEND_C_MKDIR           4
#define BTRFS_SEND_C_MKNOD           5
#define BTRFS_SEND_C_MKFIFO          6
#define BTRFS_SEND_C_MKSOCK          7
#define BTRFS_SEND_C_SYMLINK         8
#define BTRFS_SEND_C_RENAME          9
#define BTRFS_SEND_C_LINK           10
#define BTRFS_SEND_C_UNLINK         11
#define BTRFS_SEND_C_RMDIR          12
#define BTRFS_SEND_C_SET_XATTR      13
#define BTRFS_SEND_C_REMOVE_XATTR   14
#define BTRFS_SEND_C_WRITE          15
#define BTRFS_SEND_C_CLONE          16
#define BTRFS_SEND_C_TRUNCATE       17
#define BTRFS_SEND_C_CHMOD          18
#define BTRFS_SEND_C_CHOWN          19
#define BTRFS_SEND_C_UTIMES         20
#define BTRFS_SEND_C_END            21
#define BTRFS_SEND_C_UPDATE_EXTENT  22

#define BTRFS_SEND_A_UUID             1
#define BTRFS_SEND_A_CTRANSID         2
#define BTRFS_SEND_A_INO              3
#define BTRFS_SEND_A_SIZE             4
#define BTRFS_SEND_A_MODE             5
#define BTRFS_SEND_A_UID              6
#define BTRFS_SEND_A_GID              7
#define BTRFS_SEND_A_RDEV             8
#define BTRFS_SEND_A_CTIME            9
#define BTRFS_SEND_A_MTIME           10
#define BTRFS_SEND_A_ATIME           11
#define BTRFS_SEND_A_OTIME           12
#define BTRFS_SEND_A_XATTR_NAME      13
#define BTRFS_SEND_A_XATTR_DATA      14
#define BTRFS_SEND_A_PATH            15
#define BTRFS_SEND_A_PATH_TO         16
#define BTRFS_SEND_A_PATH_LINK       17
#define BTRFS_SEND_A_FILE_OFFSET     18
#define BTRFS_SEND_A_DATA            19
#define BTRFS_SEND_A_CLONE_UUID      20
#define BTRFS_SEND_A_CLONE_CTRANSID  21
#define BTRFS_SEND_A_CLONE_PATH      22
#define BTRFS_SEND_A_CLONE_OFFSET    23
#define BTRFS_SEND_A_CLONE_LEN       24

#define BTRFS_SEND_STREAM_MAGIC "btrfs-stream"

struct btrfs_stream_header {
    uint8_t magic[sizeof(BTRFS_SEND_STREAM_MAGIC)];
    uint32_t version;
};

struct btrfs_cmd_header {
    uint32_t len;
    uint16_t cmd;
    uint32_t crc;
};

struct btrfs_tlv_header {
    uint16_t tlv_type;
    uint16_t tlv_len;
};

#pragma pack(pop)
