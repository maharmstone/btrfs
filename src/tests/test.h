/* Copyright (c) Mark Harmstone 2021
 *
 * This file is part of WinBtrfs.
 *
 * WinBtrfs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public Licence as published by
 * the Free Software Foundation, either version 3 of the Licence, or
 * (at your option) any later version.
 *
 * WinBtrfs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public Licence for more details.
 *
 * You should have received a copy of the GNU Lesser General Public Licence
 * along with WinBtrfs.  If not, see <http://www.gnu.org/licenses/>. */

#pragma once

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
#include <optional>
#include <span>
#include <vector>
#include <functional>

#if __has_include(<format>)
#include <format>
#else
#include <fmt/format.h>
#include <fmt/compile.h>
#endif

enum class fs_type {
    unknown,
    ntfs,
    btrfs
};

extern "C"
NTSTATUS __stdcall NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                                        PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
                                        PVOID FileInformation, ULONG Length,
                                        FILE_INFORMATION_CLASS FileInformationClass,
                                        BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName,
                                        BOOLEAN RestartScan);

extern "C"
NTSTATUS __stdcall NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                              PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                              ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

extern "C"
NTSTATUS __stdcall NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                               PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                               ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

extern "C"
NTSTATUS __stdcall NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                      PHANDLE TokenHandle);

extern "C"
NTSTATUS __stdcall NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
                                           PTOKEN_PRIVILEGES NewState, ULONG BufferLength,
                                           PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength);

typedef enum _EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

extern "C"
NTSTATUS __stdcall NtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                                 POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType,
                                 BOOLEAN InitialState);

extern "C"
NTSTATUS __stdcall NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
                                   POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
                                   ULONG SectionPageProtection, ULONG AllocationAttributes,
                                   HANDLE FileHandle);

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap
} SECTION_INHERIT;

extern "C"
NTSTATUS __stdcall NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
                                      ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
                                      PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition,
                                      ULONG AllocationType, ULONG Protect);

extern "C"
NTSTATUS __stdcall NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);

extern "C"
NTSTATUS __stdcall NtLockFile(HANDLE FileHandle, HANDLE Event OPTIONAL, PIO_APC_ROUTINE ApcRoutine,
                              PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
                              PLARGE_INTEGER Length, ULONG Key, BOOLEAN FailImmediately,
                              BOOLEAN ExclusiveLock);

extern "C"
NTSTATUS __stdcall NtUnlockFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
                                PLARGE_INTEGER Length, ULONG Key);

extern "C"
NTSTATUS __stdcall NtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
                                         PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length,
                                         PULONG LengthNeeded);

extern "C"
NTSTATUS __stdcall NtSetSecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
                                       PSECURITY_DESCRIPTOR SecurityDescriptor);

typedef enum _EVENT_INFORMATION_CLASS {
    EventBasicInformation
} EVENT_INFORMATION_CLASS, *PEVENT_INFORMATION_CLASS;

typedef struct _EVENT_BASIC_INFORMATION {
    EVENT_TYPE EventType;
    LONG EventState;
} EVENT_BASIC_INFORMATION, *PEVENT_BASIC_INFORMATION;

extern "C"
NTSTATUS __stdcall NtQueryEvent(HANDLE EventHandle, EVENT_INFORMATION_CLASS EventInformationClass,
                                PVOID EventInformation, ULONG EventInformationLength,
                                PULONG ReturnLength);

extern "C"
NTSTATUS __stdcall NtQueryEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                 ULONG Length, BOOLEAN ReturnSingleEntry, PVOID EaList,
                                 ULONG EaListLength, PULONG EaIndex, BOOLEAN RestartScan);

extern "C"
NTSTATUS __stdcall NtSetEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                               ULONG Length);

extern "C"
NTSTATUS __stdcall NtSetInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
                                         PVOID TokenInformation, ULONG TokenInformationLength);

extern "C"
NTSTATUS __stdcall NtDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess,
                                    POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly,
                                    TOKEN_TYPE TokenType, PHANDLE NewTokenHandle);

extern "C"
NTSTATUS __stdcall NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                          PVOID ThreadInformation, ULONG ThreadInformationLength);

#define FILE_NEED_EA    0x00000080

typedef struct _FILE_GET_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR EaNameLength;
    CHAR EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

#define NtCurrentThread() ((HANDLE)(LONG_PTR) -2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR) -1)

#define FileIdInformation ((FILE_INFORMATION_CLASS)59)
#define FileIdExtdDirectoryInformation ((FILE_INFORMATION_CLASS)60)
#define FileIdExtdBothDirectoryInformation ((FILE_INFORMATION_CLASS)63)
#define FileDispositionInformationEx ((FILE_INFORMATION_CLASS)64)
#define FileRenameInformationEx ((FILE_INFORMATION_CLASS)65)
#define FileCaseSensitiveInformation ((FILE_INFORMATION_CLASS)71)
#define FileLinkInformationEx ((FILE_INFORMATION_CLASS)72)

#define FILE_WORD_ALIGNMENT 0x00000001

#define SE_SECURITY_PRIVILEGE               8
#define SE_RESTORE_PRIVILEGE                18
#define SE_CHANGE_NOTIFY_PRIVILEGE          23
#define SE_MANAGE_VOLUME_PRIVILEGE          28
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE   35

#define FILE_USE_FILE_POINTER_POSITION 0xfffffffe
#define FILE_WRITE_TO_END_OF_FILE 0xffffffff

#define FILE_RENAME_REPLACE_IF_EXISTS         0x00000001
#define FILE_RENAME_POSIX_SEMANTICS           0x00000002
#define FILE_RENAME_IGNORE_READONLY_ATTRIBUTE 0x00000040

#define FILE_LINK_REPLACE_IF_EXISTS           0x00000001
#define FILE_LINK_POSIX_SEMANTICS             0x00000002
#define FILE_LINK_IGNORE_READONLY_ATTRIBUTE   0x00000040

typedef struct _FILE_FS_DRIVER_PATH_INFORMATION {
    BOOLEAN DriverInPath;
    ULONG DriverNameLength;
    WCHAR DriverName[1];
} FILE_FS_DRIVER_PATH_INFORMATION, *PFILE_FS_DRIVER_PATH_INFORMATION;

// should be called FILE_RENAME_INFORMATION, version in mingw is outdated
typedef struct _FILE_RENAME_INFORMATION_EX {
    union {
        BOOLEAN ReplaceIfExists;
        ULONG Flags;
    };
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION_EX, *PFILE_RENAME_INFORMATION_EX;

// should be called FILE_RENAME_INFORMATION_EX, version in mingw is outdated
typedef struct _FILE_LINK_INFORMATION_EX {
    union {
        BOOLEAN ReplaceIfExists;
        ULONG Flags;
    };
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_INFORMATION_EX, *PFILE_LINK_INFORMATION_EX;

typedef struct _FILE_LINK_ENTRY_INFORMATION {
    ULONG NextEntryOffset;
    LONGLONG ParentFileId;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_ENTRY_INFORMATION, *PFILE_LINK_ENTRY_INFORMATION;

typedef struct _FILE_LINKS_INFORMATION {
    ULONG BytesNeeded;
    ULONG EntriesReturned;
    FILE_LINK_ENTRY_INFORMATION Entry;
} FILE_LINKS_INFORMATION, *PFILE_LINKS_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION_EX {
    ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX, *PFILE_DISPOSITION_INFORMATION_EX;

#define FILE_DISPOSITION_DO_NOT_DELETE              0x00000000
#define FILE_DISPOSITION_DELETE                     0x00000001
#define FILE_DISPOSITION_POSIX_SEMANTICS            0x00000002
#define FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK  0x00000004
#define FILE_DISPOSITION_ON_CLOSE                   0x00000008
#define FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE  0x00000010

typedef struct _FILE_ZERO_DATA_INFORMATION {
    LARGE_INTEGER FileOffset;
    LARGE_INTEGER BeyondFinalZero;
} FILE_ZERO_DATA_INFORMATION,*PFILE_ZERO_DATA_INFORMATION;

typedef struct _FILE_OBJECTID_BUFFER {
    BYTE ObjectId[16];
    union {
        struct {
            BYTE BirthVolumeId[16];
            BYTE BirthObjectId[16];
            BYTE DomainId[16];
        };
        BYTE ExtendedInfo[48];
    };
} FILE_OBJECTID_BUFFER, *PFILE_OBJECTID_BUFFER;

#define FILE_CS_FLAG_CASE_SENSITIVE_DIR             0x00000001

typedef struct _FILE_CASE_SENSITIVE_INFORMATION {
    ULONG Flags;
} FILE_CASE_SENSITIVE_INFORMATION, *PFILE_CASE_SENSITIVE_INFORMATION;

typedef struct _REPARSE_DATA_BUFFER {
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    };
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

typedef struct _FILE_COMPRESSION_INFORMATION {
    LARGE_INTEGER CompressedFileSize;
    USHORT CompressionFormat;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved[3];
} FILE_COMPRESSION_INFORMATION, *PFILE_COMPRESSION_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION_EX {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
    BOOLEAN AlternateStream;
    BOOLEAN MetadataAttribute;
} FILE_STANDARD_INFORMATION_EX, *PFILE_STANDARD_INFORMATION_EX;

extern "C"
NTSTATUS __stdcall NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

#ifdef _MSC_VER
#define FileDirectoryInformation ((FILE_INFORMATION_CLASS)1)
#define FileFullDirectoryInformation ((FILE_INFORMATION_CLASS)2)
#define FileBothDirectoryInformation ((FILE_INFORMATION_CLASS)3)
#define FileBasicInformation ((FILE_INFORMATION_CLASS)4)
#define FileStandardInformation ((FILE_INFORMATION_CLASS)5)
#define FileInternalInformation ((FILE_INFORMATION_CLASS)6)
#define FileEaInformation ((FILE_INFORMATION_CLASS)7)
#define FileAccessInformation ((FILE_INFORMATION_CLASS)8)
#define FileNameInformation ((FILE_INFORMATION_CLASS)9)
#define FileRenameInformation ((FILE_INFORMATION_CLASS)10)
#define FileLinkInformation ((FILE_INFORMATION_CLASS)11)
#define FileNamesInformation ((FILE_INFORMATION_CLASS)12)
#define FileDispositionInformation ((FILE_INFORMATION_CLASS)13)
#define FilePositionInformation ((FILE_INFORMATION_CLASS)14)
#define FileFullEaInformation ((FILE_INFORMATION_CLASS)15)
#define FileModeInformation ((FILE_INFORMATION_CLASS)16)
#define FileAlignmentInformation ((FILE_INFORMATION_CLASS)17)
#define FileAllInformation ((FILE_INFORMATION_CLASS)18)
#define FileAllocationInformation ((FILE_INFORMATION_CLASS)19)
#define FileEndOfFileInformation ((FILE_INFORMATION_CLASS)20)
#define FileAlternateNameInformation ((FILE_INFORMATION_CLASS)21)
#define FileStreamInformation ((FILE_INFORMATION_CLASS)22)
#define FilePipeInformation ((FILE_INFORMATION_CLASS)23)
#define FilePipeLocalInformation ((FILE_INFORMATION_CLASS)24)
#define FilePipeRemoteInformation ((FILE_INFORMATION_CLASS)25)
#define FileMailslotQueryInformation ((FILE_INFORMATION_CLASS)26)
#define FileMailslotSetInformation ((FILE_INFORMATION_CLASS)27)
#define FileCompressionInformation ((FILE_INFORMATION_CLASS)28)
#define FileObjectIdInformation ((FILE_INFORMATION_CLASS)29)
#define FileCompletionInformation ((FILE_INFORMATION_CLASS)30)
#define FileMoveClusterInformation ((FILE_INFORMATION_CLASS)31)
#define FileQuotaInformation ((FILE_INFORMATION_CLASS)32)
#define FileReparsePointInformation ((FILE_INFORMATION_CLASS)33)
#define FileNetworkOpenInformation ((FILE_INFORMATION_CLASS)34)
#define FileAttributeTagInformation ((FILE_INFORMATION_CLASS)35)
#define FileTrackingInformation ((FILE_INFORMATION_CLASS)36)
#define FileIdBothDirectoryInformation ((FILE_INFORMATION_CLASS)37)
#define FileIdFullDirectoryInformation ((FILE_INFORMATION_CLASS)38)
#define FileValidDataLengthInformation ((FILE_INFORMATION_CLASS)39)
#define FileHardLinkInformation ((FILE_INFORMATION_CLASS)46)
#define FileNormalizedNameInformation ((FILE_INFORMATION_CLASS)48)
#define FileStandardLinkInformation ((FILE_INFORMATION_CLASS)54)

extern "C"
NTSTATUS NTAPI NtQueryInformationFile(HANDLE hFile, PIO_STATUS_BLOCK io, PVOID ptr,
                                      ULONG len, FILE_INFORMATION_CLASS FileInformationClass);

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[ANYSIZE_ARRAY];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[ANYSIZE_ARRAY];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[ANYSIZE_ARRAY];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[ANYSIZE_ARRAY];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[ANYSIZE_ARRAY];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
    ULONG Reserved[3];
    ULONG NameInformationLength;
    ULONG TypeInformationLength;
    ULONG SecurityDescriptorLength;
    LARGE_INTEGER CreateTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _FILE_INTERNAL_INFORMATION {
    LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_EA_INFORMATION {
    ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION {
    ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, *PFILE_ACCESS_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

typedef struct _FILE_MODE_INFORMATION {
    ULONG Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;

typedef struct _FILE_ALIGNMENT_INFORMATION {
    ULONG AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION, *PFILE_ALIGNMENT_INFORMATION;

typedef struct _FILE_ALL_INFORMATION {
    FILE_BASIC_INFORMATION BasicInformation;
    FILE_STANDARD_INFORMATION StandardInformation;
    FILE_INTERNAL_INFORMATION InternalInformation;
    FILE_EA_INFORMATION EaInformation;
    FILE_ACCESS_INFORMATION AccessInformation;
    FILE_POSITION_INFORMATION PositionInformation;
    FILE_MODE_INFORMATION ModeInformation;
    FILE_ALIGNMENT_INFORMATION AlignmentInformation;
    FILE_NAME_INFORMATION NameInformation;
} FILE_ALL_INFORMATION, *PFILE_ALL_INFORMATION;

typedef struct _FILE_ATTRIBUTE_TAG_INFORMATION {
    ULONG FileAttributes;
    ULONG ReparseTag;
} FILE_ATTRIBUTE_TAG_INFORMATION, *PFILE_ATTRIBUTE_TAG_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef enum _FSINFOCLASS {
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,
    FileFsSizeInformation,
    FileFsDeviceInformation,
    FileFsAttributeInformation,
    FileFsControlInformation,
    FileFsFullSizeInformation,
    FileFsObjectIdInformation,
    FileFsDriverPathInformation,
    FileFsVolumeFlagsInformation,
    FileFsSectorSizeInformation,
    FileFsDataCopyInformation,
    FileFsMetadataSizeInformation,
    FileFsFullSizeInformationEx,
    FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DoDeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef struct _FILE_ALLOCATION_INFORMATION {
    LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFORMATION, *PFILE_ALLOCATION_INFORMATION;

typedef struct _FILE_END_OF_FILE_INFORMATION {
    LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;

typedef struct _FILE_RENAME_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef struct _FILE_LINK_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;

extern "C"
NTSTATUS __stdcall NtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
                                                PVOID FsInformation, ULONG Length,
                                                FS_INFORMATION_CLASS FsInformationClass);

extern "C"
NTSTATUS __stdcall NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                                   PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
                                   ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength,
                                   PVOID OutputBuffer, ULONG OutputBufferLength);

extern "C"
NTSTATUS __stdcall NtSetInformationFile(HANDLE hFile, PIO_STATUS_BLOCK io, PVOID ptr, ULONG len,
                                        FILE_INFORMATION_CLASS FileInformationClass);
#endif

typedef struct _FILE_ID_EXTD_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    ULONG ReparsePointTag;
    FILE_ID_128 FileId;
    WCHAR FileName[1];
} FILE_ID_EXTD_DIR_INFORMATION, *PFILE_ID_EXTD_DIR_INFORMATION;

typedef struct _FILE_ID_EXTD_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    ULONG ReparsePointTag;
    FILE_ID_128 FileId;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_ID_EXTD_BOTH_DIR_INFORMATION, *PFILE_ID_EXTD_BOTH_DIR_INFORMATION;

typedef struct _FILE_VALID_DATA_LENGTH_INFORMATION {
    LARGE_INTEGER ValidDataLength;
} FILE_VALID_DATA_LENGTH_INFORMATION, *PFILE_VALID_DATA_LENGTH_INFORMATION;

typedef struct _FILE_REPARSE_POINT_INFORMATION {
    LONGLONG FileReference;
    ULONG Tag;
} FILE_REPARSE_POINT_INFORMATION, *PFILE_REPARSE_POINT_INFORMATION;

typedef struct _REQUEST_OPLOCK_INPUT_BUFFER {
    WORD StructureVersion;
    WORD StructureLength;
    DWORD RequestedOplockLevel;
    DWORD Flags;
} REQUEST_OPLOCK_INPUT_BUFFER, *PREQUEST_OPLOCK_INPUT_BUFFER;

typedef struct _REQUEST_OPLOCK_OUTPUT_BUFFER {
    WORD StructureVersion;
    WORD StructureLength;
    DWORD OriginalOplockLevel;
    DWORD NewOplockLevel;
    DWORD Flags;
    ACCESS_MASK AccessMode;
    WORD ShareMode;
} REQUEST_OPLOCK_OUTPUT_BUFFER, *PREQUEST_OPLOCK_OUTPUT_BUFFER;

#define FileStatInformation ((FILE_INFORMATION_CLASS)68)

typedef struct _FILE_STAT_INFORMATION {
    LARGE_INTEGER FileId;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
    ULONG ReparseTag;
    ULONG NumberOfLinks;
    ACCESS_MASK EffectiveAccess;
} FILE_STAT_INFORMATION, *PFILE_STAT_INFORMATION;

#define FileStatLxInformation ((FILE_INFORMATION_CLASS)70)

typedef struct _FILE_STAT_LX_INFORMATION {
    LARGE_INTEGER FileId;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
    ULONG ReparseTag;
    ULONG NumberOfLinks;
    ACCESS_MASK EffectiveAccess;
    ULONG LxFlags;
    ULONG LxUid;
    ULONG LxGid;
    ULONG LxMode;
    ULONG LxDeviceIdMajor;
    ULONG LxDeviceIdMinor;
} FILE_STAT_LX_INFORMATION, *PFILE_STAT_LX_INFORMATION;

typedef struct _FILE_STANDARD_LINK_INFORMATION {
    ULONG NumberOfAccessibleLinks;
    ULONG TotalNumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_LINK_INFORMATION, *PFILE_STANDARD_LINK_INFORMATION;

typedef struct _FILE_ID_INFORMATION {
    ULONGLONG VolumeSerialNumber;
    FILE_ID_128 FileId;
} FILE_ID_INFORMATION, *PFILE_ID_INFORMATION;

class handle_closer {
public:
    typedef HANDLE pointer;

    void operator()(HANDLE h) {
        if (h == INVALID_HANDLE_VALUE)
            return;

        NtClose(h);
    }
};

typedef std::unique_ptr<HANDLE, handle_closer> unique_handle;

#define STATUS_CASE_DIFFERING_NAMES_IN_DIR ((NTSTATUS)0xc00004b3)

static __inline std::string ntstatus_to_string(NTSTATUS s) {
    switch (s) {
        case STATUS_KERNEL_APC:
            return "STATUS_KERNEL_APC";
        case STATUS_DEVICE_POWER_FAILURE:
            return "STATUS_DEVICE_POWER_FAILURE";
        case STATUS_ABIOS_NOT_PRESENT:
            return "STATUS_ABIOS_NOT_PRESENT";
        case STATUS_ABIOS_LID_NOT_EXIST:
            return "STATUS_ABIOS_LID_NOT_EXIST";
        case STATUS_ABIOS_LID_ALREADY_OWNED:
            return "STATUS_ABIOS_LID_ALREADY_OWNED";
        case STATUS_ABIOS_NOT_LID_OWNER:
            return "STATUS_ABIOS_NOT_LID_OWNER";
        case STATUS_ABIOS_INVALID_COMMAND:
            return "STATUS_ABIOS_INVALID_COMMAND";
        case STATUS_ABIOS_INVALID_LID:
            return "STATUS_ABIOS_INVALID_LID";
        case STATUS_ABIOS_SELECTOR_NOT_AVAILABLE:
            return "STATUS_ABIOS_SELECTOR_NOT_AVAILABLE";
        case STATUS_ABIOS_INVALID_SELECTOR:
            return "STATUS_ABIOS_INVALID_SELECTOR";
        case STATUS_MULTIPLE_FAULT_VIOLATION:
            return "STATUS_MULTIPLE_FAULT_VIOLATION";
        case STATUS_SUCCESS:
            return "STATUS_SUCCESS";
        case STATUS_WAIT_1:
            return "STATUS_WAIT_1";
        case STATUS_WAIT_2:
            return "STATUS_WAIT_2";
        case STATUS_WAIT_3:
            return "STATUS_WAIT_3";
        case STATUS_WAIT_63:
            return "STATUS_WAIT_63";
        case STATUS_ABANDONED:
            return "STATUS_ABANDONED";
        case STATUS_ABANDONED_WAIT_63:
            return "STATUS_ABANDONED_WAIT_63";
        case STATUS_USER_APC:
            return "STATUS_USER_APC";
        case STATUS_ALERTED:
            return "STATUS_ALERTED";
        case STATUS_TIMEOUT:
            return "STATUS_TIMEOUT";
        case STATUS_PENDING:
            return "STATUS_PENDING";
        case STATUS_REPARSE:
            return "STATUS_REPARSE";
        case STATUS_MORE_ENTRIES:
            return "STATUS_MORE_ENTRIES";
        case STATUS_NOT_ALL_ASSIGNED:
            return "STATUS_NOT_ALL_ASSIGNED";
        case STATUS_SOME_NOT_MAPPED:
            return "STATUS_SOME_NOT_MAPPED";
        case STATUS_OPLOCK_BREAK_IN_PROGRESS:
            return "STATUS_OPLOCK_BREAK_IN_PROGRESS";
        case STATUS_VOLUME_MOUNTED:
            return "STATUS_VOLUME_MOUNTED";
        case STATUS_RXACT_COMMITTED:
            return "STATUS_RXACT_COMMITTED";
        case STATUS_NOTIFY_CLEANUP:
            return "STATUS_NOTIFY_CLEANUP";
        case STATUS_NOTIFY_ENUM_DIR:
            return "STATUS_NOTIFY_ENUM_DIR";
        case STATUS_NO_QUOTAS_FOR_ACCOUNT:
            return "STATUS_NO_QUOTAS_FOR_ACCOUNT";
        case STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED:
            return "STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED";
        case STATUS_PAGE_FAULT_TRANSITION:
            return "STATUS_PAGE_FAULT_TRANSITION";
        case STATUS_PAGE_FAULT_DEMAND_ZERO:
            return "STATUS_PAGE_FAULT_DEMAND_ZERO";
        case STATUS_PAGE_FAULT_COPY_ON_WRITE:
            return "STATUS_PAGE_FAULT_COPY_ON_WRITE";
        case STATUS_PAGE_FAULT_GUARD_PAGE:
            return "STATUS_PAGE_FAULT_GUARD_PAGE";
        case STATUS_PAGE_FAULT_PAGING_FILE:
            return "STATUS_PAGE_FAULT_PAGING_FILE";
        case STATUS_CACHE_PAGE_LOCKED:
            return "STATUS_CACHE_PAGE_LOCKED";
        case STATUS_CRASH_DUMP:
            return "STATUS_CRASH_DUMP";
        case STATUS_BUFFER_ALL_ZEROS:
            return "STATUS_BUFFER_ALL_ZEROS";
        case STATUS_REPARSE_OBJECT:
            return "STATUS_REPARSE_OBJECT";
        case STATUS_RESOURCE_REQUIREMENTS_CHANGED:
            return "STATUS_RESOURCE_REQUIREMENTS_CHANGED";
        case STATUS_TRANSLATION_COMPLETE:
            return "STATUS_TRANSLATION_COMPLETE";
        case STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY:
            return "STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY";
        case STATUS_NOTHING_TO_TERMINATE:
            return "STATUS_NOTHING_TO_TERMINATE";
        case STATUS_PROCESS_NOT_IN_JOB:
            return "STATUS_PROCESS_NOT_IN_JOB";
        case STATUS_PROCESS_IN_JOB:
            return "STATUS_PROCESS_IN_JOB";
        case STATUS_VOLSNAP_HIBERNATE_READY:
            return "STATUS_VOLSNAP_HIBERNATE_READY";
        case STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY:
            return "STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY";
        case STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED:
            return "STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED";
        case STATUS_INTERRUPT_STILL_CONNECTED:
            return "STATUS_INTERRUPT_STILL_CONNECTED";
        case STATUS_PROCESS_CLONED:
            return "STATUS_PROCESS_CLONED";
        case STATUS_FILE_LOCKED_WITH_ONLY_READERS:
            return "STATUS_FILE_LOCKED_WITH_ONLY_READERS";
        case STATUS_FILE_LOCKED_WITH_WRITERS:
            return "STATUS_FILE_LOCKED_WITH_WRITERS";
        case STATUS_RESOURCEMANAGER_READ_ONLY:
            return "STATUS_RESOURCEMANAGER_READ_ONLY";
        case STATUS_WAIT_FOR_OPLOCK:
            return "STATUS_WAIT_FOR_OPLOCK";
        case DBG_EXCEPTION_HANDLED:
            return "DBG_EXCEPTION_HANDLED";
        case DBG_CONTINUE:
            return "DBG_CONTINUE";
        case STATUS_FLT_IO_COMPLETE:
            return "STATUS_FLT_IO_COMPLETE";
        case STATUS_FILE_NOT_AVAILABLE:
            return "STATUS_FILE_NOT_AVAILABLE";
        case STATUS_OBJECT_NAME_EXISTS:
            return "STATUS_OBJECT_NAME_EXISTS";
        case STATUS_THREAD_WAS_SUSPENDED:
            return "STATUS_THREAD_WAS_SUSPENDED";
        case STATUS_WORKING_SET_LIMIT_RANGE:
            return "STATUS_WORKING_SET_LIMIT_RANGE";
        case STATUS_IMAGE_NOT_AT_BASE:
            return "STATUS_IMAGE_NOT_AT_BASE";
        case STATUS_RXACT_STATE_CREATED:
            return "STATUS_RXACT_STATE_CREATED";
        case STATUS_SEGMENT_NOTIFICATION:
            return "STATUS_SEGMENT_NOTIFICATION";
        case STATUS_LOCAL_USER_SESSION_KEY:
            return "STATUS_LOCAL_USER_SESSION_KEY";
        case STATUS_BAD_CURRENT_DIRECTORY:
            return "STATUS_BAD_CURRENT_DIRECTORY";
        case STATUS_SERIAL_MORE_WRITES:
            return "STATUS_SERIAL_MORE_WRITES";
        case STATUS_REGISTRY_RECOVERED:
            return "STATUS_REGISTRY_RECOVERED";
        case STATUS_FT_READ_RECOVERY_FROM_BACKUP:
            return "STATUS_FT_READ_RECOVERY_FROM_BACKUP";
        case STATUS_FT_WRITE_RECOVERY:
            return "STATUS_FT_WRITE_RECOVERY";
        case STATUS_SERIAL_COUNTER_TIMEOUT:
            return "STATUS_SERIAL_COUNTER_TIMEOUT";
        case STATUS_NULL_LM_PASSWORD:
            return "STATUS_NULL_LM_PASSWORD";
        case STATUS_IMAGE_MACHINE_TYPE_MISMATCH:
            return "STATUS_IMAGE_MACHINE_TYPE_MISMATCH";
        case STATUS_RECEIVE_PARTIAL:
            return "STATUS_RECEIVE_PARTIAL";
        case STATUS_RECEIVE_EXPEDITED:
            return "STATUS_RECEIVE_EXPEDITED";
        case STATUS_RECEIVE_PARTIAL_EXPEDITED:
            return "STATUS_RECEIVE_PARTIAL_EXPEDITED";
        case STATUS_EVENT_DONE:
            return "STATUS_EVENT_DONE";
        case STATUS_EVENT_PENDING:
            return "STATUS_EVENT_PENDING";
        case STATUS_CHECKING_FILE_SYSTEM:
            return "STATUS_CHECKING_FILE_SYSTEM";
        case STATUS_FATAL_APP_EXIT:
            return "STATUS_FATAL_APP_EXIT";
        case STATUS_PREDEFINED_HANDLE:
            return "STATUS_PREDEFINED_HANDLE";
        case STATUS_WAS_UNLOCKED:
            return "STATUS_WAS_UNLOCKED";
        case STATUS_SERVICE_NOTIFICATION:
            return "STATUS_SERVICE_NOTIFICATION";
        case STATUS_WAS_LOCKED:
            return "STATUS_WAS_LOCKED";
        case STATUS_LOG_HARD_ERROR:
            return "STATUS_LOG_HARD_ERROR";
        case STATUS_ALREADY_WIN32:
            return "STATUS_ALREADY_WIN32";
        case STATUS_WX86_UNSIMULATE:
            return "STATUS_WX86_UNSIMULATE";
        case STATUS_WX86_CONTINUE:
            return "STATUS_WX86_CONTINUE";
        case STATUS_WX86_SINGLE_STEP:
            return "STATUS_WX86_SINGLE_STEP";
        case STATUS_WX86_BREAKPOINT:
            return "STATUS_WX86_BREAKPOINT";
        case STATUS_WX86_EXCEPTION_CONTINUE:
            return "STATUS_WX86_EXCEPTION_CONTINUE";
        case STATUS_WX86_EXCEPTION_LASTCHANCE:
            return "STATUS_WX86_EXCEPTION_LASTCHANCE";
        case STATUS_WX86_EXCEPTION_CHAIN:
            return "STATUS_WX86_EXCEPTION_CHAIN";
        case STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE:
            return "STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE";
        case STATUS_NO_YIELD_PERFORMED:
            return "STATUS_NO_YIELD_PERFORMED";
        case STATUS_TIMER_RESUME_IGNORED:
            return "STATUS_TIMER_RESUME_IGNORED";
        case STATUS_ARBITRATION_UNHANDLED:
            return "STATUS_ARBITRATION_UNHANDLED";
        case STATUS_CARDBUS_NOT_SUPPORTED:
            return "STATUS_CARDBUS_NOT_SUPPORTED";
        case STATUS_WX86_CREATEWX86TIB:
            return "STATUS_WX86_CREATEWX86TIB";
        case STATUS_MP_PROCESSOR_MISMATCH:
            return "STATUS_MP_PROCESSOR_MISMATCH";
        case STATUS_HIBERNATED:
            return "STATUS_HIBERNATED";
        case STATUS_RESUME_HIBERNATION:
            return "STATUS_RESUME_HIBERNATION";
        case STATUS_FIRMWARE_UPDATED:
            return "STATUS_FIRMWARE_UPDATED";
        case STATUS_DRIVERS_LEAKING_LOCKED_PAGES:
            return "STATUS_DRIVERS_LEAKING_LOCKED_PAGES";
        case STATUS_MESSAGE_RETRIEVED:
            return "STATUS_MESSAGE_RETRIEVED";
        case STATUS_SYSTEM_POWERSTATE_TRANSITION:
            return "STATUS_SYSTEM_POWERSTATE_TRANSITION";
        case STATUS_ALPC_CHECK_COMPLETION_LIST:
            return "STATUS_ALPC_CHECK_COMPLETION_LIST";
        case STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION:
            return "STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION";
        case STATUS_ACCESS_AUDIT_BY_POLICY:
            return "STATUS_ACCESS_AUDIT_BY_POLICY";
        case STATUS_ABANDON_HIBERFILE:
            return "STATUS_ABANDON_HIBERFILE";
        case STATUS_BIZRULES_NOT_ENABLED:
            return "STATUS_BIZRULES_NOT_ENABLED";
        case STATUS_WAKE_SYSTEM:
            return "STATUS_WAKE_SYSTEM";
        case STATUS_DS_SHUTTING_DOWN:
            return "STATUS_DS_SHUTTING_DOWN";
        case DBG_REPLY_LATER:
            return "DBG_REPLY_LATER";
        case DBG_UNABLE_TO_PROVIDE_HANDLE:
            return "DBG_UNABLE_TO_PROVIDE_HANDLE";
        case DBG_TERMINATE_THREAD:
            return "DBG_TERMINATE_THREAD";
        case DBG_TERMINATE_PROCESS:
            return "DBG_TERMINATE_PROCESS";
        case DBG_CONTROL_C:
            return "DBG_CONTROL_C";
        case DBG_PRINTEXCEPTION_C:
            return "DBG_PRINTEXCEPTION_C";
        case DBG_RIPEXCEPTION:
            return "DBG_RIPEXCEPTION";
        case DBG_CONTROL_BREAK:
            return "DBG_CONTROL_BREAK";
        case DBG_COMMAND_EXCEPTION:
            return "DBG_COMMAND_EXCEPTION";
        case DBG_PRINTEXCEPTION_WIDE_C:
            return "DBG_PRINTEXCEPTION_WIDE_C";
        case RPC_NT_UUID_LOCAL_ONLY:
            return "RPC_NT_UUID_LOCAL_ONLY";
        case RPC_NT_SEND_INCOMPLETE:
            return "RPC_NT_SEND_INCOMPLETE";
        case STATUS_CTX_CDM_CONNECT:
            return "STATUS_CTX_CDM_CONNECT";
        case STATUS_CTX_CDM_DISCONNECT:
            return "STATUS_CTX_CDM_DISCONNECT";
        case STATUS_SXS_RELEASE_ACTIVATION_CONTEXT:
            return "STATUS_SXS_RELEASE_ACTIVATION_CONTEXT";
        case STATUS_RECOVERY_NOT_NEEDED:
            return "STATUS_RECOVERY_NOT_NEEDED";
        case STATUS_RM_ALREADY_STARTED:
            return "STATUS_RM_ALREADY_STARTED";
        case STATUS_LOG_NO_RESTART:
            return "STATUS_LOG_NO_RESTART";
        case STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST:
            return "STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST";
        case STATUS_GRAPHICS_PARTIAL_DATA_POPULATED:
            return "STATUS_GRAPHICS_PARTIAL_DATA_POPULATED";
        case STATUS_GRAPHICS_DRIVER_MISMATCH:
            return "STATUS_GRAPHICS_DRIVER_MISMATCH";
        case STATUS_GRAPHICS_MODE_NOT_PINNED:
            return "STATUS_GRAPHICS_MODE_NOT_PINNED";
        case STATUS_GRAPHICS_NO_PREFERRED_MODE:
            return "STATUS_GRAPHICS_NO_PREFERRED_MODE";
        case STATUS_GRAPHICS_DATASET_IS_EMPTY:
            return "STATUS_GRAPHICS_DATASET_IS_EMPTY";
        case STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET:
            return "STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET";
        case STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED:
            return "STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED";
        case STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS:
            return "STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS";
        case STATUS_GRAPHICS_LEADLINK_START_DEFERRED:
            return "STATUS_GRAPHICS_LEADLINK_START_DEFERRED";
        case STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY:
            return "STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY";
        case STATUS_GRAPHICS_START_DEFERRED:
            return "STATUS_GRAPHICS_START_DEFERRED";
        case STATUS_NDIS_INDICATION_REQUIRED:
            return "STATUS_NDIS_INDICATION_REQUIRED";
        case STATUS_GUARD_PAGE_VIOLATION:
            return "STATUS_GUARD_PAGE_VIOLATION";
        case STATUS_DATATYPE_MISALIGNMENT:
            return "STATUS_DATATYPE_MISALIGNMENT";
        case STATUS_BREAKPOINT:
            return "STATUS_BREAKPOINT";
        case STATUS_SINGLE_STEP:
            return "STATUS_SINGLE_STEP";
        case STATUS_BUFFER_OVERFLOW:
            return "STATUS_BUFFER_OVERFLOW";
        case STATUS_NO_MORE_FILES:
            return "STATUS_NO_MORE_FILES";
        case STATUS_WAKE_SYSTEM_DEBUGGER:
            return "STATUS_WAKE_SYSTEM_DEBUGGER";
        case STATUS_HANDLES_CLOSED:
            return "STATUS_HANDLES_CLOSED";
        case STATUS_NO_INHERITANCE:
            return "STATUS_NO_INHERITANCE";
        case STATUS_GUID_SUBSTITUTION_MADE:
            return "STATUS_GUID_SUBSTITUTION_MADE";
        case STATUS_PARTIAL_COPY:
            return "STATUS_PARTIAL_COPY";
        case STATUS_DEVICE_PAPER_EMPTY:
            return "STATUS_DEVICE_PAPER_EMPTY";
        case STATUS_DEVICE_POWERED_OFF:
            return "STATUS_DEVICE_POWERED_OFF";
        case STATUS_DEVICE_OFF_LINE:
            return "STATUS_DEVICE_OFF_LINE";
        case STATUS_DEVICE_BUSY:
            return "STATUS_DEVICE_BUSY";
        case STATUS_NO_MORE_EAS:
            return "STATUS_NO_MORE_EAS";
        case STATUS_INVALID_EA_NAME:
            return "STATUS_INVALID_EA_NAME";
        case STATUS_EA_LIST_INCONSISTENT:
            return "STATUS_EA_LIST_INCONSISTENT";
        case STATUS_INVALID_EA_FLAG:
            return "STATUS_INVALID_EA_FLAG";
        case STATUS_VERIFY_REQUIRED:
            return "STATUS_VERIFY_REQUIRED";
        case STATUS_EXTRANEOUS_INFORMATION:
            return "STATUS_EXTRANEOUS_INFORMATION";
        case STATUS_RXACT_COMMIT_NECESSARY:
            return "STATUS_RXACT_COMMIT_NECESSARY";
        case STATUS_NO_MORE_ENTRIES:
            return "STATUS_NO_MORE_ENTRIES";
        case STATUS_FILEMARK_DETECTED:
            return "STATUS_FILEMARK_DETECTED";
        case STATUS_MEDIA_CHANGED:
            return "STATUS_MEDIA_CHANGED";
        case STATUS_BUS_RESET:
            return "STATUS_BUS_RESET";
        case STATUS_END_OF_MEDIA:
            return "STATUS_END_OF_MEDIA";
        case STATUS_BEGINNING_OF_MEDIA:
            return "STATUS_BEGINNING_OF_MEDIA";
        case STATUS_MEDIA_CHECK:
            return "STATUS_MEDIA_CHECK";
        case STATUS_SETMARK_DETECTED:
            return "STATUS_SETMARK_DETECTED";
        case STATUS_NO_DATA_DETECTED:
            return "STATUS_NO_DATA_DETECTED";
        case STATUS_REDIRECTOR_HAS_OPEN_HANDLES:
            return "STATUS_REDIRECTOR_HAS_OPEN_HANDLES";
        case STATUS_SERVER_HAS_OPEN_HANDLES:
            return "STATUS_SERVER_HAS_OPEN_HANDLES";
        case STATUS_ALREADY_DISCONNECTED:
            return "STATUS_ALREADY_DISCONNECTED";
        case STATUS_LONGJUMP:
            return "STATUS_LONGJUMP";
        case STATUS_CLEANER_CARTRIDGE_INSTALLED:
            return "STATUS_CLEANER_CARTRIDGE_INSTALLED";
        case STATUS_PLUGPLAY_QUERY_VETOED:
            return "STATUS_PLUGPLAY_QUERY_VETOED";
        case STATUS_UNWIND_CONSOLIDATE:
            return "STATUS_UNWIND_CONSOLIDATE";
        case STATUS_REGISTRY_HIVE_RECOVERED:
            return "STATUS_REGISTRY_HIVE_RECOVERED";
        case STATUS_DLL_MIGHT_BE_INSECURE:
            return "STATUS_DLL_MIGHT_BE_INSECURE";
        case STATUS_DLL_MIGHT_BE_INCOMPATIBLE:
            return "STATUS_DLL_MIGHT_BE_INCOMPATIBLE";
        case STATUS_STOPPED_ON_SYMLINK:
            return "STATUS_STOPPED_ON_SYMLINK";
        case STATUS_DEVICE_REQUIRES_CLEANING:
            return "STATUS_DEVICE_REQUIRES_CLEANING";
        case STATUS_DEVICE_DOOR_OPEN:
            return "STATUS_DEVICE_DOOR_OPEN";
        case STATUS_DATA_LOST_REPAIR:
            return "STATUS_DATA_LOST_REPAIR";
        case DBG_EXCEPTION_NOT_HANDLED:
            return "DBG_EXCEPTION_NOT_HANDLED";
        case STATUS_CLUSTER_NODE_ALREADY_UP:
            return "STATUS_CLUSTER_NODE_ALREADY_UP";
        case STATUS_CLUSTER_NODE_ALREADY_DOWN:
            return "STATUS_CLUSTER_NODE_ALREADY_DOWN";
        case STATUS_CLUSTER_NETWORK_ALREADY_ONLINE:
            return "STATUS_CLUSTER_NETWORK_ALREADY_ONLINE";
        case STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE:
            return "STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE";
        case STATUS_CLUSTER_NODE_ALREADY_MEMBER:
            return "STATUS_CLUSTER_NODE_ALREADY_MEMBER";
        case STATUS_COULD_NOT_RESIZE_LOG:
            return "STATUS_COULD_NOT_RESIZE_LOG";
        case STATUS_NO_TXF_METADATA:
            return "STATUS_NO_TXF_METADATA";
        case STATUS_CANT_RECOVER_WITH_HANDLE_OPEN:
            return "STATUS_CANT_RECOVER_WITH_HANDLE_OPEN";
        case STATUS_TXF_METADATA_ALREADY_PRESENT:
            return "STATUS_TXF_METADATA_ALREADY_PRESENT";
        case STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET:
            return "STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET";
        case STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED:
            return "STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED";
        case STATUS_FLT_BUFFER_TOO_SMALL:
            return "STATUS_FLT_BUFFER_TOO_SMALL";
        case STATUS_FVE_PARTIAL_METADATA:
            return "STATUS_FVE_PARTIAL_METADATA";
        case STATUS_FVE_TRANSIENT_STATE:
            return "STATUS_FVE_TRANSIENT_STATE";
        case STATUS_UNSUCCESSFUL:
            return "STATUS_UNSUCCESSFUL";
        case STATUS_NOT_IMPLEMENTED:
            return "STATUS_NOT_IMPLEMENTED";
        case STATUS_INVALID_INFO_CLASS:
            return "STATUS_INVALID_INFO_CLASS";
        case STATUS_INFO_LENGTH_MISMATCH:
            return "STATUS_INFO_LENGTH_MISMATCH";
        case STATUS_ACCESS_VIOLATION:
            return "STATUS_ACCESS_VIOLATION";
        case STATUS_IN_PAGE_ERROR:
            return "STATUS_IN_PAGE_ERROR";
        case STATUS_PAGEFILE_QUOTA:
            return "STATUS_PAGEFILE_QUOTA";
        case STATUS_INVALID_HANDLE:
            return "STATUS_INVALID_HANDLE";
        case STATUS_BAD_INITIAL_STACK:
            return "STATUS_BAD_INITIAL_STACK";
        case STATUS_BAD_INITIAL_PC:
            return "STATUS_BAD_INITIAL_PC";
        case STATUS_INVALID_CID:
            return "STATUS_INVALID_CID";
        case STATUS_TIMER_NOT_CANCELED:
            return "STATUS_TIMER_NOT_CANCELED";
        case STATUS_INVALID_PARAMETER:
            return "STATUS_INVALID_PARAMETER";
        case STATUS_NO_SUCH_DEVICE:
            return "STATUS_NO_SUCH_DEVICE";
        case STATUS_NO_SUCH_FILE:
            return "STATUS_NO_SUCH_FILE";
        case STATUS_INVALID_DEVICE_REQUEST:
            return "STATUS_INVALID_DEVICE_REQUEST";
        case STATUS_END_OF_FILE:
            return "STATUS_END_OF_FILE";
        case STATUS_WRONG_VOLUME:
            return "STATUS_WRONG_VOLUME";
        case STATUS_NO_MEDIA_IN_DEVICE:
            return "STATUS_NO_MEDIA_IN_DEVICE";
        case STATUS_UNRECOGNIZED_MEDIA:
            return "STATUS_UNRECOGNIZED_MEDIA";
        case STATUS_NONEXISTENT_SECTOR:
            return "STATUS_NONEXISTENT_SECTOR";
        case STATUS_MORE_PROCESSING_REQUIRED:
            return "STATUS_MORE_PROCESSING_REQUIRED";
        case STATUS_NO_MEMORY:
            return "STATUS_NO_MEMORY";
        case STATUS_CONFLICTING_ADDRESSES:
            return "STATUS_CONFLICTING_ADDRESSES";
        case STATUS_NOT_MAPPED_VIEW:
            return "STATUS_NOT_MAPPED_VIEW";
        case STATUS_UNABLE_TO_FREE_VM:
            return "STATUS_UNABLE_TO_FREE_VM";
        case STATUS_UNABLE_TO_DELETE_SECTION:
            return "STATUS_UNABLE_TO_DELETE_SECTION";
        case STATUS_INVALID_SYSTEM_SERVICE:
            return "STATUS_INVALID_SYSTEM_SERVICE";
        case STATUS_ILLEGAL_INSTRUCTION:
            return "STATUS_ILLEGAL_INSTRUCTION";
        case STATUS_INVALID_LOCK_SEQUENCE:
            return "STATUS_INVALID_LOCK_SEQUENCE";
        case STATUS_INVALID_VIEW_SIZE:
            return "STATUS_INVALID_VIEW_SIZE";
        case STATUS_INVALID_FILE_FOR_SECTION:
            return "STATUS_INVALID_FILE_FOR_SECTION";
        case STATUS_ALREADY_COMMITTED:
            return "STATUS_ALREADY_COMMITTED";
        case STATUS_ACCESS_DENIED:
            return "STATUS_ACCESS_DENIED";
        case STATUS_BUFFER_TOO_SMALL:
            return "STATUS_BUFFER_TOO_SMALL";
        case STATUS_OBJECT_TYPE_MISMATCH:
            return "STATUS_OBJECT_TYPE_MISMATCH";
        case STATUS_NONCONTINUABLE_EXCEPTION:
            return "STATUS_NONCONTINUABLE_EXCEPTION";
        case STATUS_INVALID_DISPOSITION:
            return "STATUS_INVALID_DISPOSITION";
        case STATUS_UNWIND:
            return "STATUS_UNWIND";
        case STATUS_BAD_STACK:
            return "STATUS_BAD_STACK";
        case STATUS_INVALID_UNWIND_TARGET:
            return "STATUS_INVALID_UNWIND_TARGET";
        case STATUS_NOT_LOCKED:
            return "STATUS_NOT_LOCKED";
        case STATUS_PARITY_ERROR:
            return "STATUS_PARITY_ERROR";
        case STATUS_UNABLE_TO_DECOMMIT_VM:
            return "STATUS_UNABLE_TO_DECOMMIT_VM";
        case STATUS_NOT_COMMITTED:
            return "STATUS_NOT_COMMITTED";
        case STATUS_INVALID_PORT_ATTRIBUTES:
            return "STATUS_INVALID_PORT_ATTRIBUTES";
        case STATUS_PORT_MESSAGE_TOO_LONG:
            return "STATUS_PORT_MESSAGE_TOO_LONG";
        case STATUS_INVALID_PARAMETER_MIX:
            return "STATUS_INVALID_PARAMETER_MIX";
        case STATUS_INVALID_QUOTA_LOWER:
            return "STATUS_INVALID_QUOTA_LOWER";
        case STATUS_DISK_CORRUPT_ERROR:
            return "STATUS_DISK_CORRUPT_ERROR";
        case STATUS_OBJECT_NAME_INVALID:
            return "STATUS_OBJECT_NAME_INVALID";
        case STATUS_OBJECT_NAME_NOT_FOUND:
            return "STATUS_OBJECT_NAME_NOT_FOUND";
        case STATUS_OBJECT_NAME_COLLISION:
            return "STATUS_OBJECT_NAME_COLLISION";
        case STATUS_PORT_DISCONNECTED:
            return "STATUS_PORT_DISCONNECTED";
        case STATUS_DEVICE_ALREADY_ATTACHED:
            return "STATUS_DEVICE_ALREADY_ATTACHED";
        case STATUS_OBJECT_PATH_INVALID:
            return "STATUS_OBJECT_PATH_INVALID";
        case STATUS_OBJECT_PATH_NOT_FOUND:
            return "STATUS_OBJECT_PATH_NOT_FOUND";
        case STATUS_OBJECT_PATH_SYNTAX_BAD:
            return "STATUS_OBJECT_PATH_SYNTAX_BAD";
        case STATUS_DATA_OVERRUN:
            return "STATUS_DATA_OVERRUN";
        case STATUS_DATA_LATE_ERROR:
            return "STATUS_DATA_LATE_ERROR";
        case STATUS_DATA_ERROR:
            return "STATUS_DATA_ERROR";
        case STATUS_CRC_ERROR:
            return "STATUS_CRC_ERROR";
        case STATUS_SECTION_TOO_BIG:
            return "STATUS_SECTION_TOO_BIG";
        case STATUS_PORT_CONNECTION_REFUSED:
            return "STATUS_PORT_CONNECTION_REFUSED";
        case STATUS_INVALID_PORT_HANDLE:
            return "STATUS_INVALID_PORT_HANDLE";
        case STATUS_SHARING_VIOLATION:
            return "STATUS_SHARING_VIOLATION";
        case STATUS_QUOTA_EXCEEDED:
            return "STATUS_QUOTA_EXCEEDED";
        case STATUS_INVALID_PAGE_PROTECTION:
            return "STATUS_INVALID_PAGE_PROTECTION";
        case STATUS_MUTANT_NOT_OWNED:
            return "STATUS_MUTANT_NOT_OWNED";
        case STATUS_SEMAPHORE_LIMIT_EXCEEDED:
            return "STATUS_SEMAPHORE_LIMIT_EXCEEDED";
        case STATUS_PORT_ALREADY_SET:
            return "STATUS_PORT_ALREADY_SET";
        case STATUS_SECTION_NOT_IMAGE:
            return "STATUS_SECTION_NOT_IMAGE";
        case STATUS_SUSPEND_COUNT_EXCEEDED:
            return "STATUS_SUSPEND_COUNT_EXCEEDED";
        case STATUS_THREAD_IS_TERMINATING:
            return "STATUS_THREAD_IS_TERMINATING";
        case STATUS_BAD_WORKING_SET_LIMIT:
            return "STATUS_BAD_WORKING_SET_LIMIT";
        case STATUS_INCOMPATIBLE_FILE_MAP:
            return "STATUS_INCOMPATIBLE_FILE_MAP";
        case STATUS_SECTION_PROTECTION:
            return "STATUS_SECTION_PROTECTION";
        case STATUS_EAS_NOT_SUPPORTED:
            return "STATUS_EAS_NOT_SUPPORTED";
        case STATUS_EA_TOO_LARGE:
            return "STATUS_EA_TOO_LARGE";
        case STATUS_NONEXISTENT_EA_ENTRY:
            return "STATUS_NONEXISTENT_EA_ENTRY";
        case STATUS_NO_EAS_ON_FILE:
            return "STATUS_NO_EAS_ON_FILE";
        case STATUS_EA_CORRUPT_ERROR:
            return "STATUS_EA_CORRUPT_ERROR";
        case STATUS_FILE_LOCK_CONFLICT:
            return "STATUS_FILE_LOCK_CONFLICT";
        case STATUS_LOCK_NOT_GRANTED:
            return "STATUS_LOCK_NOT_GRANTED";
        case STATUS_DELETE_PENDING:
            return "STATUS_DELETE_PENDING";
        case STATUS_CTL_FILE_NOT_SUPPORTED:
            return "STATUS_CTL_FILE_NOT_SUPPORTED";
        case STATUS_UNKNOWN_REVISION:
            return "STATUS_UNKNOWN_REVISION";
        case STATUS_REVISION_MISMATCH:
            return "STATUS_REVISION_MISMATCH";
        case STATUS_INVALID_OWNER:
            return "STATUS_INVALID_OWNER";
        case STATUS_INVALID_PRIMARY_GROUP:
            return "STATUS_INVALID_PRIMARY_GROUP";
        case STATUS_NO_IMPERSONATION_TOKEN:
            return "STATUS_NO_IMPERSONATION_TOKEN";
        case STATUS_CANT_DISABLE_MANDATORY:
            return "STATUS_CANT_DISABLE_MANDATORY";
        case STATUS_NO_LOGON_SERVERS:
            return "STATUS_NO_LOGON_SERVERS";
        case STATUS_NO_SUCH_LOGON_SESSION:
            return "STATUS_NO_SUCH_LOGON_SESSION";
        case STATUS_NO_SUCH_PRIVILEGE:
            return "STATUS_NO_SUCH_PRIVILEGE";
        case STATUS_PRIVILEGE_NOT_HELD:
            return "STATUS_PRIVILEGE_NOT_HELD";
        case STATUS_INVALID_ACCOUNT_NAME:
            return "STATUS_INVALID_ACCOUNT_NAME";
        case STATUS_USER_EXISTS:
            return "STATUS_USER_EXISTS";
        case STATUS_NO_SUCH_USER:
            return "STATUS_NO_SUCH_USER";
        case STATUS_GROUP_EXISTS:
            return "STATUS_GROUP_EXISTS";
        case STATUS_NO_SUCH_GROUP:
            return "STATUS_NO_SUCH_GROUP";
        case STATUS_MEMBER_IN_GROUP:
            return "STATUS_MEMBER_IN_GROUP";
        case STATUS_MEMBER_NOT_IN_GROUP:
            return "STATUS_MEMBER_NOT_IN_GROUP";
        case STATUS_LAST_ADMIN:
            return "STATUS_LAST_ADMIN";
        case STATUS_WRONG_PASSWORD:
            return "STATUS_WRONG_PASSWORD";
        case STATUS_ILL_FORMED_PASSWORD:
            return "STATUS_ILL_FORMED_PASSWORD";
        case STATUS_PASSWORD_RESTRICTION:
            return "STATUS_PASSWORD_RESTRICTION";
        case STATUS_LOGON_FAILURE:
            return "STATUS_LOGON_FAILURE";
        case STATUS_ACCOUNT_RESTRICTION:
            return "STATUS_ACCOUNT_RESTRICTION";
        case STATUS_INVALID_LOGON_HOURS:
            return "STATUS_INVALID_LOGON_HOURS";
        case STATUS_INVALID_WORKSTATION:
            return "STATUS_INVALID_WORKSTATION";
        case STATUS_PASSWORD_EXPIRED:
            return "STATUS_PASSWORD_EXPIRED";
        case STATUS_ACCOUNT_DISABLED:
            return "STATUS_ACCOUNT_DISABLED";
        case STATUS_NONE_MAPPED:
            return "STATUS_NONE_MAPPED";
        case STATUS_TOO_MANY_LUIDS_REQUESTED:
            return "STATUS_TOO_MANY_LUIDS_REQUESTED";
        case STATUS_LUIDS_EXHAUSTED:
            return "STATUS_LUIDS_EXHAUSTED";
        case STATUS_INVALID_SUB_AUTHORITY:
            return "STATUS_INVALID_SUB_AUTHORITY";
        case STATUS_INVALID_ACL:
            return "STATUS_INVALID_ACL";
        case STATUS_INVALID_SID:
            return "STATUS_INVALID_SID";
        case STATUS_INVALID_SECURITY_DESCR:
            return "STATUS_INVALID_SECURITY_DESCR";
        case STATUS_PROCEDURE_NOT_FOUND:
            return "STATUS_PROCEDURE_NOT_FOUND";
        case STATUS_INVALID_IMAGE_FORMAT:
            return "STATUS_INVALID_IMAGE_FORMAT";
        case STATUS_NO_TOKEN:
            return "STATUS_NO_TOKEN";
        case STATUS_BAD_INHERITANCE_ACL:
            return "STATUS_BAD_INHERITANCE_ACL";
        case STATUS_RANGE_NOT_LOCKED:
            return "STATUS_RANGE_NOT_LOCKED";
        case STATUS_DISK_FULL:
            return "STATUS_DISK_FULL";
        case STATUS_SERVER_DISABLED:
            return "STATUS_SERVER_DISABLED";
        case STATUS_SERVER_NOT_DISABLED:
            return "STATUS_SERVER_NOT_DISABLED";
        case STATUS_TOO_MANY_GUIDS_REQUESTED:
            return "STATUS_TOO_MANY_GUIDS_REQUESTED";
        case STATUS_GUIDS_EXHAUSTED:
            return "STATUS_GUIDS_EXHAUSTED";
        case STATUS_INVALID_ID_AUTHORITY:
            return "STATUS_INVALID_ID_AUTHORITY";
        case STATUS_AGENTS_EXHAUSTED:
            return "STATUS_AGENTS_EXHAUSTED";
        case STATUS_INVALID_VOLUME_LABEL:
            return "STATUS_INVALID_VOLUME_LABEL";
        case STATUS_SECTION_NOT_EXTENDED:
            return "STATUS_SECTION_NOT_EXTENDED";
        case STATUS_NOT_MAPPED_DATA:
            return "STATUS_NOT_MAPPED_DATA";
        case STATUS_RESOURCE_DATA_NOT_FOUND:
            return "STATUS_RESOURCE_DATA_NOT_FOUND";
        case STATUS_RESOURCE_TYPE_NOT_FOUND:
            return "STATUS_RESOURCE_TYPE_NOT_FOUND";
        case STATUS_RESOURCE_NAME_NOT_FOUND:
            return "STATUS_RESOURCE_NAME_NOT_FOUND";
        case STATUS_ARRAY_BOUNDS_EXCEEDED:
            return "STATUS_ARRAY_BOUNDS_EXCEEDED";
        case STATUS_FLOAT_DENORMAL_OPERAND:
            return "STATUS_FLOAT_DENORMAL_OPERAND";
        case STATUS_FLOAT_DIVIDE_BY_ZERO:
            return "STATUS_FLOAT_DIVIDE_BY_ZERO";
        case STATUS_FLOAT_INEXACT_RESULT:
            return "STATUS_FLOAT_INEXACT_RESULT";
        case STATUS_FLOAT_INVALID_OPERATION:
            return "STATUS_FLOAT_INVALID_OPERATION";
        case STATUS_FLOAT_OVERFLOW:
            return "STATUS_FLOAT_OVERFLOW";
        case STATUS_FLOAT_STACK_CHECK:
            return "STATUS_FLOAT_STACK_CHECK";
        case STATUS_FLOAT_UNDERFLOW:
            return "STATUS_FLOAT_UNDERFLOW";
        case STATUS_INTEGER_DIVIDE_BY_ZERO:
            return "STATUS_INTEGER_DIVIDE_BY_ZERO";
        case STATUS_INTEGER_OVERFLOW:
            return "STATUS_INTEGER_OVERFLOW";
        case STATUS_PRIVILEGED_INSTRUCTION:
            return "STATUS_PRIVILEGED_INSTRUCTION";
        case STATUS_TOO_MANY_PAGING_FILES:
            return "STATUS_TOO_MANY_PAGING_FILES";
        case STATUS_FILE_INVALID:
            return "STATUS_FILE_INVALID";
        case STATUS_ALLOTTED_SPACE_EXCEEDED:
            return "STATUS_ALLOTTED_SPACE_EXCEEDED";
        case STATUS_INSUFFICIENT_RESOURCES:
            return "STATUS_INSUFFICIENT_RESOURCES";
        case STATUS_DFS_EXIT_PATH_FOUND:
            return "STATUS_DFS_EXIT_PATH_FOUND";
        case STATUS_DEVICE_DATA_ERROR:
            return "STATUS_DEVICE_DATA_ERROR";
        case STATUS_DEVICE_NOT_CONNECTED:
            return "STATUS_DEVICE_NOT_CONNECTED";
        case STATUS_FREE_VM_NOT_AT_BASE:
            return "STATUS_FREE_VM_NOT_AT_BASE";
        case STATUS_MEMORY_NOT_ALLOCATED:
            return "STATUS_MEMORY_NOT_ALLOCATED";
        case STATUS_WORKING_SET_QUOTA:
            return "STATUS_WORKING_SET_QUOTA";
        case STATUS_MEDIA_WRITE_PROTECTED:
            return "STATUS_MEDIA_WRITE_PROTECTED";
        case STATUS_DEVICE_NOT_READY:
            return "STATUS_DEVICE_NOT_READY";
        case STATUS_INVALID_GROUP_ATTRIBUTES:
            return "STATUS_INVALID_GROUP_ATTRIBUTES";
        case STATUS_BAD_IMPERSONATION_LEVEL:
            return "STATUS_BAD_IMPERSONATION_LEVEL";
        case STATUS_CANT_OPEN_ANONYMOUS:
            return "STATUS_CANT_OPEN_ANONYMOUS";
        case STATUS_BAD_VALIDATION_CLASS:
            return "STATUS_BAD_VALIDATION_CLASS";
        case STATUS_BAD_TOKEN_TYPE:
            return "STATUS_BAD_TOKEN_TYPE";
        case STATUS_BAD_MASTER_BOOT_RECORD:
            return "STATUS_BAD_MASTER_BOOT_RECORD";
        case STATUS_INSTRUCTION_MISALIGNMENT:
            return "STATUS_INSTRUCTION_MISALIGNMENT";
        case STATUS_INSTANCE_NOT_AVAILABLE:
            return "STATUS_INSTANCE_NOT_AVAILABLE";
        case STATUS_PIPE_NOT_AVAILABLE:
            return "STATUS_PIPE_NOT_AVAILABLE";
        case STATUS_INVALID_PIPE_STATE:
            return "STATUS_INVALID_PIPE_STATE";
        case STATUS_PIPE_BUSY:
            return "STATUS_PIPE_BUSY";
        case STATUS_ILLEGAL_FUNCTION:
            return "STATUS_ILLEGAL_FUNCTION";
        case STATUS_PIPE_DISCONNECTED:
            return "STATUS_PIPE_DISCONNECTED";
        case STATUS_PIPE_CLOSING:
            return "STATUS_PIPE_CLOSING";
        case STATUS_PIPE_CONNECTED:
            return "STATUS_PIPE_CONNECTED";
        case STATUS_PIPE_LISTENING:
            return "STATUS_PIPE_LISTENING";
        case STATUS_INVALID_READ_MODE:
            return "STATUS_INVALID_READ_MODE";
        case STATUS_IO_TIMEOUT:
            return "STATUS_IO_TIMEOUT";
        case STATUS_FILE_FORCED_CLOSED:
            return "STATUS_FILE_FORCED_CLOSED";
        case STATUS_PROFILING_NOT_STARTED:
            return "STATUS_PROFILING_NOT_STARTED";
        case STATUS_PROFILING_NOT_STOPPED:
            return "STATUS_PROFILING_NOT_STOPPED";
        case STATUS_COULD_NOT_INTERPRET:
            return "STATUS_COULD_NOT_INTERPRET";
        case STATUS_FILE_IS_A_DIRECTORY:
            return "STATUS_FILE_IS_A_DIRECTORY";
        case STATUS_NOT_SUPPORTED:
            return "STATUS_NOT_SUPPORTED";
        case STATUS_REMOTE_NOT_LISTENING:
            return "STATUS_REMOTE_NOT_LISTENING";
        case STATUS_DUPLICATE_NAME:
            return "STATUS_DUPLICATE_NAME";
        case STATUS_BAD_NETWORK_PATH:
            return "STATUS_BAD_NETWORK_PATH";
        case STATUS_NETWORK_BUSY:
            return "STATUS_NETWORK_BUSY";
        case STATUS_DEVICE_DOES_NOT_EXIST:
            return "STATUS_DEVICE_DOES_NOT_EXIST";
        case STATUS_TOO_MANY_COMMANDS:
            return "STATUS_TOO_MANY_COMMANDS";
        case STATUS_ADAPTER_HARDWARE_ERROR:
            return "STATUS_ADAPTER_HARDWARE_ERROR";
        case STATUS_INVALID_NETWORK_RESPONSE:
            return "STATUS_INVALID_NETWORK_RESPONSE";
        case STATUS_UNEXPECTED_NETWORK_ERROR:
            return "STATUS_UNEXPECTED_NETWORK_ERROR";
        case STATUS_BAD_REMOTE_ADAPTER:
            return "STATUS_BAD_REMOTE_ADAPTER";
        case STATUS_PRINT_QUEUE_FULL:
            return "STATUS_PRINT_QUEUE_FULL";
        case STATUS_NO_SPOOL_SPACE:
            return "STATUS_NO_SPOOL_SPACE";
        case STATUS_PRINT_CANCELLED:
            return "STATUS_PRINT_CANCELLED";
        case STATUS_NETWORK_NAME_DELETED:
            return "STATUS_NETWORK_NAME_DELETED";
        case STATUS_NETWORK_ACCESS_DENIED:
            return "STATUS_NETWORK_ACCESS_DENIED";
        case STATUS_BAD_DEVICE_TYPE:
            return "STATUS_BAD_DEVICE_TYPE";
        case STATUS_BAD_NETWORK_NAME:
            return "STATUS_BAD_NETWORK_NAME";
        case STATUS_TOO_MANY_NAMES:
            return "STATUS_TOO_MANY_NAMES";
        case STATUS_TOO_MANY_SESSIONS:
            return "STATUS_TOO_MANY_SESSIONS";
        case STATUS_SHARING_PAUSED:
            return "STATUS_SHARING_PAUSED";
        case STATUS_REQUEST_NOT_ACCEPTED:
            return "STATUS_REQUEST_NOT_ACCEPTED";
        case STATUS_REDIRECTOR_PAUSED:
            return "STATUS_REDIRECTOR_PAUSED";
        case STATUS_NET_WRITE_FAULT:
            return "STATUS_NET_WRITE_FAULT";
        case STATUS_PROFILING_AT_LIMIT:
            return "STATUS_PROFILING_AT_LIMIT";
        case STATUS_NOT_SAME_DEVICE:
            return "STATUS_NOT_SAME_DEVICE";
        case STATUS_FILE_RENAMED:
            return "STATUS_FILE_RENAMED";
        case STATUS_VIRTUAL_CIRCUIT_CLOSED:
            return "STATUS_VIRTUAL_CIRCUIT_CLOSED";
        case STATUS_NO_SECURITY_ON_OBJECT:
            return "STATUS_NO_SECURITY_ON_OBJECT";
        case STATUS_CANT_WAIT:
            return "STATUS_CANT_WAIT";
        case STATUS_PIPE_EMPTY:
            return "STATUS_PIPE_EMPTY";
        case STATUS_CANT_ACCESS_DOMAIN_INFO:
            return "STATUS_CANT_ACCESS_DOMAIN_INFO";
        case STATUS_CANT_TERMINATE_SELF:
            return "STATUS_CANT_TERMINATE_SELF";
        case STATUS_INVALID_SERVER_STATE:
            return "STATUS_INVALID_SERVER_STATE";
        case STATUS_INVALID_DOMAIN_STATE:
            return "STATUS_INVALID_DOMAIN_STATE";
        case STATUS_INVALID_DOMAIN_ROLE:
            return "STATUS_INVALID_DOMAIN_ROLE";
        case STATUS_NO_SUCH_DOMAIN:
            return "STATUS_NO_SUCH_DOMAIN";
        case STATUS_DOMAIN_EXISTS:
            return "STATUS_DOMAIN_EXISTS";
        case STATUS_DOMAIN_LIMIT_EXCEEDED:
            return "STATUS_DOMAIN_LIMIT_EXCEEDED";
        case STATUS_OPLOCK_NOT_GRANTED:
            return "STATUS_OPLOCK_NOT_GRANTED";
        case STATUS_INVALID_OPLOCK_PROTOCOL:
            return "STATUS_INVALID_OPLOCK_PROTOCOL";
        case STATUS_INTERNAL_DB_CORRUPTION:
            return "STATUS_INTERNAL_DB_CORRUPTION";
        case STATUS_INTERNAL_ERROR:
            return "STATUS_INTERNAL_ERROR";
        case STATUS_GENERIC_NOT_MAPPED:
            return "STATUS_GENERIC_NOT_MAPPED";
        case STATUS_BAD_DESCRIPTOR_FORMAT:
            return "STATUS_BAD_DESCRIPTOR_FORMAT";
        case STATUS_INVALID_USER_BUFFER:
            return "STATUS_INVALID_USER_BUFFER";
        case STATUS_UNEXPECTED_IO_ERROR:
            return "STATUS_UNEXPECTED_IO_ERROR";
        case STATUS_UNEXPECTED_MM_CREATE_ERR:
            return "STATUS_UNEXPECTED_MM_CREATE_ERR";
        case STATUS_UNEXPECTED_MM_MAP_ERROR:
            return "STATUS_UNEXPECTED_MM_MAP_ERROR";
        case STATUS_UNEXPECTED_MM_EXTEND_ERR:
            return "STATUS_UNEXPECTED_MM_EXTEND_ERR";
        case STATUS_NOT_LOGON_PROCESS:
            return "STATUS_NOT_LOGON_PROCESS";
        case STATUS_LOGON_SESSION_EXISTS:
            return "STATUS_LOGON_SESSION_EXISTS";
        case STATUS_INVALID_PARAMETER_1:
            return "STATUS_INVALID_PARAMETER_1";
        case STATUS_INVALID_PARAMETER_2:
            return "STATUS_INVALID_PARAMETER_2";
        case STATUS_INVALID_PARAMETER_3:
            return "STATUS_INVALID_PARAMETER_3";
        case STATUS_INVALID_PARAMETER_4:
            return "STATUS_INVALID_PARAMETER_4";
        case STATUS_INVALID_PARAMETER_5:
            return "STATUS_INVALID_PARAMETER_5";
        case STATUS_INVALID_PARAMETER_6:
            return "STATUS_INVALID_PARAMETER_6";
        case STATUS_INVALID_PARAMETER_7:
            return "STATUS_INVALID_PARAMETER_7";
        case STATUS_INVALID_PARAMETER_8:
            return "STATUS_INVALID_PARAMETER_8";
        case STATUS_INVALID_PARAMETER_9:
            return "STATUS_INVALID_PARAMETER_9";
        case STATUS_INVALID_PARAMETER_10:
            return "STATUS_INVALID_PARAMETER_10";
        case STATUS_INVALID_PARAMETER_11:
            return "STATUS_INVALID_PARAMETER_11";
        case STATUS_INVALID_PARAMETER_12:
            return "STATUS_INVALID_PARAMETER_12";
        case STATUS_REDIRECTOR_NOT_STARTED:
            return "STATUS_REDIRECTOR_NOT_STARTED";
        case STATUS_REDIRECTOR_STARTED:
            return "STATUS_REDIRECTOR_STARTED";
        case STATUS_STACK_OVERFLOW:
            return "STATUS_STACK_OVERFLOW";
        case STATUS_NO_SUCH_PACKAGE:
            return "STATUS_NO_SUCH_PACKAGE";
        case STATUS_BAD_FUNCTION_TABLE:
            return "STATUS_BAD_FUNCTION_TABLE";
        case STATUS_VARIABLE_NOT_FOUND:
            return "STATUS_VARIABLE_NOT_FOUND";
        case STATUS_DIRECTORY_NOT_EMPTY:
            return "STATUS_DIRECTORY_NOT_EMPTY";
        case STATUS_FILE_CORRUPT_ERROR:
            return "STATUS_FILE_CORRUPT_ERROR";
        case STATUS_NOT_A_DIRECTORY:
            return "STATUS_NOT_A_DIRECTORY";
        case STATUS_BAD_LOGON_SESSION_STATE:
            return "STATUS_BAD_LOGON_SESSION_STATE";
        case STATUS_LOGON_SESSION_COLLISION:
            return "STATUS_LOGON_SESSION_COLLISION";
        case STATUS_NAME_TOO_LONG:
            return "STATUS_NAME_TOO_LONG";
        case STATUS_FILES_OPEN:
            return "STATUS_FILES_OPEN";
        case STATUS_CONNECTION_IN_USE:
            return "STATUS_CONNECTION_IN_USE";
        case STATUS_MESSAGE_NOT_FOUND:
            return "STATUS_MESSAGE_NOT_FOUND";
        case STATUS_PROCESS_IS_TERMINATING:
            return "STATUS_PROCESS_IS_TERMINATING";
        case STATUS_INVALID_LOGON_TYPE:
            return "STATUS_INVALID_LOGON_TYPE";
        case STATUS_NO_GUID_TRANSLATION:
            return "STATUS_NO_GUID_TRANSLATION";
        case STATUS_CANNOT_IMPERSONATE:
            return "STATUS_CANNOT_IMPERSONATE";
        case STATUS_IMAGE_ALREADY_LOADED:
            return "STATUS_IMAGE_ALREADY_LOADED";
        case STATUS_NO_LDT:
            return "STATUS_NO_LDT";
        case STATUS_INVALID_LDT_SIZE:
            return "STATUS_INVALID_LDT_SIZE";
        case STATUS_INVALID_LDT_OFFSET:
            return "STATUS_INVALID_LDT_OFFSET";
        case STATUS_INVALID_LDT_DESCRIPTOR:
            return "STATUS_INVALID_LDT_DESCRIPTOR";
        case STATUS_INVALID_IMAGE_NE_FORMAT:
            return "STATUS_INVALID_IMAGE_NE_FORMAT";
        case STATUS_RXACT_INVALID_STATE:
            return "STATUS_RXACT_INVALID_STATE";
        case STATUS_RXACT_COMMIT_FAILURE:
            return "STATUS_RXACT_COMMIT_FAILURE";
        case STATUS_MAPPED_FILE_SIZE_ZERO:
            return "STATUS_MAPPED_FILE_SIZE_ZERO";
        case STATUS_TOO_MANY_OPENED_FILES:
            return "STATUS_TOO_MANY_OPENED_FILES";
        case STATUS_CANCELLED:
            return "STATUS_CANCELLED";
        case STATUS_CANNOT_DELETE:
            return "STATUS_CANNOT_DELETE";
        case STATUS_INVALID_COMPUTER_NAME:
            return "STATUS_INVALID_COMPUTER_NAME";
        case STATUS_FILE_DELETED:
            return "STATUS_FILE_DELETED";
        case STATUS_SPECIAL_ACCOUNT:
            return "STATUS_SPECIAL_ACCOUNT";
        case STATUS_SPECIAL_GROUP:
            return "STATUS_SPECIAL_GROUP";
        case STATUS_SPECIAL_USER:
            return "STATUS_SPECIAL_USER";
        case STATUS_MEMBERS_PRIMARY_GROUP:
            return "STATUS_MEMBERS_PRIMARY_GROUP";
        case STATUS_FILE_CLOSED:
            return "STATUS_FILE_CLOSED";
        case STATUS_TOO_MANY_THREADS:
            return "STATUS_TOO_MANY_THREADS";
        case STATUS_THREAD_NOT_IN_PROCESS:
            return "STATUS_THREAD_NOT_IN_PROCESS";
        case STATUS_TOKEN_ALREADY_IN_USE:
            return "STATUS_TOKEN_ALREADY_IN_USE";
        case STATUS_PAGEFILE_QUOTA_EXCEEDED:
            return "STATUS_PAGEFILE_QUOTA_EXCEEDED";
        case STATUS_COMMITMENT_LIMIT:
            return "STATUS_COMMITMENT_LIMIT";
        case STATUS_INVALID_IMAGE_LE_FORMAT:
            return "STATUS_INVALID_IMAGE_LE_FORMAT";
        case STATUS_INVALID_IMAGE_NOT_MZ:
            return "STATUS_INVALID_IMAGE_NOT_MZ";
        case STATUS_INVALID_IMAGE_PROTECT:
            return "STATUS_INVALID_IMAGE_PROTECT";
        case STATUS_INVALID_IMAGE_WIN_16:
            return "STATUS_INVALID_IMAGE_WIN_16";
        case STATUS_LOGON_SERVER_CONFLICT:
            return "STATUS_LOGON_SERVER_CONFLICT";
        case STATUS_TIME_DIFFERENCE_AT_DC:
            return "STATUS_TIME_DIFFERENCE_AT_DC";
        case STATUS_SYNCHRONIZATION_REQUIRED:
            return "STATUS_SYNCHRONIZATION_REQUIRED";
        case STATUS_DLL_NOT_FOUND:
            return "STATUS_DLL_NOT_FOUND";
        case STATUS_OPEN_FAILED:
            return "STATUS_OPEN_FAILED";
        case STATUS_IO_PRIVILEGE_FAILED:
            return "STATUS_IO_PRIVILEGE_FAILED";
        case STATUS_ORDINAL_NOT_FOUND:
            return "STATUS_ORDINAL_NOT_FOUND";
        case STATUS_ENTRYPOINT_NOT_FOUND:
            return "STATUS_ENTRYPOINT_NOT_FOUND";
        case STATUS_CONTROL_C_EXIT:
            return "STATUS_CONTROL_C_EXIT";
        case STATUS_LOCAL_DISCONNECT:
            return "STATUS_LOCAL_DISCONNECT";
        case STATUS_REMOTE_DISCONNECT:
            return "STATUS_REMOTE_DISCONNECT";
        case STATUS_REMOTE_RESOURCES:
            return "STATUS_REMOTE_RESOURCES";
        case STATUS_LINK_FAILED:
            return "STATUS_LINK_FAILED";
        case STATUS_LINK_TIMEOUT:
            return "STATUS_LINK_TIMEOUT";
        case STATUS_INVALID_CONNECTION:
            return "STATUS_INVALID_CONNECTION";
        case STATUS_INVALID_ADDRESS:
            return "STATUS_INVALID_ADDRESS";
        case STATUS_DLL_INIT_FAILED:
            return "STATUS_DLL_INIT_FAILED";
        case STATUS_MISSING_SYSTEMFILE:
            return "STATUS_MISSING_SYSTEMFILE";
        case STATUS_UNHANDLED_EXCEPTION:
            return "STATUS_UNHANDLED_EXCEPTION";
        case STATUS_APP_INIT_FAILURE:
            return "STATUS_APP_INIT_FAILURE";
        case STATUS_PAGEFILE_CREATE_FAILED:
            return "STATUS_PAGEFILE_CREATE_FAILED";
        case STATUS_NO_PAGEFILE:
            return "STATUS_NO_PAGEFILE";
        case STATUS_INVALID_LEVEL:
            return "STATUS_INVALID_LEVEL";
        case STATUS_WRONG_PASSWORD_CORE:
            return "STATUS_WRONG_PASSWORD_CORE";
        case STATUS_ILLEGAL_FLOAT_CONTEXT:
            return "STATUS_ILLEGAL_FLOAT_CONTEXT";
        case STATUS_PIPE_BROKEN:
            return "STATUS_PIPE_BROKEN";
        case STATUS_REGISTRY_CORRUPT:
            return "STATUS_REGISTRY_CORRUPT";
        case STATUS_REGISTRY_IO_FAILED:
            return "STATUS_REGISTRY_IO_FAILED";
        case STATUS_NO_EVENT_PAIR:
            return "STATUS_NO_EVENT_PAIR";
        case STATUS_UNRECOGNIZED_VOLUME:
            return "STATUS_UNRECOGNIZED_VOLUME";
        case STATUS_SERIAL_NO_DEVICE_INITED:
            return "STATUS_SERIAL_NO_DEVICE_INITED";
        case STATUS_NO_SUCH_ALIAS:
            return "STATUS_NO_SUCH_ALIAS";
        case STATUS_MEMBER_NOT_IN_ALIAS:
            return "STATUS_MEMBER_NOT_IN_ALIAS";
        case STATUS_MEMBER_IN_ALIAS:
            return "STATUS_MEMBER_IN_ALIAS";
        case STATUS_ALIAS_EXISTS:
            return "STATUS_ALIAS_EXISTS";
        case STATUS_LOGON_NOT_GRANTED:
            return "STATUS_LOGON_NOT_GRANTED";
        case STATUS_TOO_MANY_SECRETS:
            return "STATUS_TOO_MANY_SECRETS";
        case STATUS_SECRET_TOO_LONG:
            return "STATUS_SECRET_TOO_LONG";
        case STATUS_INTERNAL_DB_ERROR:
            return "STATUS_INTERNAL_DB_ERROR";
        case STATUS_FULLSCREEN_MODE:
            return "STATUS_FULLSCREEN_MODE";
        case STATUS_TOO_MANY_CONTEXT_IDS:
            return "STATUS_TOO_MANY_CONTEXT_IDS";
        case STATUS_LOGON_TYPE_NOT_GRANTED:
            return "STATUS_LOGON_TYPE_NOT_GRANTED";
        case STATUS_NOT_REGISTRY_FILE:
            return "STATUS_NOT_REGISTRY_FILE";
        case STATUS_NT_CROSS_ENCRYPTION_REQUIRED:
            return "STATUS_NT_CROSS_ENCRYPTION_REQUIRED";
        case STATUS_DOMAIN_CTRLR_CONFIG_ERROR:
            return "STATUS_DOMAIN_CTRLR_CONFIG_ERROR";
        case STATUS_FT_MISSING_MEMBER:
            return "STATUS_FT_MISSING_MEMBER";
        case STATUS_ILL_FORMED_SERVICE_ENTRY:
            return "STATUS_ILL_FORMED_SERVICE_ENTRY";
        case STATUS_ILLEGAL_CHARACTER:
            return "STATUS_ILLEGAL_CHARACTER";
        case STATUS_UNMAPPABLE_CHARACTER:
            return "STATUS_UNMAPPABLE_CHARACTER";
        case STATUS_UNDEFINED_CHARACTER:
            return "STATUS_UNDEFINED_CHARACTER";
        case STATUS_FLOPPY_VOLUME:
            return "STATUS_FLOPPY_VOLUME";
        case STATUS_FLOPPY_ID_MARK_NOT_FOUND:
            return "STATUS_FLOPPY_ID_MARK_NOT_FOUND";
        case STATUS_FLOPPY_WRONG_CYLINDER:
            return "STATUS_FLOPPY_WRONG_CYLINDER";
        case STATUS_FLOPPY_UNKNOWN_ERROR:
            return "STATUS_FLOPPY_UNKNOWN_ERROR";
        case STATUS_FLOPPY_BAD_REGISTERS:
            return "STATUS_FLOPPY_BAD_REGISTERS";
        case STATUS_DISK_RECALIBRATE_FAILED:
            return "STATUS_DISK_RECALIBRATE_FAILED";
        case STATUS_DISK_OPERATION_FAILED:
            return "STATUS_DISK_OPERATION_FAILED";
        case STATUS_DISK_RESET_FAILED:
            return "STATUS_DISK_RESET_FAILED";
        case STATUS_SHARED_IRQ_BUSY:
            return "STATUS_SHARED_IRQ_BUSY";
        case STATUS_FT_ORPHANING:
            return "STATUS_FT_ORPHANING";
        case STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT:
            return "STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT";
        case STATUS_PARTITION_FAILURE:
            return "STATUS_PARTITION_FAILURE";
        case STATUS_INVALID_BLOCK_LENGTH:
            return "STATUS_INVALID_BLOCK_LENGTH";
        case STATUS_DEVICE_NOT_PARTITIONED:
            return "STATUS_DEVICE_NOT_PARTITIONED";
        case STATUS_UNABLE_TO_LOCK_MEDIA:
            return "STATUS_UNABLE_TO_LOCK_MEDIA";
        case STATUS_UNABLE_TO_UNLOAD_MEDIA:
            return "STATUS_UNABLE_TO_UNLOAD_MEDIA";
        case STATUS_EOM_OVERFLOW:
            return "STATUS_EOM_OVERFLOW";
        case STATUS_NO_MEDIA:
            return "STATUS_NO_MEDIA";
        case STATUS_NO_SUCH_MEMBER:
            return "STATUS_NO_SUCH_MEMBER";
        case STATUS_INVALID_MEMBER:
            return "STATUS_INVALID_MEMBER";
        case STATUS_KEY_DELETED:
            return "STATUS_KEY_DELETED";
        case STATUS_NO_LOG_SPACE:
            return "STATUS_NO_LOG_SPACE";
        case STATUS_TOO_MANY_SIDS:
            return "STATUS_TOO_MANY_SIDS";
        case STATUS_LM_CROSS_ENCRYPTION_REQUIRED:
            return "STATUS_LM_CROSS_ENCRYPTION_REQUIRED";
        case STATUS_KEY_HAS_CHILDREN:
            return "STATUS_KEY_HAS_CHILDREN";
        case STATUS_CHILD_MUST_BE_VOLATILE:
            return "STATUS_CHILD_MUST_BE_VOLATILE";
        case STATUS_DEVICE_CONFIGURATION_ERROR:
            return "STATUS_DEVICE_CONFIGURATION_ERROR";
        case STATUS_DRIVER_INTERNAL_ERROR:
            return "STATUS_DRIVER_INTERNAL_ERROR";
        case STATUS_INVALID_DEVICE_STATE:
            return "STATUS_INVALID_DEVICE_STATE";
        case STATUS_IO_DEVICE_ERROR:
            return "STATUS_IO_DEVICE_ERROR";
        case STATUS_DEVICE_PROTOCOL_ERROR:
            return "STATUS_DEVICE_PROTOCOL_ERROR";
        case STATUS_BACKUP_CONTROLLER:
            return "STATUS_BACKUP_CONTROLLER";
        case STATUS_LOG_FILE_FULL:
            return "STATUS_LOG_FILE_FULL";
        case STATUS_TOO_LATE:
            return "STATUS_TOO_LATE";
        case STATUS_NO_TRUST_LSA_SECRET:
            return "STATUS_NO_TRUST_LSA_SECRET";
        case STATUS_NO_TRUST_SAM_ACCOUNT:
            return "STATUS_NO_TRUST_SAM_ACCOUNT";
        case STATUS_TRUSTED_DOMAIN_FAILURE:
            return "STATUS_TRUSTED_DOMAIN_FAILURE";
        case STATUS_TRUSTED_RELATIONSHIP_FAILURE:
            return "STATUS_TRUSTED_RELATIONSHIP_FAILURE";
        case STATUS_EVENTLOG_FILE_CORRUPT:
            return "STATUS_EVENTLOG_FILE_CORRUPT";
        case STATUS_EVENTLOG_CANT_START:
            return "STATUS_EVENTLOG_CANT_START";
        case STATUS_TRUST_FAILURE:
            return "STATUS_TRUST_FAILURE";
        case STATUS_MUTANT_LIMIT_EXCEEDED:
            return "STATUS_MUTANT_LIMIT_EXCEEDED";
        case STATUS_NETLOGON_NOT_STARTED:
            return "STATUS_NETLOGON_NOT_STARTED";
        case STATUS_ACCOUNT_EXPIRED:
            return "STATUS_ACCOUNT_EXPIRED";
        case STATUS_POSSIBLE_DEADLOCK:
            return "STATUS_POSSIBLE_DEADLOCK";
        case STATUS_NETWORK_CREDENTIAL_CONFLICT:
            return "STATUS_NETWORK_CREDENTIAL_CONFLICT";
        case STATUS_REMOTE_SESSION_LIMIT:
            return "STATUS_REMOTE_SESSION_LIMIT";
        case STATUS_EVENTLOG_FILE_CHANGED:
            return "STATUS_EVENTLOG_FILE_CHANGED";
        case STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT:
            return "STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT";
        case STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT:
            return "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT";
        case STATUS_NOLOGON_SERVER_TRUST_ACCOUNT:
            return "STATUS_NOLOGON_SERVER_TRUST_ACCOUNT";
        case STATUS_DOMAIN_TRUST_INCONSISTENT:
            return "STATUS_DOMAIN_TRUST_INCONSISTENT";
        case STATUS_FS_DRIVER_REQUIRED:
            return "STATUS_FS_DRIVER_REQUIRED";
        case STATUS_IMAGE_ALREADY_LOADED_AS_DLL:
            return "STATUS_IMAGE_ALREADY_LOADED_AS_DLL";
        case STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING:
            return "STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING";
        case STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME:
            return "STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME";
        case STATUS_SECURITY_STREAM_IS_INCONSISTENT:
            return "STATUS_SECURITY_STREAM_IS_INCONSISTENT";
        case STATUS_INVALID_LOCK_RANGE:
            return "STATUS_INVALID_LOCK_RANGE";
        case STATUS_INVALID_ACE_CONDITION:
            return "STATUS_INVALID_ACE_CONDITION";
        case STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT:
            return "STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT";
        case STATUS_NOTIFICATION_GUID_ALREADY_DEFINED:
            return "STATUS_NOTIFICATION_GUID_ALREADY_DEFINED";
        case STATUS_NETWORK_OPEN_RESTRICTION:
            return "STATUS_NETWORK_OPEN_RESTRICTION";
        case STATUS_NO_USER_SESSION_KEY:
            return "STATUS_NO_USER_SESSION_KEY";
        case STATUS_USER_SESSION_DELETED:
            return "STATUS_USER_SESSION_DELETED";
        case STATUS_RESOURCE_LANG_NOT_FOUND:
            return "STATUS_RESOURCE_LANG_NOT_FOUND";
        case STATUS_INSUFF_SERVER_RESOURCES:
            return "STATUS_INSUFF_SERVER_RESOURCES";
        case STATUS_INVALID_BUFFER_SIZE:
            return "STATUS_INVALID_BUFFER_SIZE";
        case STATUS_INVALID_ADDRESS_COMPONENT:
            return "STATUS_INVALID_ADDRESS_COMPONENT";
        case STATUS_INVALID_ADDRESS_WILDCARD:
            return "STATUS_INVALID_ADDRESS_WILDCARD";
        case STATUS_TOO_MANY_ADDRESSES:
            return "STATUS_TOO_MANY_ADDRESSES";
        case STATUS_ADDRESS_ALREADY_EXISTS:
            return "STATUS_ADDRESS_ALREADY_EXISTS";
        case STATUS_ADDRESS_CLOSED:
            return "STATUS_ADDRESS_CLOSED";
        case STATUS_CONNECTION_DISCONNECTED:
            return "STATUS_CONNECTION_DISCONNECTED";
        case STATUS_CONNECTION_RESET:
            return "STATUS_CONNECTION_RESET";
        case STATUS_TOO_MANY_NODES:
            return "STATUS_TOO_MANY_NODES";
        case STATUS_TRANSACTION_ABORTED:
            return "STATUS_TRANSACTION_ABORTED";
        case STATUS_TRANSACTION_TIMED_OUT:
            return "STATUS_TRANSACTION_TIMED_OUT";
        case STATUS_TRANSACTION_NO_RELEASE:
            return "STATUS_TRANSACTION_NO_RELEASE";
        case STATUS_TRANSACTION_NO_MATCH:
            return "STATUS_TRANSACTION_NO_MATCH";
        case STATUS_TRANSACTION_RESPONDED:
            return "STATUS_TRANSACTION_RESPONDED";
        case STATUS_TRANSACTION_INVALID_ID:
            return "STATUS_TRANSACTION_INVALID_ID";
        case STATUS_TRANSACTION_INVALID_TYPE:
            return "STATUS_TRANSACTION_INVALID_TYPE";
        case STATUS_NOT_SERVER_SESSION:
            return "STATUS_NOT_SERVER_SESSION";
        case STATUS_NOT_CLIENT_SESSION:
            return "STATUS_NOT_CLIENT_SESSION";
        case STATUS_CANNOT_LOAD_REGISTRY_FILE:
            return "STATUS_CANNOT_LOAD_REGISTRY_FILE";
        case STATUS_DEBUG_ATTACH_FAILED:
            return "STATUS_DEBUG_ATTACH_FAILED";
        case STATUS_SYSTEM_PROCESS_TERMINATED:
            return "STATUS_SYSTEM_PROCESS_TERMINATED";
        case STATUS_DATA_NOT_ACCEPTED:
            return "STATUS_DATA_NOT_ACCEPTED";
        case STATUS_NO_BROWSER_SERVERS_FOUND:
            return "STATUS_NO_BROWSER_SERVERS_FOUND";
        case STATUS_VDM_HARD_ERROR:
            return "STATUS_VDM_HARD_ERROR";
        case STATUS_DRIVER_CANCEL_TIMEOUT:
            return "STATUS_DRIVER_CANCEL_TIMEOUT";
        case STATUS_REPLY_MESSAGE_MISMATCH:
            return "STATUS_REPLY_MESSAGE_MISMATCH";
        case STATUS_MAPPED_ALIGNMENT:
            return "STATUS_MAPPED_ALIGNMENT";
        case STATUS_IMAGE_CHECKSUM_MISMATCH:
            return "STATUS_IMAGE_CHECKSUM_MISMATCH";
        case STATUS_LOST_WRITEBEHIND_DATA:
            return "STATUS_LOST_WRITEBEHIND_DATA";
        case STATUS_CLIENT_SERVER_PARAMETERS_INVALID:
            return "STATUS_CLIENT_SERVER_PARAMETERS_INVALID";
        case STATUS_PASSWORD_MUST_CHANGE:
            return "STATUS_PASSWORD_MUST_CHANGE";
        case STATUS_NOT_FOUND:
            return "STATUS_NOT_FOUND";
        case STATUS_NOT_TINY_STREAM:
            return "STATUS_NOT_TINY_STREAM";
        case STATUS_RECOVERY_FAILURE:
            return "STATUS_RECOVERY_FAILURE";
        case STATUS_STACK_OVERFLOW_READ:
            return "STATUS_STACK_OVERFLOW_READ";
        case STATUS_FAIL_CHECK:
            return "STATUS_FAIL_CHECK";
        case STATUS_DUPLICATE_OBJECTID:
            return "STATUS_DUPLICATE_OBJECTID";
        case STATUS_OBJECTID_EXISTS:
            return "STATUS_OBJECTID_EXISTS";
        case STATUS_CONVERT_TO_LARGE:
            return "STATUS_CONVERT_TO_LARGE";
        case STATUS_RETRY:
            return "STATUS_RETRY";
        case STATUS_FOUND_OUT_OF_SCOPE:
            return "STATUS_FOUND_OUT_OF_SCOPE";
        case STATUS_ALLOCATE_BUCKET:
            return "STATUS_ALLOCATE_BUCKET";
        case STATUS_PROPSET_NOT_FOUND:
            return "STATUS_PROPSET_NOT_FOUND";
        case STATUS_MARSHALL_OVERFLOW:
            return "STATUS_MARSHALL_OVERFLOW";
        case STATUS_INVALID_VARIANT:
            return "STATUS_INVALID_VARIANT";
        case STATUS_DOMAIN_CONTROLLER_NOT_FOUND:
            return "STATUS_DOMAIN_CONTROLLER_NOT_FOUND";
        case STATUS_ACCOUNT_LOCKED_OUT:
            return "STATUS_ACCOUNT_LOCKED_OUT";
        case STATUS_HANDLE_NOT_CLOSABLE:
            return "STATUS_HANDLE_NOT_CLOSABLE";
        case STATUS_CONNECTION_REFUSED:
            return "STATUS_CONNECTION_REFUSED";
        case STATUS_GRACEFUL_DISCONNECT:
            return "STATUS_GRACEFUL_DISCONNECT";
        case STATUS_ADDRESS_ALREADY_ASSOCIATED:
            return "STATUS_ADDRESS_ALREADY_ASSOCIATED";
        case STATUS_ADDRESS_NOT_ASSOCIATED:
            return "STATUS_ADDRESS_NOT_ASSOCIATED";
        case STATUS_CONNECTION_INVALID:
            return "STATUS_CONNECTION_INVALID";
        case STATUS_CONNECTION_ACTIVE:
            return "STATUS_CONNECTION_ACTIVE";
        case STATUS_NETWORK_UNREACHABLE:
            return "STATUS_NETWORK_UNREACHABLE";
        case STATUS_HOST_UNREACHABLE:
            return "STATUS_HOST_UNREACHABLE";
        case STATUS_PROTOCOL_UNREACHABLE:
            return "STATUS_PROTOCOL_UNREACHABLE";
        case STATUS_PORT_UNREACHABLE:
            return "STATUS_PORT_UNREACHABLE";
        case STATUS_REQUEST_ABORTED:
            return "STATUS_REQUEST_ABORTED";
        case STATUS_CONNECTION_ABORTED:
            return "STATUS_CONNECTION_ABORTED";
        case STATUS_BAD_COMPRESSION_BUFFER:
            return "STATUS_BAD_COMPRESSION_BUFFER";
        case STATUS_USER_MAPPED_FILE:
            return "STATUS_USER_MAPPED_FILE";
        case STATUS_AUDIT_FAILED:
            return "STATUS_AUDIT_FAILED";
        case STATUS_TIMER_RESOLUTION_NOT_SET:
            return "STATUS_TIMER_RESOLUTION_NOT_SET";
        case STATUS_CONNECTION_COUNT_LIMIT:
            return "STATUS_CONNECTION_COUNT_LIMIT";
        case STATUS_LOGIN_TIME_RESTRICTION:
            return "STATUS_LOGIN_TIME_RESTRICTION";
        case STATUS_LOGIN_WKSTA_RESTRICTION:
            return "STATUS_LOGIN_WKSTA_RESTRICTION";
        case STATUS_IMAGE_MP_UP_MISMATCH:
            return "STATUS_IMAGE_MP_UP_MISMATCH";
        case STATUS_INSUFFICIENT_LOGON_INFO:
            return "STATUS_INSUFFICIENT_LOGON_INFO";
        case STATUS_BAD_DLL_ENTRYPOINT:
            return "STATUS_BAD_DLL_ENTRYPOINT";
        case STATUS_BAD_SERVICE_ENTRYPOINT:
            return "STATUS_BAD_SERVICE_ENTRYPOINT";
        case STATUS_LPC_REPLY_LOST:
            return "STATUS_LPC_REPLY_LOST";
        case STATUS_IP_ADDRESS_CONFLICT1:
            return "STATUS_IP_ADDRESS_CONFLICT1";
        case STATUS_IP_ADDRESS_CONFLICT2:
            return "STATUS_IP_ADDRESS_CONFLICT2";
        case STATUS_REGISTRY_QUOTA_LIMIT:
            return "STATUS_REGISTRY_QUOTA_LIMIT";
        case STATUS_PATH_NOT_COVERED:
            return "STATUS_PATH_NOT_COVERED";
        case STATUS_NO_CALLBACK_ACTIVE:
            return "STATUS_NO_CALLBACK_ACTIVE";
        case STATUS_LICENSE_QUOTA_EXCEEDED:
            return "STATUS_LICENSE_QUOTA_EXCEEDED";
        case STATUS_PWD_TOO_SHORT:
            return "STATUS_PWD_TOO_SHORT";
        case STATUS_PWD_TOO_RECENT:
            return "STATUS_PWD_TOO_RECENT";
        case STATUS_PWD_HISTORY_CONFLICT:
            return "STATUS_PWD_HISTORY_CONFLICT";
        case STATUS_PLUGPLAY_NO_DEVICE:
            return "STATUS_PLUGPLAY_NO_DEVICE";
        case STATUS_UNSUPPORTED_COMPRESSION:
            return "STATUS_UNSUPPORTED_COMPRESSION";
        case STATUS_INVALID_HW_PROFILE:
            return "STATUS_INVALID_HW_PROFILE";
        case STATUS_INVALID_PLUGPLAY_DEVICE_PATH:
            return "STATUS_INVALID_PLUGPLAY_DEVICE_PATH";
        case STATUS_DRIVER_ORDINAL_NOT_FOUND:
            return "STATUS_DRIVER_ORDINAL_NOT_FOUND";
        case STATUS_DRIVER_ENTRYPOINT_NOT_FOUND:
            return "STATUS_DRIVER_ENTRYPOINT_NOT_FOUND";
        case STATUS_RESOURCE_NOT_OWNED:
            return "STATUS_RESOURCE_NOT_OWNED";
        case STATUS_TOO_MANY_LINKS:
            return "STATUS_TOO_MANY_LINKS";
        case STATUS_QUOTA_LIST_INCONSISTENT:
            return "STATUS_QUOTA_LIST_INCONSISTENT";
        case STATUS_FILE_IS_OFFLINE:
            return "STATUS_FILE_IS_OFFLINE";
        case STATUS_EVALUATION_EXPIRATION:
            return "STATUS_EVALUATION_EXPIRATION";
        case STATUS_ILLEGAL_DLL_RELOCATION:
            return "STATUS_ILLEGAL_DLL_RELOCATION";
        case STATUS_LICENSE_VIOLATION:
            return "STATUS_LICENSE_VIOLATION";
        case STATUS_DLL_INIT_FAILED_LOGOFF:
            return "STATUS_DLL_INIT_FAILED_LOGOFF";
        case STATUS_DRIVER_UNABLE_TO_LOAD:
            return "STATUS_DRIVER_UNABLE_TO_LOAD";
        case STATUS_DFS_UNAVAILABLE:
            return "STATUS_DFS_UNAVAILABLE";
        case STATUS_VOLUME_DISMOUNTED:
            return "STATUS_VOLUME_DISMOUNTED";
        case STATUS_WX86_INTERNAL_ERROR:
            return "STATUS_WX86_INTERNAL_ERROR";
        case STATUS_WX86_FLOAT_STACK_CHECK:
            return "STATUS_WX86_FLOAT_STACK_CHECK";
        case STATUS_VALIDATE_CONTINUE:
            return "STATUS_VALIDATE_CONTINUE";
        case STATUS_NO_MATCH:
            return "STATUS_NO_MATCH";
        case STATUS_NO_MORE_MATCHES:
            return "STATUS_NO_MORE_MATCHES";
        case STATUS_NOT_A_REPARSE_POINT:
            return "STATUS_NOT_A_REPARSE_POINT";
        case STATUS_IO_REPARSE_TAG_INVALID:
            return "STATUS_IO_REPARSE_TAG_INVALID";
        case STATUS_IO_REPARSE_TAG_MISMATCH:
            return "STATUS_IO_REPARSE_TAG_MISMATCH";
        case STATUS_IO_REPARSE_DATA_INVALID:
            return "STATUS_IO_REPARSE_DATA_INVALID";
        case STATUS_IO_REPARSE_TAG_NOT_HANDLED:
            return "STATUS_IO_REPARSE_TAG_NOT_HANDLED";
        case STATUS_REPARSE_POINT_NOT_RESOLVED:
            return "STATUS_REPARSE_POINT_NOT_RESOLVED";
        case STATUS_DIRECTORY_IS_A_REPARSE_POINT:
            return "STATUS_DIRECTORY_IS_A_REPARSE_POINT";
        case STATUS_RANGE_LIST_CONFLICT:
            return "STATUS_RANGE_LIST_CONFLICT";
        case STATUS_SOURCE_ELEMENT_EMPTY:
            return "STATUS_SOURCE_ELEMENT_EMPTY";
        case STATUS_DESTINATION_ELEMENT_FULL:
            return "STATUS_DESTINATION_ELEMENT_FULL";
        case STATUS_ILLEGAL_ELEMENT_ADDRESS:
            return "STATUS_ILLEGAL_ELEMENT_ADDRESS";
        case STATUS_MAGAZINE_NOT_PRESENT:
            return "STATUS_MAGAZINE_NOT_PRESENT";
        case STATUS_REINITIALIZATION_NEEDED:
            return "STATUS_REINITIALIZATION_NEEDED";
        case STATUS_ENCRYPTION_FAILED:
            return "STATUS_ENCRYPTION_FAILED";
        case STATUS_DECRYPTION_FAILED:
            return "STATUS_DECRYPTION_FAILED";
        case STATUS_RANGE_NOT_FOUND:
            return "STATUS_RANGE_NOT_FOUND";
        case STATUS_NO_RECOVERY_POLICY:
            return "STATUS_NO_RECOVERY_POLICY";
        case STATUS_NO_EFS:
            return "STATUS_NO_EFS";
        case STATUS_WRONG_EFS:
            return "STATUS_WRONG_EFS";
        case STATUS_NO_USER_KEYS:
            return "STATUS_NO_USER_KEYS";
        case STATUS_FILE_NOT_ENCRYPTED:
            return "STATUS_FILE_NOT_ENCRYPTED";
        case STATUS_NOT_EXPORT_FORMAT:
            return "STATUS_NOT_EXPORT_FORMAT";
        case STATUS_FILE_ENCRYPTED:
            return "STATUS_FILE_ENCRYPTED";
        case STATUS_WMI_GUID_NOT_FOUND:
            return "STATUS_WMI_GUID_NOT_FOUND";
        case STATUS_WMI_INSTANCE_NOT_FOUND:
            return "STATUS_WMI_INSTANCE_NOT_FOUND";
        case STATUS_WMI_ITEMID_NOT_FOUND:
            return "STATUS_WMI_ITEMID_NOT_FOUND";
        case STATUS_WMI_TRY_AGAIN:
            return "STATUS_WMI_TRY_AGAIN";
        case STATUS_SHARED_POLICY:
            return "STATUS_SHARED_POLICY";
        case STATUS_POLICY_OBJECT_NOT_FOUND:
            return "STATUS_POLICY_OBJECT_NOT_FOUND";
        case STATUS_POLICY_ONLY_IN_DS:
            return "STATUS_POLICY_ONLY_IN_DS";
        case STATUS_VOLUME_NOT_UPGRADED:
            return "STATUS_VOLUME_NOT_UPGRADED";
        case STATUS_REMOTE_STORAGE_NOT_ACTIVE:
            return "STATUS_REMOTE_STORAGE_NOT_ACTIVE";
        case STATUS_REMOTE_STORAGE_MEDIA_ERROR:
            return "STATUS_REMOTE_STORAGE_MEDIA_ERROR";
        case STATUS_NO_TRACKING_SERVICE:
            return "STATUS_NO_TRACKING_SERVICE";
        case STATUS_SERVER_SID_MISMATCH:
            return "STATUS_SERVER_SID_MISMATCH";
        case STATUS_DS_NO_ATTRIBUTE_OR_VALUE:
            return "STATUS_DS_NO_ATTRIBUTE_OR_VALUE";
        case STATUS_DS_INVALID_ATTRIBUTE_SYNTAX:
            return "STATUS_DS_INVALID_ATTRIBUTE_SYNTAX";
        case STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED:
            return "STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED";
        case STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS:
            return "STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS";
        case STATUS_DS_BUSY:
            return "STATUS_DS_BUSY";
        case STATUS_DS_UNAVAILABLE:
            return "STATUS_DS_UNAVAILABLE";
        case STATUS_DS_NO_RIDS_ALLOCATED:
            return "STATUS_DS_NO_RIDS_ALLOCATED";
        case STATUS_DS_NO_MORE_RIDS:
            return "STATUS_DS_NO_MORE_RIDS";
        case STATUS_DS_INCORRECT_ROLE_OWNER:
            return "STATUS_DS_INCORRECT_ROLE_OWNER";
        case STATUS_DS_RIDMGR_INIT_ERROR:
            return "STATUS_DS_RIDMGR_INIT_ERROR";
        case STATUS_DS_OBJ_CLASS_VIOLATION:
            return "STATUS_DS_OBJ_CLASS_VIOLATION";
        case STATUS_DS_CANT_ON_NON_LEAF:
            return "STATUS_DS_CANT_ON_NON_LEAF";
        case STATUS_DS_CANT_ON_RDN:
            return "STATUS_DS_CANT_ON_RDN";
        case STATUS_DS_CANT_MOD_OBJ_CLASS:
            return "STATUS_DS_CANT_MOD_OBJ_CLASS";
        case STATUS_DS_CROSS_DOM_MOVE_FAILED:
            return "STATUS_DS_CROSS_DOM_MOVE_FAILED";
        case STATUS_DS_GC_NOT_AVAILABLE:
            return "STATUS_DS_GC_NOT_AVAILABLE";
        case STATUS_DIRECTORY_SERVICE_REQUIRED:
            return "STATUS_DIRECTORY_SERVICE_REQUIRED";
        case STATUS_REPARSE_ATTRIBUTE_CONFLICT:
            return "STATUS_REPARSE_ATTRIBUTE_CONFLICT";
        case STATUS_CANT_ENABLE_DENY_ONLY:
            return "STATUS_CANT_ENABLE_DENY_ONLY";
        case STATUS_FLOAT_MULTIPLE_FAULTS:
            return "STATUS_FLOAT_MULTIPLE_FAULTS";
        case STATUS_FLOAT_MULTIPLE_TRAPS:
            return "STATUS_FLOAT_MULTIPLE_TRAPS";
        case STATUS_DEVICE_REMOVED:
            return "STATUS_DEVICE_REMOVED";
        case STATUS_JOURNAL_DELETE_IN_PROGRESS:
            return "STATUS_JOURNAL_DELETE_IN_PROGRESS";
        case STATUS_JOURNAL_NOT_ACTIVE:
            return "STATUS_JOURNAL_NOT_ACTIVE";
        case STATUS_NOINTERFACE:
            return "STATUS_NOINTERFACE";
        case STATUS_DS_ADMIN_LIMIT_EXCEEDED:
            return "STATUS_DS_ADMIN_LIMIT_EXCEEDED";
        case STATUS_DRIVER_FAILED_SLEEP:
            return "STATUS_DRIVER_FAILED_SLEEP";
        case STATUS_MUTUAL_AUTHENTICATION_FAILED:
            return "STATUS_MUTUAL_AUTHENTICATION_FAILED";
        case STATUS_CORRUPT_SYSTEM_FILE:
            return "STATUS_CORRUPT_SYSTEM_FILE";
        case STATUS_DATATYPE_MISALIGNMENT_ERROR:
            return "STATUS_DATATYPE_MISALIGNMENT_ERROR";
        case STATUS_WMI_READ_ONLY:
            return "STATUS_WMI_READ_ONLY";
        case STATUS_WMI_SET_FAILURE:
            return "STATUS_WMI_SET_FAILURE";
        case STATUS_COMMITMENT_MINIMUM:
            return "STATUS_COMMITMENT_MINIMUM";
        case STATUS_REG_NAT_CONSUMPTION:
            return "STATUS_REG_NAT_CONSUMPTION";
        case STATUS_TRANSPORT_FULL:
            return "STATUS_TRANSPORT_FULL";
        case STATUS_DS_SAM_INIT_FAILURE:
            return "STATUS_DS_SAM_INIT_FAILURE";
        case STATUS_ONLY_IF_CONNECTED:
            return "STATUS_ONLY_IF_CONNECTED";
        case STATUS_DS_SENSITIVE_GROUP_VIOLATION:
            return "STATUS_DS_SENSITIVE_GROUP_VIOLATION";
        case STATUS_PNP_RESTART_ENUMERATION:
            return "STATUS_PNP_RESTART_ENUMERATION";
        case STATUS_JOURNAL_ENTRY_DELETED:
            return "STATUS_JOURNAL_ENTRY_DELETED";
        case STATUS_DS_CANT_MOD_PRIMARYGROUPID:
            return "STATUS_DS_CANT_MOD_PRIMARYGROUPID";
        case STATUS_SYSTEM_IMAGE_BAD_SIGNATURE:
            return "STATUS_SYSTEM_IMAGE_BAD_SIGNATURE";
        case STATUS_PNP_REBOOT_REQUIRED:
            return "STATUS_PNP_REBOOT_REQUIRED";
        case STATUS_POWER_STATE_INVALID:
            return "STATUS_POWER_STATE_INVALID";
        case STATUS_DS_INVALID_GROUP_TYPE:
            return "STATUS_DS_INVALID_GROUP_TYPE";
        case STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN:
            return "STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN";
        case STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN:
            return "STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN";
        case STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER:
            return "STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER";
        case STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER:
            return "STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER";
        case STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER:
            return "STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER";
        case STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER:
            return "STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER";
        case STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER:
            return "STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER";
        case STATUS_DS_HAVE_PRIMARY_MEMBERS:
            return "STATUS_DS_HAVE_PRIMARY_MEMBERS";
        case STATUS_WMI_NOT_SUPPORTED:
            return "STATUS_WMI_NOT_SUPPORTED";
        case STATUS_INSUFFICIENT_POWER:
            return "STATUS_INSUFFICIENT_POWER";
        case STATUS_SAM_NEED_BOOTKEY_PASSWORD:
            return "STATUS_SAM_NEED_BOOTKEY_PASSWORD";
        case STATUS_SAM_NEED_BOOTKEY_FLOPPY:
            return "STATUS_SAM_NEED_BOOTKEY_FLOPPY";
        case STATUS_DS_CANT_START:
            return "STATUS_DS_CANT_START";
        case STATUS_DS_INIT_FAILURE:
            return "STATUS_DS_INIT_FAILURE";
        case STATUS_SAM_INIT_FAILURE:
            return "STATUS_SAM_INIT_FAILURE";
        case STATUS_DS_GC_REQUIRED:
            return "STATUS_DS_GC_REQUIRED";
        case STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY:
            return "STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY";
        case STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS:
            return "STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS";
        case STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED:
            return "STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED";
        case STATUS_CURRENT_DOMAIN_NOT_ALLOWED:
            return "STATUS_CURRENT_DOMAIN_NOT_ALLOWED";
        case STATUS_CANNOT_MAKE:
            return "STATUS_CANNOT_MAKE";
        case STATUS_SYSTEM_SHUTDOWN:
            return "STATUS_SYSTEM_SHUTDOWN";
        case STATUS_DS_INIT_FAILURE_CONSOLE:
            return "STATUS_DS_INIT_FAILURE_CONSOLE";
        case STATUS_DS_SAM_INIT_FAILURE_CONSOLE:
            return "STATUS_DS_SAM_INIT_FAILURE_CONSOLE";
        case STATUS_UNFINISHED_CONTEXT_DELETED:
            return "STATUS_UNFINISHED_CONTEXT_DELETED";
        case STATUS_NO_TGT_REPLY:
            return "STATUS_NO_TGT_REPLY";
        case STATUS_OBJECTID_NOT_FOUND:
            return "STATUS_OBJECTID_NOT_FOUND";
        case STATUS_NO_IP_ADDRESSES:
            return "STATUS_NO_IP_ADDRESSES";
        case STATUS_WRONG_CREDENTIAL_HANDLE:
            return "STATUS_WRONG_CREDENTIAL_HANDLE";
        case STATUS_CRYPTO_SYSTEM_INVALID:
            return "STATUS_CRYPTO_SYSTEM_INVALID";
        case STATUS_MAX_REFERRALS_EXCEEDED:
            return "STATUS_MAX_REFERRALS_EXCEEDED";
        case STATUS_MUST_BE_KDC:
            return "STATUS_MUST_BE_KDC";
        case STATUS_STRONG_CRYPTO_NOT_SUPPORTED:
            return "STATUS_STRONG_CRYPTO_NOT_SUPPORTED";
        case STATUS_TOO_MANY_PRINCIPALS:
            return "STATUS_TOO_MANY_PRINCIPALS";
        case STATUS_NO_PA_DATA:
            return "STATUS_NO_PA_DATA";
        case STATUS_PKINIT_NAME_MISMATCH:
            return "STATUS_PKINIT_NAME_MISMATCH";
        case STATUS_SMARTCARD_LOGON_REQUIRED:
            return "STATUS_SMARTCARD_LOGON_REQUIRED";
        case STATUS_KDC_INVALID_REQUEST:
            return "STATUS_KDC_INVALID_REQUEST";
        case STATUS_KDC_UNABLE_TO_REFER:
            return "STATUS_KDC_UNABLE_TO_REFER";
        case STATUS_KDC_UNKNOWN_ETYPE:
            return "STATUS_KDC_UNKNOWN_ETYPE";
        case STATUS_SHUTDOWN_IN_PROGRESS:
            return "STATUS_SHUTDOWN_IN_PROGRESS";
        case STATUS_SERVER_SHUTDOWN_IN_PROGRESS:
            return "STATUS_SERVER_SHUTDOWN_IN_PROGRESS";
        case STATUS_NOT_SUPPORTED_ON_SBS:
            return "STATUS_NOT_SUPPORTED_ON_SBS";
        case STATUS_WMI_GUID_DISCONNECTED:
            return "STATUS_WMI_GUID_DISCONNECTED";
        case STATUS_WMI_ALREADY_DISABLED:
            return "STATUS_WMI_ALREADY_DISABLED";
        case STATUS_WMI_ALREADY_ENABLED:
            return "STATUS_WMI_ALREADY_ENABLED";
        case STATUS_MFT_TOO_FRAGMENTED:
            return "STATUS_MFT_TOO_FRAGMENTED";
        case STATUS_COPY_PROTECTION_FAILURE:
            return "STATUS_COPY_PROTECTION_FAILURE";
        case STATUS_CSS_AUTHENTICATION_FAILURE:
            return "STATUS_CSS_AUTHENTICATION_FAILURE";
        case STATUS_CSS_KEY_NOT_PRESENT:
            return "STATUS_CSS_KEY_NOT_PRESENT";
        case STATUS_CSS_KEY_NOT_ESTABLISHED:
            return "STATUS_CSS_KEY_NOT_ESTABLISHED";
        case STATUS_CSS_SCRAMBLED_SECTOR:
            return "STATUS_CSS_SCRAMBLED_SECTOR";
        case STATUS_CSS_REGION_MISMATCH:
            return "STATUS_CSS_REGION_MISMATCH";
        case STATUS_CSS_RESETS_EXHAUSTED:
            return "STATUS_CSS_RESETS_EXHAUSTED";
        case STATUS_PKINIT_FAILURE:
            return "STATUS_PKINIT_FAILURE";
        case STATUS_SMARTCARD_SUBSYSTEM_FAILURE:
            return "STATUS_SMARTCARD_SUBSYSTEM_FAILURE";
        case STATUS_NO_KERB_KEY:
            return "STATUS_NO_KERB_KEY";
        case STATUS_HOST_DOWN:
            return "STATUS_HOST_DOWN";
        case STATUS_UNSUPPORTED_PREAUTH:
            return "STATUS_UNSUPPORTED_PREAUTH";
        case STATUS_EFS_ALG_BLOB_TOO_BIG:
            return "STATUS_EFS_ALG_BLOB_TOO_BIG";
        case STATUS_PORT_NOT_SET:
            return "STATUS_PORT_NOT_SET";
        case STATUS_DEBUGGER_INACTIVE:
            return "STATUS_DEBUGGER_INACTIVE";
        case STATUS_DS_VERSION_CHECK_FAILURE:
            return "STATUS_DS_VERSION_CHECK_FAILURE";
        case STATUS_AUDITING_DISABLED:
            return "STATUS_AUDITING_DISABLED";
        case STATUS_PRENT4_MACHINE_ACCOUNT:
            return "STATUS_PRENT4_MACHINE_ACCOUNT";
        case STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER:
            return "STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER";
        case STATUS_INVALID_IMAGE_WIN_32:
            return "STATUS_INVALID_IMAGE_WIN_32";
        case STATUS_INVALID_IMAGE_WIN_64:
            return "STATUS_INVALID_IMAGE_WIN_64";
        case STATUS_BAD_BINDINGS:
            return "STATUS_BAD_BINDINGS";
        case STATUS_NETWORK_SESSION_EXPIRED:
            return "STATUS_NETWORK_SESSION_EXPIRED";
        case STATUS_APPHELP_BLOCK:
            return "STATUS_APPHELP_BLOCK";
        case STATUS_ALL_SIDS_FILTERED:
            return "STATUS_ALL_SIDS_FILTERED";
        case STATUS_NOT_SAFE_MODE_DRIVER:
            return "STATUS_NOT_SAFE_MODE_DRIVER";
        case STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT:
            return "STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT";
        case STATUS_ACCESS_DISABLED_BY_POLICY_PATH:
            return "STATUS_ACCESS_DISABLED_BY_POLICY_PATH";
        case STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER:
            return "STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER";
        case STATUS_ACCESS_DISABLED_BY_POLICY_OTHER:
            return "STATUS_ACCESS_DISABLED_BY_POLICY_OTHER";
        case STATUS_FAILED_DRIVER_ENTRY:
            return "STATUS_FAILED_DRIVER_ENTRY";
        case STATUS_DEVICE_ENUMERATION_ERROR:
            return "STATUS_DEVICE_ENUMERATION_ERROR";
        case STATUS_MOUNT_POINT_NOT_RESOLVED:
            return "STATUS_MOUNT_POINT_NOT_RESOLVED";
        case STATUS_INVALID_DEVICE_OBJECT_PARAMETER:
            return "STATUS_INVALID_DEVICE_OBJECT_PARAMETER";
        case STATUS_MCA_OCCURED:
            return "STATUS_MCA_OCCURED";
        case STATUS_DRIVER_BLOCKED_CRITICAL:
            return "STATUS_DRIVER_BLOCKED_CRITICAL";
        case STATUS_DRIVER_BLOCKED:
            return "STATUS_DRIVER_BLOCKED";
        case STATUS_DRIVER_DATABASE_ERROR:
            return "STATUS_DRIVER_DATABASE_ERROR";
        case STATUS_SYSTEM_HIVE_TOO_LARGE:
            return "STATUS_SYSTEM_HIVE_TOO_LARGE";
        case STATUS_INVALID_IMPORT_OF_NON_DLL:
            return "STATUS_INVALID_IMPORT_OF_NON_DLL";
        case STATUS_NO_SECRETS:
            return "STATUS_NO_SECRETS";
        case STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY:
            return "STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY";
        case STATUS_FAILED_STACK_SWITCH:
            return "STATUS_FAILED_STACK_SWITCH";
        case STATUS_HEAP_CORRUPTION:
            return "STATUS_HEAP_CORRUPTION";
        case STATUS_SMARTCARD_WRONG_PIN:
            return "STATUS_SMARTCARD_WRONG_PIN";
        case STATUS_SMARTCARD_CARD_BLOCKED:
            return "STATUS_SMARTCARD_CARD_BLOCKED";
        case STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED:
            return "STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED";
        case STATUS_SMARTCARD_NO_CARD:
            return "STATUS_SMARTCARD_NO_CARD";
        case STATUS_SMARTCARD_NO_KEY_CONTAINER:
            return "STATUS_SMARTCARD_NO_KEY_CONTAINER";
        case STATUS_SMARTCARD_NO_CERTIFICATE:
            return "STATUS_SMARTCARD_NO_CERTIFICATE";
        case STATUS_SMARTCARD_NO_KEYSET:
            return "STATUS_SMARTCARD_NO_KEYSET";
        case STATUS_SMARTCARD_IO_ERROR:
            return "STATUS_SMARTCARD_IO_ERROR";
        case STATUS_DOWNGRADE_DETECTED:
            return "STATUS_DOWNGRADE_DETECTED";
        case STATUS_SMARTCARD_CERT_REVOKED:
            return "STATUS_SMARTCARD_CERT_REVOKED";
        case STATUS_ISSUING_CA_UNTRUSTED:
            return "STATUS_ISSUING_CA_UNTRUSTED";
        case STATUS_REVOCATION_OFFLINE_C:
            return "STATUS_REVOCATION_OFFLINE_C";
        case STATUS_PKINIT_CLIENT_FAILURE:
            return "STATUS_PKINIT_CLIENT_FAILURE";
        case STATUS_SMARTCARD_CERT_EXPIRED:
            return "STATUS_SMARTCARD_CERT_EXPIRED";
        case STATUS_DRIVER_FAILED_PRIOR_UNLOAD:
            return "STATUS_DRIVER_FAILED_PRIOR_UNLOAD";
        case STATUS_SMARTCARD_SILENT_CONTEXT:
            return "STATUS_SMARTCARD_SILENT_CONTEXT";
        case STATUS_PER_USER_TRUST_QUOTA_EXCEEDED:
            return "STATUS_PER_USER_TRUST_QUOTA_EXCEEDED";
        case STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED:
            return "STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED";
        case STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED:
            return "STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED";
        case STATUS_DS_NAME_NOT_UNIQUE:
            return "STATUS_DS_NAME_NOT_UNIQUE";
        case STATUS_DS_DUPLICATE_ID_FOUND:
            return "STATUS_DS_DUPLICATE_ID_FOUND";
        case STATUS_DS_GROUP_CONVERSION_ERROR:
            return "STATUS_DS_GROUP_CONVERSION_ERROR";
        case STATUS_VOLSNAP_PREPARE_HIBERNATE:
            return "STATUS_VOLSNAP_PREPARE_HIBERNATE";
        case STATUS_USER2USER_REQUIRED:
            return "STATUS_USER2USER_REQUIRED";
        case STATUS_STACK_BUFFER_OVERRUN:
            return "STATUS_STACK_BUFFER_OVERRUN";
        case STATUS_NO_S4U_PROT_SUPPORT:
            return "STATUS_NO_S4U_PROT_SUPPORT";
        case STATUS_CROSSREALM_DELEGATION_FAILURE:
            return "STATUS_CROSSREALM_DELEGATION_FAILURE";
        case STATUS_REVOCATION_OFFLINE_KDC:
            return "STATUS_REVOCATION_OFFLINE_KDC";
        case STATUS_ISSUING_CA_UNTRUSTED_KDC:
            return "STATUS_ISSUING_CA_UNTRUSTED_KDC";
        case STATUS_KDC_CERT_EXPIRED:
            return "STATUS_KDC_CERT_EXPIRED";
        case STATUS_KDC_CERT_REVOKED:
            return "STATUS_KDC_CERT_REVOKED";
        case STATUS_PARAMETER_QUOTA_EXCEEDED:
            return "STATUS_PARAMETER_QUOTA_EXCEEDED";
        case STATUS_HIBERNATION_FAILURE:
            return "STATUS_HIBERNATION_FAILURE";
        case STATUS_DELAY_LOAD_FAILED:
            return "STATUS_DELAY_LOAD_FAILED";
        case STATUS_AUTHENTICATION_FIREWALL_FAILED:
            return "STATUS_AUTHENTICATION_FIREWALL_FAILED";
        case STATUS_VDM_DISALLOWED:
            return "STATUS_VDM_DISALLOWED";
        case STATUS_HUNG_DISPLAY_DRIVER_THREAD:
            return "STATUS_HUNG_DISPLAY_DRIVER_THREAD";
        case STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE:
            return "STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE";
        case STATUS_INVALID_CRUNTIME_PARAMETER:
            return "STATUS_INVALID_CRUNTIME_PARAMETER";
        case STATUS_NTLM_BLOCKED:
            return "STATUS_NTLM_BLOCKED";
        case STATUS_DS_SRC_SID_EXISTS_IN_FOREST:
            return "STATUS_DS_SRC_SID_EXISTS_IN_FOREST";
        case STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST:
            return "STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST";
        case STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST:
            return "STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST";
        case STATUS_INVALID_USER_PRINCIPAL_NAME:
            return "STATUS_INVALID_USER_PRINCIPAL_NAME";
        case STATUS_ASSERTION_FAILURE:
            return "STATUS_ASSERTION_FAILURE";
        case STATUS_VERIFIER_STOP:
            return "STATUS_VERIFIER_STOP";
        case STATUS_CALLBACK_POP_STACK:
            return "STATUS_CALLBACK_POP_STACK";
        case STATUS_INCOMPATIBLE_DRIVER_BLOCKED:
            return "STATUS_INCOMPATIBLE_DRIVER_BLOCKED";
        case STATUS_HIVE_UNLOADED:
            return "STATUS_HIVE_UNLOADED";
        case STATUS_COMPRESSION_DISABLED:
            return "STATUS_COMPRESSION_DISABLED";
        case STATUS_FILE_SYSTEM_LIMITATION:
            return "STATUS_FILE_SYSTEM_LIMITATION";
        case STATUS_INVALID_IMAGE_HASH:
            return "STATUS_INVALID_IMAGE_HASH";
        case STATUS_NOT_CAPABLE:
            return "STATUS_NOT_CAPABLE";
        case STATUS_REQUEST_OUT_OF_SEQUENCE:
            return "STATUS_REQUEST_OUT_OF_SEQUENCE";
        case STATUS_IMPLEMENTATION_LIMIT:
            return "STATUS_IMPLEMENTATION_LIMIT";
        case STATUS_ELEVATION_REQUIRED:
            return "STATUS_ELEVATION_REQUIRED";
        case STATUS_NO_SECURITY_CONTEXT:
            return "STATUS_NO_SECURITY_CONTEXT";
        case STATUS_PKU2U_CERT_FAILURE:
            return "STATUS_PKU2U_CERT_FAILURE";
        case STATUS_BEYOND_VDL:
            return "STATUS_BEYOND_VDL";
        case STATUS_ENCOUNTERED_WRITE_IN_PROGRESS:
            return "STATUS_ENCOUNTERED_WRITE_IN_PROGRESS";
        case STATUS_PTE_CHANGED:
            return "STATUS_PTE_CHANGED";
        case STATUS_PURGE_FAILED:
            return "STATUS_PURGE_FAILED";
        case STATUS_CRED_REQUIRES_CONFIRMATION:
            return "STATUS_CRED_REQUIRES_CONFIRMATION";
        case STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE:
            return "STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE";
        case STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER:
            return "STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER";
        case STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE:
            return "STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE";
        case STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE:
            return "STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE";
        case STATUS_CS_ENCRYPTION_FILE_NOT_CSE:
            return "STATUS_CS_ENCRYPTION_FILE_NOT_CSE";
        case STATUS_INVALID_LABEL:
            return "STATUS_INVALID_LABEL";
        case STATUS_DRIVER_PROCESS_TERMINATED:
            return "STATUS_DRIVER_PROCESS_TERMINATED";
        case STATUS_AMBIGUOUS_SYSTEM_DEVICE:
            return "STATUS_AMBIGUOUS_SYSTEM_DEVICE";
        case STATUS_SYSTEM_DEVICE_NOT_FOUND:
            return "STATUS_SYSTEM_DEVICE_NOT_FOUND";
        case STATUS_RESTART_BOOT_APPLICATION:
            return "STATUS_RESTART_BOOT_APPLICATION";
        case STATUS_INSUFFICIENT_NVRAM_RESOURCES:
            return "STATUS_INSUFFICIENT_NVRAM_RESOURCES";
        case STATUS_INVALID_TASK_NAME:
            return "STATUS_INVALID_TASK_NAME";
        case STATUS_INVALID_TASK_INDEX:
            return "STATUS_INVALID_TASK_INDEX";
        case STATUS_THREAD_ALREADY_IN_TASK:
            return "STATUS_THREAD_ALREADY_IN_TASK";
        case STATUS_CALLBACK_BYPASS:
            return "STATUS_CALLBACK_BYPASS";
        case STATUS_FAIL_FAST_EXCEPTION:
            return "STATUS_FAIL_FAST_EXCEPTION";
        case STATUS_IMAGE_CERT_REVOKED:
            return "STATUS_IMAGE_CERT_REVOKED";
        case STATUS_PORT_CLOSED:
            return "STATUS_PORT_CLOSED";
        case STATUS_MESSAGE_LOST:
            return "STATUS_MESSAGE_LOST";
        case STATUS_INVALID_MESSAGE:
            return "STATUS_INVALID_MESSAGE";
        case STATUS_REQUEST_CANCELED:
            return "STATUS_REQUEST_CANCELED";
        case STATUS_RECURSIVE_DISPATCH:
            return "STATUS_RECURSIVE_DISPATCH";
        case STATUS_LPC_RECEIVE_BUFFER_EXPECTED:
            return "STATUS_LPC_RECEIVE_BUFFER_EXPECTED";
        case STATUS_LPC_INVALID_CONNECTION_USAGE:
            return "STATUS_LPC_INVALID_CONNECTION_USAGE";
        case STATUS_LPC_REQUESTS_NOT_ALLOWED:
            return "STATUS_LPC_REQUESTS_NOT_ALLOWED";
        case STATUS_RESOURCE_IN_USE:
            return "STATUS_RESOURCE_IN_USE";
        case STATUS_HARDWARE_MEMORY_ERROR:
            return "STATUS_HARDWARE_MEMORY_ERROR";
        case STATUS_THREADPOOL_HANDLE_EXCEPTION:
            return "STATUS_THREADPOOL_HANDLE_EXCEPTION";
        case STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED:
            return "STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED";
        case STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED:
            return "STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED";
        case STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED:
            return "STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED";
        case STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED:
            return "STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED";
        case STATUS_THREADPOOL_RELEASED_DURING_OPERATION:
            return "STATUS_THREADPOOL_RELEASED_DURING_OPERATION";
        case STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING:
            return "STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING";
        case STATUS_APC_RETURNED_WHILE_IMPERSONATING:
            return "STATUS_APC_RETURNED_WHILE_IMPERSONATING";
        case STATUS_PROCESS_IS_PROTECTED:
            return "STATUS_PROCESS_IS_PROTECTED";
        case STATUS_MCA_EXCEPTION:
            return "STATUS_MCA_EXCEPTION";
        case STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE:
            return "STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE";
        case STATUS_SYMLINK_CLASS_DISABLED:
            return "STATUS_SYMLINK_CLASS_DISABLED";
        case STATUS_INVALID_IDN_NORMALIZATION:
            return "STATUS_INVALID_IDN_NORMALIZATION";
        case STATUS_NO_UNICODE_TRANSLATION:
            return "STATUS_NO_UNICODE_TRANSLATION";
        case STATUS_ALREADY_REGISTERED:
            return "STATUS_ALREADY_REGISTERED";
        case STATUS_CONTEXT_MISMATCH:
            return "STATUS_CONTEXT_MISMATCH";
        case STATUS_PORT_ALREADY_HAS_COMPLETION_LIST:
            return "STATUS_PORT_ALREADY_HAS_COMPLETION_LIST";
        case STATUS_CALLBACK_RETURNED_THREAD_PRIORITY:
            return "STATUS_CALLBACK_RETURNED_THREAD_PRIORITY";
        case STATUS_INVALID_THREAD:
            return "STATUS_INVALID_THREAD";
        case STATUS_CALLBACK_RETURNED_TRANSACTION:
            return "STATUS_CALLBACK_RETURNED_TRANSACTION";
        case STATUS_CALLBACK_RETURNED_LDR_LOCK:
            return "STATUS_CALLBACK_RETURNED_LDR_LOCK";
        case STATUS_CALLBACK_RETURNED_LANG:
            return "STATUS_CALLBACK_RETURNED_LANG";
        case STATUS_CALLBACK_RETURNED_PRI_BACK:
            return "STATUS_CALLBACK_RETURNED_PRI_BACK";
        case STATUS_DISK_REPAIR_DISABLED:
            return "STATUS_DISK_REPAIR_DISABLED";
        case STATUS_DS_DOMAIN_RENAME_IN_PROGRESS:
            return "STATUS_DS_DOMAIN_RENAME_IN_PROGRESS";
        case STATUS_DISK_QUOTA_EXCEEDED:
            return "STATUS_DISK_QUOTA_EXCEEDED";
        case STATUS_CONTENT_BLOCKED:
            return "STATUS_CONTENT_BLOCKED";
        case STATUS_BAD_CLUSTERS:
            return "STATUS_BAD_CLUSTERS";
        case STATUS_VOLUME_DIRTY:
            return "STATUS_VOLUME_DIRTY";
        case STATUS_FILE_CHECKED_OUT:
            return "STATUS_FILE_CHECKED_OUT";
        case STATUS_CHECKOUT_REQUIRED:
            return "STATUS_CHECKOUT_REQUIRED";
        case STATUS_BAD_FILE_TYPE:
            return "STATUS_BAD_FILE_TYPE";
        case STATUS_FILE_TOO_LARGE:
            return "STATUS_FILE_TOO_LARGE";
        case STATUS_FORMS_AUTH_REQUIRED:
            return "STATUS_FORMS_AUTH_REQUIRED";
        case STATUS_VIRUS_INFECTED:
            return "STATUS_VIRUS_INFECTED";
        case STATUS_VIRUS_DELETED:
            return "STATUS_VIRUS_DELETED";
        case STATUS_BAD_MCFG_TABLE:
            return "STATUS_BAD_MCFG_TABLE";
        case STATUS_CANNOT_BREAK_OPLOCK:
            return "STATUS_CANNOT_BREAK_OPLOCK";
        case STATUS_WOW_ASSERTION:
            return "STATUS_WOW_ASSERTION";
        case STATUS_INVALID_SIGNATURE:
            return "STATUS_INVALID_SIGNATURE";
        case STATUS_HMAC_NOT_SUPPORTED:
            return "STATUS_HMAC_NOT_SUPPORTED";
        case STATUS_IPSEC_QUEUE_OVERFLOW:
            return "STATUS_IPSEC_QUEUE_OVERFLOW";
        case STATUS_ND_QUEUE_OVERFLOW:
            return "STATUS_ND_QUEUE_OVERFLOW";
        case STATUS_HOPLIMIT_EXCEEDED:
            return "STATUS_HOPLIMIT_EXCEEDED";
        case STATUS_PROTOCOL_NOT_SUPPORTED:
            return "STATUS_PROTOCOL_NOT_SUPPORTED";
        case STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED:
            return "STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED";
        case STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR:
            return "STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR";
        case STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR:
            return "STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR";
        case STATUS_XML_PARSE_ERROR:
            return "STATUS_XML_PARSE_ERROR";
        case STATUS_XMLDSIG_ERROR:
            return "STATUS_XMLDSIG_ERROR";
        case STATUS_WRONG_COMPARTMENT:
            return "STATUS_WRONG_COMPARTMENT";
        case STATUS_AUTHIP_FAILURE:
            return "STATUS_AUTHIP_FAILURE";
        case STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS:
            return "STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS";
        case STATUS_DS_OID_NOT_FOUND:
            return "STATUS_DS_OID_NOT_FOUND";
        case STATUS_HASH_NOT_SUPPORTED:
            return "STATUS_HASH_NOT_SUPPORTED";
        case STATUS_HASH_NOT_PRESENT:
            return "STATUS_HASH_NOT_PRESENT";
        case DBG_NO_STATE_CHANGE:
            return "DBG_NO_STATE_CHANGE";
        case DBG_APP_NOT_IDLE:
            return "DBG_APP_NOT_IDLE";
        case RPC_NT_INVALID_STRING_BINDING:
            return "RPC_NT_INVALID_STRING_BINDING";
        case RPC_NT_WRONG_KIND_OF_BINDING:
            return "RPC_NT_WRONG_KIND_OF_BINDING";
        case RPC_NT_INVALID_BINDING:
            return "RPC_NT_INVALID_BINDING";
        case RPC_NT_PROTSEQ_NOT_SUPPORTED:
            return "RPC_NT_PROTSEQ_NOT_SUPPORTED";
        case RPC_NT_INVALID_RPC_PROTSEQ:
            return "RPC_NT_INVALID_RPC_PROTSEQ";
        case RPC_NT_INVALID_STRING_UUID:
            return "RPC_NT_INVALID_STRING_UUID";
        case RPC_NT_INVALID_ENDPOINT_FORMAT:
            return "RPC_NT_INVALID_ENDPOINT_FORMAT";
        case RPC_NT_INVALID_NET_ADDR:
            return "RPC_NT_INVALID_NET_ADDR";
        case RPC_NT_NO_ENDPOINT_FOUND:
            return "RPC_NT_NO_ENDPOINT_FOUND";
        case RPC_NT_INVALID_TIMEOUT:
            return "RPC_NT_INVALID_TIMEOUT";
        case RPC_NT_OBJECT_NOT_FOUND:
            return "RPC_NT_OBJECT_NOT_FOUND";
        case RPC_NT_ALREADY_REGISTERED:
            return "RPC_NT_ALREADY_REGISTERED";
        case RPC_NT_TYPE_ALREADY_REGISTERED:
            return "RPC_NT_TYPE_ALREADY_REGISTERED";
        case RPC_NT_ALREADY_LISTENING:
            return "RPC_NT_ALREADY_LISTENING";
        case RPC_NT_NO_PROTSEQS_REGISTERED:
            return "RPC_NT_NO_PROTSEQS_REGISTERED";
        case RPC_NT_NOT_LISTENING:
            return "RPC_NT_NOT_LISTENING";
        case RPC_NT_UNKNOWN_MGR_TYPE:
            return "RPC_NT_UNKNOWN_MGR_TYPE";
        case RPC_NT_UNKNOWN_IF:
            return "RPC_NT_UNKNOWN_IF";
        case RPC_NT_NO_BINDINGS:
            return "RPC_NT_NO_BINDINGS";
        case RPC_NT_NO_PROTSEQS:
            return "RPC_NT_NO_PROTSEQS";
        case RPC_NT_CANT_CREATE_ENDPOINT:
            return "RPC_NT_CANT_CREATE_ENDPOINT";
        case RPC_NT_OUT_OF_RESOURCES:
            return "RPC_NT_OUT_OF_RESOURCES";
        case RPC_NT_SERVER_UNAVAILABLE:
            return "RPC_NT_SERVER_UNAVAILABLE";
        case RPC_NT_SERVER_TOO_BUSY:
            return "RPC_NT_SERVER_TOO_BUSY";
        case RPC_NT_INVALID_NETWORK_OPTIONS:
            return "RPC_NT_INVALID_NETWORK_OPTIONS";
        case RPC_NT_NO_CALL_ACTIVE:
            return "RPC_NT_NO_CALL_ACTIVE";
        case RPC_NT_CALL_FAILED:
            return "RPC_NT_CALL_FAILED";
        case RPC_NT_CALL_FAILED_DNE:
            return "RPC_NT_CALL_FAILED_DNE";
        case RPC_NT_PROTOCOL_ERROR:
            return "RPC_NT_PROTOCOL_ERROR";
        case RPC_NT_UNSUPPORTED_TRANS_SYN:
            return "RPC_NT_UNSUPPORTED_TRANS_SYN";
        case RPC_NT_UNSUPPORTED_TYPE:
            return "RPC_NT_UNSUPPORTED_TYPE";
        case RPC_NT_INVALID_TAG:
            return "RPC_NT_INVALID_TAG";
        case RPC_NT_INVALID_BOUND:
            return "RPC_NT_INVALID_BOUND";
        case RPC_NT_NO_ENTRY_NAME:
            return "RPC_NT_NO_ENTRY_NAME";
        case RPC_NT_INVALID_NAME_SYNTAX:
            return "RPC_NT_INVALID_NAME_SYNTAX";
        case RPC_NT_UNSUPPORTED_NAME_SYNTAX:
            return "RPC_NT_UNSUPPORTED_NAME_SYNTAX";
        case RPC_NT_UUID_NO_ADDRESS:
            return "RPC_NT_UUID_NO_ADDRESS";
        case RPC_NT_DUPLICATE_ENDPOINT:
            return "RPC_NT_DUPLICATE_ENDPOINT";
        case RPC_NT_UNKNOWN_AUTHN_TYPE:
            return "RPC_NT_UNKNOWN_AUTHN_TYPE";
        case RPC_NT_MAX_CALLS_TOO_SMALL:
            return "RPC_NT_MAX_CALLS_TOO_SMALL";
        case RPC_NT_STRING_TOO_LONG:
            return "RPC_NT_STRING_TOO_LONG";
        case RPC_NT_PROTSEQ_NOT_FOUND:
            return "RPC_NT_PROTSEQ_NOT_FOUND";
        case RPC_NT_PROCNUM_OUT_OF_RANGE:
            return "RPC_NT_PROCNUM_OUT_OF_RANGE";
        case RPC_NT_BINDING_HAS_NO_AUTH:
            return "RPC_NT_BINDING_HAS_NO_AUTH";
        case RPC_NT_UNKNOWN_AUTHN_SERVICE:
            return "RPC_NT_UNKNOWN_AUTHN_SERVICE";
        case RPC_NT_UNKNOWN_AUTHN_LEVEL:
            return "RPC_NT_UNKNOWN_AUTHN_LEVEL";
        case RPC_NT_INVALID_AUTH_IDENTITY:
            return "RPC_NT_INVALID_AUTH_IDENTITY";
        case RPC_NT_UNKNOWN_AUTHZ_SERVICE:
            return "RPC_NT_UNKNOWN_AUTHZ_SERVICE";
        case EPT_NT_INVALID_ENTRY:
            return "EPT_NT_INVALID_ENTRY";
        case EPT_NT_CANT_PERFORM_OP:
            return "EPT_NT_CANT_PERFORM_OP";
        case EPT_NT_NOT_REGISTERED:
            return "EPT_NT_NOT_REGISTERED";
        case RPC_NT_NOTHING_TO_EXPORT:
            return "RPC_NT_NOTHING_TO_EXPORT";
        case RPC_NT_INCOMPLETE_NAME:
            return "RPC_NT_INCOMPLETE_NAME";
        case RPC_NT_INVALID_VERS_OPTION:
            return "RPC_NT_INVALID_VERS_OPTION";
        case RPC_NT_NO_MORE_MEMBERS:
            return "RPC_NT_NO_MORE_MEMBERS";
        case RPC_NT_NOT_ALL_OBJS_UNEXPORTED:
            return "RPC_NT_NOT_ALL_OBJS_UNEXPORTED";
        case RPC_NT_INTERFACE_NOT_FOUND:
            return "RPC_NT_INTERFACE_NOT_FOUND";
        case RPC_NT_ENTRY_ALREADY_EXISTS:
            return "RPC_NT_ENTRY_ALREADY_EXISTS";
        case RPC_NT_ENTRY_NOT_FOUND:
            return "RPC_NT_ENTRY_NOT_FOUND";
        case RPC_NT_NAME_SERVICE_UNAVAILABLE:
            return "RPC_NT_NAME_SERVICE_UNAVAILABLE";
        case RPC_NT_INVALID_NAF_ID:
            return "RPC_NT_INVALID_NAF_ID";
        case RPC_NT_CANNOT_SUPPORT:
            return "RPC_NT_CANNOT_SUPPORT";
        case RPC_NT_NO_CONTEXT_AVAILABLE:
            return "RPC_NT_NO_CONTEXT_AVAILABLE";
        case RPC_NT_INTERNAL_ERROR:
            return "RPC_NT_INTERNAL_ERROR";
        case RPC_NT_ZERO_DIVIDE:
            return "RPC_NT_ZERO_DIVIDE";
        case RPC_NT_ADDRESS_ERROR:
            return "RPC_NT_ADDRESS_ERROR";
        case RPC_NT_FP_DIV_ZERO:
            return "RPC_NT_FP_DIV_ZERO";
        case RPC_NT_FP_UNDERFLOW:
            return "RPC_NT_FP_UNDERFLOW";
        case RPC_NT_FP_OVERFLOW:
            return "RPC_NT_FP_OVERFLOW";
        case RPC_NT_CALL_IN_PROGRESS:
            return "RPC_NT_CALL_IN_PROGRESS";
        case RPC_NT_NO_MORE_BINDINGS:
            return "RPC_NT_NO_MORE_BINDINGS";
        case RPC_NT_GROUP_MEMBER_NOT_FOUND:
            return "RPC_NT_GROUP_MEMBER_NOT_FOUND";
        case EPT_NT_CANT_CREATE:
            return "EPT_NT_CANT_CREATE";
        case RPC_NT_INVALID_OBJECT:
            return "RPC_NT_INVALID_OBJECT";
        case RPC_NT_NO_INTERFACES:
            return "RPC_NT_NO_INTERFACES";
        case RPC_NT_CALL_CANCELLED:
            return "RPC_NT_CALL_CANCELLED";
        case RPC_NT_BINDING_INCOMPLETE:
            return "RPC_NT_BINDING_INCOMPLETE";
        case RPC_NT_COMM_FAILURE:
            return "RPC_NT_COMM_FAILURE";
        case RPC_NT_UNSUPPORTED_AUTHN_LEVEL:
            return "RPC_NT_UNSUPPORTED_AUTHN_LEVEL";
        case RPC_NT_NO_PRINC_NAME:
            return "RPC_NT_NO_PRINC_NAME";
        case RPC_NT_NOT_RPC_ERROR:
            return "RPC_NT_NOT_RPC_ERROR";
        case RPC_NT_SEC_PKG_ERROR:
            return "RPC_NT_SEC_PKG_ERROR";
        case RPC_NT_NOT_CANCELLED:
            return "RPC_NT_NOT_CANCELLED";
        case RPC_NT_INVALID_ASYNC_HANDLE:
            return "RPC_NT_INVALID_ASYNC_HANDLE";
        case RPC_NT_INVALID_ASYNC_CALL:
            return "RPC_NT_INVALID_ASYNC_CALL";
        case RPC_NT_PROXY_ACCESS_DENIED:
            return "RPC_NT_PROXY_ACCESS_DENIED";
        case RPC_NT_NO_MORE_ENTRIES:
            return "RPC_NT_NO_MORE_ENTRIES";
        case RPC_NT_SS_CHAR_TRANS_OPEN_FAIL:
            return "RPC_NT_SS_CHAR_TRANS_OPEN_FAIL";
        case RPC_NT_SS_CHAR_TRANS_SHORT_FILE:
            return "RPC_NT_SS_CHAR_TRANS_SHORT_FILE";
        case RPC_NT_SS_IN_NULL_CONTEXT:
            return "RPC_NT_SS_IN_NULL_CONTEXT";
        case RPC_NT_SS_CONTEXT_MISMATCH:
            return "RPC_NT_SS_CONTEXT_MISMATCH";
        case RPC_NT_SS_CONTEXT_DAMAGED:
            return "RPC_NT_SS_CONTEXT_DAMAGED";
        case RPC_NT_SS_HANDLES_MISMATCH:
            return "RPC_NT_SS_HANDLES_MISMATCH";
        case RPC_NT_SS_CANNOT_GET_CALL_HANDLE:
            return "RPC_NT_SS_CANNOT_GET_CALL_HANDLE";
        case RPC_NT_NULL_REF_POINTER:
            return "RPC_NT_NULL_REF_POINTER";
        case RPC_NT_ENUM_VALUE_OUT_OF_RANGE:
            return "RPC_NT_ENUM_VALUE_OUT_OF_RANGE";
        case RPC_NT_BYTE_COUNT_TOO_SMALL:
            return "RPC_NT_BYTE_COUNT_TOO_SMALL";
        case RPC_NT_BAD_STUB_DATA:
            return "RPC_NT_BAD_STUB_DATA";
        case RPC_NT_INVALID_ES_ACTION:
            return "RPC_NT_INVALID_ES_ACTION";
        case RPC_NT_WRONG_ES_VERSION:
            return "RPC_NT_WRONG_ES_VERSION";
        case RPC_NT_WRONG_STUB_VERSION:
            return "RPC_NT_WRONG_STUB_VERSION";
        case RPC_NT_INVALID_PIPE_OBJECT:
            return "RPC_NT_INVALID_PIPE_OBJECT";
        case RPC_NT_INVALID_PIPE_OPERATION:
            return "RPC_NT_INVALID_PIPE_OPERATION";
        case RPC_NT_WRONG_PIPE_VERSION:
            return "RPC_NT_WRONG_PIPE_VERSION";
        case RPC_NT_PIPE_CLOSED:
            return "RPC_NT_PIPE_CLOSED";
        case RPC_NT_PIPE_DISCIPLINE_ERROR:
            return "RPC_NT_PIPE_DISCIPLINE_ERROR";
        case RPC_NT_PIPE_EMPTY:
            return "RPC_NT_PIPE_EMPTY";
        case STATUS_PNP_BAD_MPS_TABLE:
            return "STATUS_PNP_BAD_MPS_TABLE";
        case STATUS_PNP_TRANSLATION_FAILED:
            return "STATUS_PNP_TRANSLATION_FAILED";
        case STATUS_PNP_IRQ_TRANSLATION_FAILED:
            return "STATUS_PNP_IRQ_TRANSLATION_FAILED";
        case STATUS_PNP_INVALID_ID:
            return "STATUS_PNP_INVALID_ID";
        case STATUS_IO_REISSUE_AS_CACHED:
            return "STATUS_IO_REISSUE_AS_CACHED";
        case STATUS_CTX_WINSTATION_NAME_INVALID:
            return "STATUS_CTX_WINSTATION_NAME_INVALID";
        case STATUS_CTX_INVALID_PD:
            return "STATUS_CTX_INVALID_PD";
        case STATUS_CTX_PD_NOT_FOUND:
            return "STATUS_CTX_PD_NOT_FOUND";
        case STATUS_CTX_CLOSE_PENDING:
            return "STATUS_CTX_CLOSE_PENDING";
        case STATUS_CTX_NO_OUTBUF:
            return "STATUS_CTX_NO_OUTBUF";
        case STATUS_CTX_MODEM_INF_NOT_FOUND:
            return "STATUS_CTX_MODEM_INF_NOT_FOUND";
        case STATUS_CTX_INVALID_MODEMNAME:
            return "STATUS_CTX_INVALID_MODEMNAME";
        case STATUS_CTX_RESPONSE_ERROR:
            return "STATUS_CTX_RESPONSE_ERROR";
        case STATUS_CTX_MODEM_RESPONSE_TIMEOUT:
            return "STATUS_CTX_MODEM_RESPONSE_TIMEOUT";
        case STATUS_CTX_MODEM_RESPONSE_NO_CARRIER:
            return "STATUS_CTX_MODEM_RESPONSE_NO_CARRIER";
        case STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE:
            return "STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE";
        case STATUS_CTX_MODEM_RESPONSE_BUSY:
            return "STATUS_CTX_MODEM_RESPONSE_BUSY";
        case STATUS_CTX_MODEM_RESPONSE_VOICE:
            return "STATUS_CTX_MODEM_RESPONSE_VOICE";
        case STATUS_CTX_TD_ERROR:
            return "STATUS_CTX_TD_ERROR";
        case STATUS_CTX_LICENSE_CLIENT_INVALID:
            return "STATUS_CTX_LICENSE_CLIENT_INVALID";
        case STATUS_CTX_LICENSE_NOT_AVAILABLE:
            return "STATUS_CTX_LICENSE_NOT_AVAILABLE";
        case STATUS_CTX_LICENSE_EXPIRED:
            return "STATUS_CTX_LICENSE_EXPIRED";
        case STATUS_CTX_WINSTATION_NOT_FOUND:
            return "STATUS_CTX_WINSTATION_NOT_FOUND";
        case STATUS_CTX_WINSTATION_NAME_COLLISION:
            return "STATUS_CTX_WINSTATION_NAME_COLLISION";
        case STATUS_CTX_WINSTATION_BUSY:
            return "STATUS_CTX_WINSTATION_BUSY";
        case STATUS_CTX_BAD_VIDEO_MODE:
            return "STATUS_CTX_BAD_VIDEO_MODE";
        case STATUS_CTX_GRAPHICS_INVALID:
            return "STATUS_CTX_GRAPHICS_INVALID";
        case STATUS_CTX_NOT_CONSOLE:
            return "STATUS_CTX_NOT_CONSOLE";
        case STATUS_CTX_CLIENT_QUERY_TIMEOUT:
            return "STATUS_CTX_CLIENT_QUERY_TIMEOUT";
        case STATUS_CTX_CONSOLE_DISCONNECT:
            return "STATUS_CTX_CONSOLE_DISCONNECT";
        case STATUS_CTX_CONSOLE_CONNECT:
            return "STATUS_CTX_CONSOLE_CONNECT";
        case STATUS_CTX_SHADOW_DENIED:
            return "STATUS_CTX_SHADOW_DENIED";
        case STATUS_CTX_WINSTATION_ACCESS_DENIED:
            return "STATUS_CTX_WINSTATION_ACCESS_DENIED";
        case STATUS_CTX_INVALID_WD:
            return "STATUS_CTX_INVALID_WD";
        case STATUS_CTX_WD_NOT_FOUND:
            return "STATUS_CTX_WD_NOT_FOUND";
        case STATUS_CTX_SHADOW_INVALID:
            return "STATUS_CTX_SHADOW_INVALID";
        case STATUS_CTX_SHADOW_DISABLED:
            return "STATUS_CTX_SHADOW_DISABLED";
        case STATUS_RDP_PROTOCOL_ERROR:
            return "STATUS_RDP_PROTOCOL_ERROR";
        case STATUS_CTX_CLIENT_LICENSE_NOT_SET:
            return "STATUS_CTX_CLIENT_LICENSE_NOT_SET";
        case STATUS_CTX_CLIENT_LICENSE_IN_USE:
            return "STATUS_CTX_CLIENT_LICENSE_IN_USE";
        case STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE:
            return "STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE";
        case STATUS_CTX_SHADOW_NOT_RUNNING:
            return "STATUS_CTX_SHADOW_NOT_RUNNING";
        case STATUS_CTX_LOGON_DISABLED:
            return "STATUS_CTX_LOGON_DISABLED";
        case STATUS_CTX_SECURITY_LAYER_ERROR:
            return "STATUS_CTX_SECURITY_LAYER_ERROR";
        case STATUS_TS_INCOMPATIBLE_SESSIONS:
            return "STATUS_TS_INCOMPATIBLE_SESSIONS";
        case STATUS_MUI_FILE_NOT_FOUND:
            return "STATUS_MUI_FILE_NOT_FOUND";
        case STATUS_MUI_INVALID_FILE:
            return "STATUS_MUI_INVALID_FILE";
        case STATUS_MUI_INVALID_RC_CONFIG:
            return "STATUS_MUI_INVALID_RC_CONFIG";
        case STATUS_MUI_INVALID_LOCALE_NAME:
            return "STATUS_MUI_INVALID_LOCALE_NAME";
        case STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME:
            return "STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME";
        case STATUS_MUI_FILE_NOT_LOADED:
            return "STATUS_MUI_FILE_NOT_LOADED";
        case STATUS_RESOURCE_ENUM_USER_STOP:
            return "STATUS_RESOURCE_ENUM_USER_STOP";
        case STATUS_CLUSTER_INVALID_NODE:
            return "STATUS_CLUSTER_INVALID_NODE";
        case STATUS_CLUSTER_NODE_EXISTS:
            return "STATUS_CLUSTER_NODE_EXISTS";
        case STATUS_CLUSTER_JOIN_IN_PROGRESS:
            return "STATUS_CLUSTER_JOIN_IN_PROGRESS";
        case STATUS_CLUSTER_NODE_NOT_FOUND:
            return "STATUS_CLUSTER_NODE_NOT_FOUND";
        case STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND:
            return "STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND";
        case STATUS_CLUSTER_NETWORK_EXISTS:
            return "STATUS_CLUSTER_NETWORK_EXISTS";
        case STATUS_CLUSTER_NETWORK_NOT_FOUND:
            return "STATUS_CLUSTER_NETWORK_NOT_FOUND";
        case STATUS_CLUSTER_NETINTERFACE_EXISTS:
            return "STATUS_CLUSTER_NETINTERFACE_EXISTS";
        case STATUS_CLUSTER_NETINTERFACE_NOT_FOUND:
            return "STATUS_CLUSTER_NETINTERFACE_NOT_FOUND";
        case STATUS_CLUSTER_INVALID_REQUEST:
            return "STATUS_CLUSTER_INVALID_REQUEST";
        case STATUS_CLUSTER_INVALID_NETWORK_PROVIDER:
            return "STATUS_CLUSTER_INVALID_NETWORK_PROVIDER";
        case STATUS_CLUSTER_NODE_DOWN:
            return "STATUS_CLUSTER_NODE_DOWN";
        case STATUS_CLUSTER_NODE_UNREACHABLE:
            return "STATUS_CLUSTER_NODE_UNREACHABLE";
        case STATUS_CLUSTER_NODE_NOT_MEMBER:
            return "STATUS_CLUSTER_NODE_NOT_MEMBER";
        case STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS:
            return "STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS";
        case STATUS_CLUSTER_INVALID_NETWORK:
            return "STATUS_CLUSTER_INVALID_NETWORK";
        case STATUS_CLUSTER_NO_NET_ADAPTERS:
            return "STATUS_CLUSTER_NO_NET_ADAPTERS";
        case STATUS_CLUSTER_NODE_UP:
            return "STATUS_CLUSTER_NODE_UP";
        case STATUS_CLUSTER_NODE_PAUSED:
            return "STATUS_CLUSTER_NODE_PAUSED";
        case STATUS_CLUSTER_NODE_NOT_PAUSED:
            return "STATUS_CLUSTER_NODE_NOT_PAUSED";
        case STATUS_CLUSTER_NO_SECURITY_CONTEXT:
            return "STATUS_CLUSTER_NO_SECURITY_CONTEXT";
        case STATUS_CLUSTER_NETWORK_NOT_INTERNAL:
            return "STATUS_CLUSTER_NETWORK_NOT_INTERNAL";
        case STATUS_CLUSTER_POISONED:
            return "STATUS_CLUSTER_POISONED";
        case STATUS_ACPI_INVALID_OPCODE:
            return "STATUS_ACPI_INVALID_OPCODE";
        case STATUS_ACPI_STACK_OVERFLOW:
            return "STATUS_ACPI_STACK_OVERFLOW";
        case STATUS_ACPI_ASSERT_FAILED:
            return "STATUS_ACPI_ASSERT_FAILED";
        case STATUS_ACPI_INVALID_INDEX:
            return "STATUS_ACPI_INVALID_INDEX";
        case STATUS_ACPI_INVALID_ARGUMENT:
            return "STATUS_ACPI_INVALID_ARGUMENT";
        case STATUS_ACPI_FATAL:
            return "STATUS_ACPI_FATAL";
        case STATUS_ACPI_INVALID_SUPERNAME:
            return "STATUS_ACPI_INVALID_SUPERNAME";
        case STATUS_ACPI_INVALID_ARGTYPE:
            return "STATUS_ACPI_INVALID_ARGTYPE";
        case STATUS_ACPI_INVALID_OBJTYPE:
            return "STATUS_ACPI_INVALID_OBJTYPE";
        case STATUS_ACPI_INVALID_TARGETTYPE:
            return "STATUS_ACPI_INVALID_TARGETTYPE";
        case STATUS_ACPI_INCORRECT_ARGUMENT_COUNT:
            return "STATUS_ACPI_INCORRECT_ARGUMENT_COUNT";
        case STATUS_ACPI_ADDRESS_NOT_MAPPED:
            return "STATUS_ACPI_ADDRESS_NOT_MAPPED";
        case STATUS_ACPI_INVALID_EVENTTYPE:
            return "STATUS_ACPI_INVALID_EVENTTYPE";
        case STATUS_ACPI_HANDLER_COLLISION:
            return "STATUS_ACPI_HANDLER_COLLISION";
        case STATUS_ACPI_INVALID_DATA:
            return "STATUS_ACPI_INVALID_DATA";
        case STATUS_ACPI_INVALID_REGION:
            return "STATUS_ACPI_INVALID_REGION";
        case STATUS_ACPI_INVALID_ACCESS_SIZE:
            return "STATUS_ACPI_INVALID_ACCESS_SIZE";
        case STATUS_ACPI_ACQUIRE_GLOBAL_LOCK:
            return "STATUS_ACPI_ACQUIRE_GLOBAL_LOCK";
        case STATUS_ACPI_ALREADY_INITIALIZED:
            return "STATUS_ACPI_ALREADY_INITIALIZED";
        case STATUS_ACPI_NOT_INITIALIZED:
            return "STATUS_ACPI_NOT_INITIALIZED";
        case STATUS_ACPI_INVALID_MUTEX_LEVEL:
            return "STATUS_ACPI_INVALID_MUTEX_LEVEL";
        case STATUS_ACPI_MUTEX_NOT_OWNED:
            return "STATUS_ACPI_MUTEX_NOT_OWNED";
        case STATUS_ACPI_MUTEX_NOT_OWNER:
            return "STATUS_ACPI_MUTEX_NOT_OWNER";
        case STATUS_ACPI_RS_ACCESS:
            return "STATUS_ACPI_RS_ACCESS";
        case STATUS_ACPI_INVALID_TABLE:
            return "STATUS_ACPI_INVALID_TABLE";
        case STATUS_ACPI_REG_HANDLER_FAILED:
            return "STATUS_ACPI_REG_HANDLER_FAILED";
        case STATUS_ACPI_POWER_REQUEST_FAILED:
            return "STATUS_ACPI_POWER_REQUEST_FAILED";
        case STATUS_SXS_SECTION_NOT_FOUND:
            return "STATUS_SXS_SECTION_NOT_FOUND";
        case STATUS_SXS_CANT_GEN_ACTCTX:
            return "STATUS_SXS_CANT_GEN_ACTCTX";
        case STATUS_SXS_INVALID_ACTCTXDATA_FORMAT:
            return "STATUS_SXS_INVALID_ACTCTXDATA_FORMAT";
        case STATUS_SXS_ASSEMBLY_NOT_FOUND:
            return "STATUS_SXS_ASSEMBLY_NOT_FOUND";
        case STATUS_SXS_MANIFEST_FORMAT_ERROR:
            return "STATUS_SXS_MANIFEST_FORMAT_ERROR";
        case STATUS_SXS_MANIFEST_PARSE_ERROR:
            return "STATUS_SXS_MANIFEST_PARSE_ERROR";
        case STATUS_SXS_ACTIVATION_CONTEXT_DISABLED:
            return "STATUS_SXS_ACTIVATION_CONTEXT_DISABLED";
        case STATUS_SXS_KEY_NOT_FOUND:
            return "STATUS_SXS_KEY_NOT_FOUND";
        case STATUS_SXS_VERSION_CONFLICT:
            return "STATUS_SXS_VERSION_CONFLICT";
        case STATUS_SXS_WRONG_SECTION_TYPE:
            return "STATUS_SXS_WRONG_SECTION_TYPE";
        case STATUS_SXS_THREAD_QUERIES_DISABLED:
            return "STATUS_SXS_THREAD_QUERIES_DISABLED";
        case STATUS_SXS_ASSEMBLY_MISSING:
            return "STATUS_SXS_ASSEMBLY_MISSING";
        case STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET:
            return "STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET";
        case STATUS_SXS_EARLY_DEACTIVATION:
            return "STATUS_SXS_EARLY_DEACTIVATION";
        case STATUS_SXS_INVALID_DEACTIVATION:
            return "STATUS_SXS_INVALID_DEACTIVATION";
        case STATUS_SXS_MULTIPLE_DEACTIVATION:
            return "STATUS_SXS_MULTIPLE_DEACTIVATION";
        case STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY:
            return "STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY";
        case STATUS_SXS_PROCESS_TERMINATION_REQUESTED:
            return "STATUS_SXS_PROCESS_TERMINATION_REQUESTED";
        case STATUS_SXS_CORRUPT_ACTIVATION_STACK:
            return "STATUS_SXS_CORRUPT_ACTIVATION_STACK";
        case STATUS_SXS_CORRUPTION:
            return "STATUS_SXS_CORRUPTION";
        case STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE:
            return "STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE";
        case STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME:
            return "STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME";
        case STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE:
            return "STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE";
        case STATUS_SXS_IDENTITY_PARSE_ERROR:
            return "STATUS_SXS_IDENTITY_PARSE_ERROR";
        case STATUS_SXS_COMPONENT_STORE_CORRUPT:
            return "STATUS_SXS_COMPONENT_STORE_CORRUPT";
        case STATUS_SXS_FILE_HASH_MISMATCH:
            return "STATUS_SXS_FILE_HASH_MISMATCH";
        case STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT:
            return "STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT";
        case STATUS_SXS_IDENTITIES_DIFFERENT:
            return "STATUS_SXS_IDENTITIES_DIFFERENT";
        case STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT:
            return "STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT";
        case STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY:
            return "STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY";
        case STATUS_ADVANCED_INSTALLER_FAILED:
            return "STATUS_ADVANCED_INSTALLER_FAILED";
        case STATUS_XML_ENCODING_MISMATCH:
            return "STATUS_XML_ENCODING_MISMATCH";
        case STATUS_SXS_MANIFEST_TOO_BIG:
            return "STATUS_SXS_MANIFEST_TOO_BIG";
        case STATUS_SXS_SETTING_NOT_REGISTERED:
            return "STATUS_SXS_SETTING_NOT_REGISTERED";
        case STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE:
            return "STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE";
        case STATUS_SMI_PRIMITIVE_INSTALLER_FAILED:
            return "STATUS_SMI_PRIMITIVE_INSTALLER_FAILED";
        case STATUS_GENERIC_COMMAND_FAILED:
            return "STATUS_GENERIC_COMMAND_FAILED";
        case STATUS_SXS_FILE_HASH_MISSING:
            return "STATUS_SXS_FILE_HASH_MISSING";
        case STATUS_TRANSACTIONAL_CONFLICT:
            return "STATUS_TRANSACTIONAL_CONFLICT";
        case STATUS_INVALID_TRANSACTION:
            return "STATUS_INVALID_TRANSACTION";
        case STATUS_TRANSACTION_NOT_ACTIVE:
            return "STATUS_TRANSACTION_NOT_ACTIVE";
        case STATUS_TM_INITIALIZATION_FAILED:
            return "STATUS_TM_INITIALIZATION_FAILED";
        case STATUS_RM_NOT_ACTIVE:
            return "STATUS_RM_NOT_ACTIVE";
        case STATUS_RM_METADATA_CORRUPT:
            return "STATUS_RM_METADATA_CORRUPT";
        case STATUS_TRANSACTION_NOT_JOINED:
            return "STATUS_TRANSACTION_NOT_JOINED";
        case STATUS_DIRECTORY_NOT_RM:
            return "STATUS_DIRECTORY_NOT_RM";
        case STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE:
            return "STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE";
        case STATUS_LOG_RESIZE_INVALID_SIZE:
            return "STATUS_LOG_RESIZE_INVALID_SIZE";
        case STATUS_REMOTE_FILE_VERSION_MISMATCH:
            return "STATUS_REMOTE_FILE_VERSION_MISMATCH";
        case STATUS_CRM_PROTOCOL_ALREADY_EXISTS:
            return "STATUS_CRM_PROTOCOL_ALREADY_EXISTS";
        case STATUS_TRANSACTION_PROPAGATION_FAILED:
            return "STATUS_TRANSACTION_PROPAGATION_FAILED";
        case STATUS_CRM_PROTOCOL_NOT_FOUND:
            return "STATUS_CRM_PROTOCOL_NOT_FOUND";
        case STATUS_TRANSACTION_SUPERIOR_EXISTS:
            return "STATUS_TRANSACTION_SUPERIOR_EXISTS";
        case STATUS_TRANSACTION_REQUEST_NOT_VALID:
            return "STATUS_TRANSACTION_REQUEST_NOT_VALID";
        case STATUS_TRANSACTION_NOT_REQUESTED:
            return "STATUS_TRANSACTION_NOT_REQUESTED";
        case STATUS_TRANSACTION_ALREADY_ABORTED:
            return "STATUS_TRANSACTION_ALREADY_ABORTED";
        case STATUS_TRANSACTION_ALREADY_COMMITTED:
            return "STATUS_TRANSACTION_ALREADY_COMMITTED";
        case STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER:
            return "STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER";
        case STATUS_CURRENT_TRANSACTION_NOT_VALID:
            return "STATUS_CURRENT_TRANSACTION_NOT_VALID";
        case STATUS_LOG_GROWTH_FAILED:
            return "STATUS_LOG_GROWTH_FAILED";
        case STATUS_OBJECT_NO_LONGER_EXISTS:
            return "STATUS_OBJECT_NO_LONGER_EXISTS";
        case STATUS_STREAM_MINIVERSION_NOT_FOUND:
            return "STATUS_STREAM_MINIVERSION_NOT_FOUND";
        case STATUS_STREAM_MINIVERSION_NOT_VALID:
            return "STATUS_STREAM_MINIVERSION_NOT_VALID";
        case STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION:
            return "STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION";
        case STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT:
            return "STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT";
        case STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS:
            return "STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS";
        case STATUS_HANDLE_NO_LONGER_VALID:
            return "STATUS_HANDLE_NO_LONGER_VALID";
        case STATUS_LOG_CORRUPTION_DETECTED:
            return "STATUS_LOG_CORRUPTION_DETECTED";
        case STATUS_RM_DISCONNECTED:
            return "STATUS_RM_DISCONNECTED";
        case STATUS_ENLISTMENT_NOT_SUPERIOR:
            return "STATUS_ENLISTMENT_NOT_SUPERIOR";
        case STATUS_FILE_IDENTITY_NOT_PERSISTENT:
            return "STATUS_FILE_IDENTITY_NOT_PERSISTENT";
        case STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY:
            return "STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY";
        case STATUS_CANT_CROSS_RM_BOUNDARY:
            return "STATUS_CANT_CROSS_RM_BOUNDARY";
        case STATUS_TXF_DIR_NOT_EMPTY:
            return "STATUS_TXF_DIR_NOT_EMPTY";
        case STATUS_INDOUBT_TRANSACTIONS_EXIST:
            return "STATUS_INDOUBT_TRANSACTIONS_EXIST";
        case STATUS_TM_VOLATILE:
            return "STATUS_TM_VOLATILE";
        case STATUS_ROLLBACK_TIMER_EXPIRED:
            return "STATUS_ROLLBACK_TIMER_EXPIRED";
        case STATUS_TXF_ATTRIBUTE_CORRUPT:
            return "STATUS_TXF_ATTRIBUTE_CORRUPT";
        case STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION:
            return "STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION";
        case STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED:
            return "STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED";
        case STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE:
            return "STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE";
        case STATUS_TRANSACTION_REQUIRED_PROMOTION:
            return "STATUS_TRANSACTION_REQUIRED_PROMOTION";
        case STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION:
            return "STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION";
        case STATUS_TRANSACTIONS_NOT_FROZEN:
            return "STATUS_TRANSACTIONS_NOT_FROZEN";
        case STATUS_TRANSACTION_FREEZE_IN_PROGRESS:
            return "STATUS_TRANSACTION_FREEZE_IN_PROGRESS";
        case STATUS_NOT_SNAPSHOT_VOLUME:
            return "STATUS_NOT_SNAPSHOT_VOLUME";
        case STATUS_NO_SAVEPOINT_WITH_OPEN_FILES:
            return "STATUS_NO_SAVEPOINT_WITH_OPEN_FILES";
        case STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION:
            return "STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION";
        case STATUS_TM_IDENTITY_MISMATCH:
            return "STATUS_TM_IDENTITY_MISMATCH";
        case STATUS_FLOATED_SECTION:
            return "STATUS_FLOATED_SECTION";
        case STATUS_CANNOT_ACCEPT_TRANSACTED_WORK:
            return "STATUS_CANNOT_ACCEPT_TRANSACTED_WORK";
        case STATUS_CANNOT_ABORT_TRANSACTIONS:
            return "STATUS_CANNOT_ABORT_TRANSACTIONS";
        case STATUS_TRANSACTION_NOT_FOUND:
            return "STATUS_TRANSACTION_NOT_FOUND";
        case STATUS_RESOURCEMANAGER_NOT_FOUND:
            return "STATUS_RESOURCEMANAGER_NOT_FOUND";
        case STATUS_ENLISTMENT_NOT_FOUND:
            return "STATUS_ENLISTMENT_NOT_FOUND";
        case STATUS_TRANSACTIONMANAGER_NOT_FOUND:
            return "STATUS_TRANSACTIONMANAGER_NOT_FOUND";
        case STATUS_TRANSACTIONMANAGER_NOT_ONLINE:
            return "STATUS_TRANSACTIONMANAGER_NOT_ONLINE";
        case STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION:
            return "STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION";
        case STATUS_TRANSACTION_NOT_ROOT:
            return "STATUS_TRANSACTION_NOT_ROOT";
        case STATUS_TRANSACTION_OBJECT_EXPIRED:
            return "STATUS_TRANSACTION_OBJECT_EXPIRED";
        case STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION:
            return "STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION";
        case STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED:
            return "STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED";
        case STATUS_TRANSACTION_RECORD_TOO_LONG:
            return "STATUS_TRANSACTION_RECORD_TOO_LONG";
        case STATUS_NO_LINK_TRACKING_IN_TRANSACTION:
            return "STATUS_NO_LINK_TRACKING_IN_TRANSACTION";
        case STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION:
            return "STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION";
        case STATUS_TRANSACTION_INTEGRITY_VIOLATED:
            return "STATUS_TRANSACTION_INTEGRITY_VIOLATED";
        case STATUS_EXPIRED_HANDLE:
            return "STATUS_EXPIRED_HANDLE";
        case STATUS_TRANSACTION_NOT_ENLISTED:
            return "STATUS_TRANSACTION_NOT_ENLISTED";
        case STATUS_LOG_SECTOR_INVALID:
            return "STATUS_LOG_SECTOR_INVALID";
        case STATUS_LOG_SECTOR_PARITY_INVALID:
            return "STATUS_LOG_SECTOR_PARITY_INVALID";
        case STATUS_LOG_SECTOR_REMAPPED:
            return "STATUS_LOG_SECTOR_REMAPPED";
        case STATUS_LOG_BLOCK_INCOMPLETE:
            return "STATUS_LOG_BLOCK_INCOMPLETE";
        case STATUS_LOG_INVALID_RANGE:
            return "STATUS_LOG_INVALID_RANGE";
        case STATUS_LOG_BLOCKS_EXHAUSTED:
            return "STATUS_LOG_BLOCKS_EXHAUSTED";
        case STATUS_LOG_READ_CONTEXT_INVALID:
            return "STATUS_LOG_READ_CONTEXT_INVALID";
        case STATUS_LOG_RESTART_INVALID:
            return "STATUS_LOG_RESTART_INVALID";
        case STATUS_LOG_BLOCK_VERSION:
            return "STATUS_LOG_BLOCK_VERSION";
        case STATUS_LOG_BLOCK_INVALID:
            return "STATUS_LOG_BLOCK_INVALID";
        case STATUS_LOG_READ_MODE_INVALID:
            return "STATUS_LOG_READ_MODE_INVALID";
        case STATUS_LOG_METADATA_CORRUPT:
            return "STATUS_LOG_METADATA_CORRUPT";
        case STATUS_LOG_METADATA_INVALID:
            return "STATUS_LOG_METADATA_INVALID";
        case STATUS_LOG_METADATA_INCONSISTENT:
            return "STATUS_LOG_METADATA_INCONSISTENT";
        case STATUS_LOG_RESERVATION_INVALID:
            return "STATUS_LOG_RESERVATION_INVALID";
        case STATUS_LOG_CANT_DELETE:
            return "STATUS_LOG_CANT_DELETE";
        case STATUS_LOG_CONTAINER_LIMIT_EXCEEDED:
            return "STATUS_LOG_CONTAINER_LIMIT_EXCEEDED";
        case STATUS_LOG_START_OF_LOG:
            return "STATUS_LOG_START_OF_LOG";
        case STATUS_LOG_POLICY_ALREADY_INSTALLED:
            return "STATUS_LOG_POLICY_ALREADY_INSTALLED";
        case STATUS_LOG_POLICY_NOT_INSTALLED:
            return "STATUS_LOG_POLICY_NOT_INSTALLED";
        case STATUS_LOG_POLICY_INVALID:
            return "STATUS_LOG_POLICY_INVALID";
        case STATUS_LOG_POLICY_CONFLICT:
            return "STATUS_LOG_POLICY_CONFLICT";
        case STATUS_LOG_PINNED_ARCHIVE_TAIL:
            return "STATUS_LOG_PINNED_ARCHIVE_TAIL";
        case STATUS_LOG_RECORD_NONEXISTENT:
            return "STATUS_LOG_RECORD_NONEXISTENT";
        case STATUS_LOG_RECORDS_RESERVED_INVALID:
            return "STATUS_LOG_RECORDS_RESERVED_INVALID";
        case STATUS_LOG_SPACE_RESERVED_INVALID:
            return "STATUS_LOG_SPACE_RESERVED_INVALID";
        case STATUS_LOG_TAIL_INVALID:
            return "STATUS_LOG_TAIL_INVALID";
        case STATUS_LOG_FULL:
            return "STATUS_LOG_FULL";
        case STATUS_LOG_MULTIPLEXED:
            return "STATUS_LOG_MULTIPLEXED";
        case STATUS_LOG_DEDICATED:
            return "STATUS_LOG_DEDICATED";
        case STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS:
            return "STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS";
        case STATUS_LOG_ARCHIVE_IN_PROGRESS:
            return "STATUS_LOG_ARCHIVE_IN_PROGRESS";
        case STATUS_LOG_EPHEMERAL:
            return "STATUS_LOG_EPHEMERAL";
        case STATUS_LOG_NOT_ENOUGH_CONTAINERS:
            return "STATUS_LOG_NOT_ENOUGH_CONTAINERS";
        case STATUS_LOG_CLIENT_ALREADY_REGISTERED:
            return "STATUS_LOG_CLIENT_ALREADY_REGISTERED";
        case STATUS_LOG_CLIENT_NOT_REGISTERED:
            return "STATUS_LOG_CLIENT_NOT_REGISTERED";
        case STATUS_LOG_FULL_HANDLER_IN_PROGRESS:
            return "STATUS_LOG_FULL_HANDLER_IN_PROGRESS";
        case STATUS_LOG_CONTAINER_READ_FAILED:
            return "STATUS_LOG_CONTAINER_READ_FAILED";
        case STATUS_LOG_CONTAINER_WRITE_FAILED:
            return "STATUS_LOG_CONTAINER_WRITE_FAILED";
        case STATUS_LOG_CONTAINER_OPEN_FAILED:
            return "STATUS_LOG_CONTAINER_OPEN_FAILED";
        case STATUS_LOG_CONTAINER_STATE_INVALID:
            return "STATUS_LOG_CONTAINER_STATE_INVALID";
        case STATUS_LOG_STATE_INVALID:
            return "STATUS_LOG_STATE_INVALID";
        case STATUS_LOG_PINNED:
            return "STATUS_LOG_PINNED";
        case STATUS_LOG_METADATA_FLUSH_FAILED:
            return "STATUS_LOG_METADATA_FLUSH_FAILED";
        case STATUS_LOG_INCONSISTENT_SECURITY:
            return "STATUS_LOG_INCONSISTENT_SECURITY";
        case STATUS_LOG_APPENDED_FLUSH_FAILED:
            return "STATUS_LOG_APPENDED_FLUSH_FAILED";
        case STATUS_LOG_PINNED_RESERVATION:
            return "STATUS_LOG_PINNED_RESERVATION";
        case STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD:
            return "STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD";
        case STATUS_FLT_NO_HANDLER_DEFINED:
            return "STATUS_FLT_NO_HANDLER_DEFINED";
        case STATUS_FLT_CONTEXT_ALREADY_DEFINED:
            return "STATUS_FLT_CONTEXT_ALREADY_DEFINED";
        case STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST:
            return "STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST";
        case STATUS_FLT_DISALLOW_FAST_IO:
            return "STATUS_FLT_DISALLOW_FAST_IO";
        case STATUS_FLT_INVALID_NAME_REQUEST:
            return "STATUS_FLT_INVALID_NAME_REQUEST";
        case STATUS_FLT_NOT_SAFE_TO_POST_OPERATION:
            return "STATUS_FLT_NOT_SAFE_TO_POST_OPERATION";
        case STATUS_FLT_NOT_INITIALIZED:
            return "STATUS_FLT_NOT_INITIALIZED";
        case STATUS_FLT_FILTER_NOT_READY:
            return "STATUS_FLT_FILTER_NOT_READY";
        case STATUS_FLT_POST_OPERATION_CLEANUP:
            return "STATUS_FLT_POST_OPERATION_CLEANUP";
        case STATUS_FLT_INTERNAL_ERROR:
            return "STATUS_FLT_INTERNAL_ERROR";
        case STATUS_FLT_DELETING_OBJECT:
            return "STATUS_FLT_DELETING_OBJECT";
        case STATUS_FLT_MUST_BE_NONPAGED_POOL:
            return "STATUS_FLT_MUST_BE_NONPAGED_POOL";
        case STATUS_FLT_DUPLICATE_ENTRY:
            return "STATUS_FLT_DUPLICATE_ENTRY";
        case STATUS_FLT_CBDQ_DISABLED:
            return "STATUS_FLT_CBDQ_DISABLED";
        case STATUS_FLT_DO_NOT_ATTACH:
            return "STATUS_FLT_DO_NOT_ATTACH";
        case STATUS_FLT_DO_NOT_DETACH:
            return "STATUS_FLT_DO_NOT_DETACH";
        case STATUS_FLT_INSTANCE_ALTITUDE_COLLISION:
            return "STATUS_FLT_INSTANCE_ALTITUDE_COLLISION";
        case STATUS_FLT_INSTANCE_NAME_COLLISION:
            return "STATUS_FLT_INSTANCE_NAME_COLLISION";
        case STATUS_FLT_FILTER_NOT_FOUND:
            return "STATUS_FLT_FILTER_NOT_FOUND";
        case STATUS_FLT_VOLUME_NOT_FOUND:
            return "STATUS_FLT_VOLUME_NOT_FOUND";
        case STATUS_FLT_INSTANCE_NOT_FOUND:
            return "STATUS_FLT_INSTANCE_NOT_FOUND";
        case STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND:
            return "STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND";
        case STATUS_FLT_INVALID_CONTEXT_REGISTRATION:
            return "STATUS_FLT_INVALID_CONTEXT_REGISTRATION";
        case STATUS_FLT_NAME_CACHE_MISS:
            return "STATUS_FLT_NAME_CACHE_MISS";
        case STATUS_FLT_NO_DEVICE_OBJECT:
            return "STATUS_FLT_NO_DEVICE_OBJECT";
        case STATUS_FLT_VOLUME_ALREADY_MOUNTED:
            return "STATUS_FLT_VOLUME_ALREADY_MOUNTED";
        case STATUS_FLT_ALREADY_ENLISTED:
            return "STATUS_FLT_ALREADY_ENLISTED";
        case STATUS_FLT_CONTEXT_ALREADY_LINKED:
            return "STATUS_FLT_CONTEXT_ALREADY_LINKED";
        case STATUS_FLT_NO_WAITER_FOR_REPLY:
            return "STATUS_FLT_NO_WAITER_FOR_REPLY";
        case STATUS_MONITOR_NO_DESCRIPTOR:
            return "STATUS_MONITOR_NO_DESCRIPTOR";
        case STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT:
            return "STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT";
        case STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM:
            return "STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM";
        case STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK:
            return "STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK";
        case STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED:
            return "STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED";
        case STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK:
            return "STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK";
        case STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK:
            return "STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK";
        case STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA:
            return "STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA";
        case STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK:
            return "STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK";
        case STATUS_MONITOR_INVALID_MANUFACTURE_DATE:
            return "STATUS_MONITOR_INVALID_MANUFACTURE_DATE";
        case STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER:
            return "STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER";
        case STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER:
            return "STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER";
        case STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER:
            return "STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER";
        case STATUS_GRAPHICS_ADAPTER_WAS_RESET:
            return "STATUS_GRAPHICS_ADAPTER_WAS_RESET";
        case STATUS_GRAPHICS_INVALID_DRIVER_MODEL:
            return "STATUS_GRAPHICS_INVALID_DRIVER_MODEL";
        case STATUS_GRAPHICS_PRESENT_MODE_CHANGED:
            return "STATUS_GRAPHICS_PRESENT_MODE_CHANGED";
        case STATUS_GRAPHICS_PRESENT_OCCLUDED:
            return "STATUS_GRAPHICS_PRESENT_OCCLUDED";
        case STATUS_GRAPHICS_PRESENT_DENIED:
            return "STATUS_GRAPHICS_PRESENT_DENIED";
        case STATUS_GRAPHICS_CANNOTCOLORCONVERT:
            return "STATUS_GRAPHICS_CANNOTCOLORCONVERT";
        case STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED:
            return "STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED";
        case STATUS_GRAPHICS_PRESENT_UNOCCLUDED:
            return "STATUS_GRAPHICS_PRESENT_UNOCCLUDED";
        case STATUS_GRAPHICS_NO_VIDEO_MEMORY:
            return "STATUS_GRAPHICS_NO_VIDEO_MEMORY";
        case STATUS_GRAPHICS_CANT_LOCK_MEMORY:
            return "STATUS_GRAPHICS_CANT_LOCK_MEMORY";
        case STATUS_GRAPHICS_ALLOCATION_BUSY:
            return "STATUS_GRAPHICS_ALLOCATION_BUSY";
        case STATUS_GRAPHICS_TOO_MANY_REFERENCES:
            return "STATUS_GRAPHICS_TOO_MANY_REFERENCES";
        case STATUS_GRAPHICS_TRY_AGAIN_LATER:
            return "STATUS_GRAPHICS_TRY_AGAIN_LATER";
        case STATUS_GRAPHICS_TRY_AGAIN_NOW:
            return "STATUS_GRAPHICS_TRY_AGAIN_NOW";
        case STATUS_GRAPHICS_ALLOCATION_INVALID:
            return "STATUS_GRAPHICS_ALLOCATION_INVALID";
        case STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE:
            return "STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE";
        case STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED:
            return "STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED";
        case STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION:
            return "STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION";
        case STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE:
            return "STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE";
        case STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION:
            return "STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION";
        case STATUS_GRAPHICS_ALLOCATION_CLOSED:
            return "STATUS_GRAPHICS_ALLOCATION_CLOSED";
        case STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE:
            return "STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE";
        case STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE:
            return "STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE";
        case STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE:
            return "STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE";
        case STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST:
            return "STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST";
        case STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE:
            return "STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE";
        case STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY:
            return "STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY";
        case STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED";
        case STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED";
        case STATUS_GRAPHICS_INVALID_VIDPN:
            return "STATUS_GRAPHICS_INVALID_VIDPN";
        case STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE:
            return "STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE";
        case STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET:
            return "STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET";
        case STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED";
        case STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET:
            return "STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET";
        case STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET:
            return "STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET";
        case STATUS_GRAPHICS_INVALID_FREQUENCY:
            return "STATUS_GRAPHICS_INVALID_FREQUENCY";
        case STATUS_GRAPHICS_INVALID_ACTIVE_REGION:
            return "STATUS_GRAPHICS_INVALID_ACTIVE_REGION";
        case STATUS_GRAPHICS_INVALID_TOTAL_REGION:
            return "STATUS_GRAPHICS_INVALID_TOTAL_REGION";
        case STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE:
            return "STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE";
        case STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE:
            return "STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE";
        case STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET:
            return "STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET";
        case STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY:
            return "STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY";
        case STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET:
            return "STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET";
        case STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET:
            return "STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET";
        case STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET:
            return "STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET";
        case STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET:
            return "STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET";
        case STATUS_GRAPHICS_TARGET_ALREADY_IN_SET:
            return "STATUS_GRAPHICS_TARGET_ALREADY_IN_SET";
        case STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH:
            return "STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH";
        case STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY:
            return "STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY";
        case STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET:
            return "STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET";
        case STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE:
            return "STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE";
        case STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET:
            return "STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET";
        case STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET:
            return "STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET";
        case STATUS_GRAPHICS_STALE_MODESET:
            return "STATUS_GRAPHICS_STALE_MODESET";
        case STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET:
            return "STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET";
        case STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE:
            return "STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE";
        case STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN:
            return "STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN";
        case STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE:
            return "STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE";
        case STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION:
            return "STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION";
        case STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES:
            return "STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES";
        case STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY:
            return "STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY";
        case STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE:
            return "STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE";
        case STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET:
            return "STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET";
        case STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET:
            return "STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET";
        case STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR:
            return "STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR";
        case STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET:
            return "STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET";
        case STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET:
            return "STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET";
        case STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE:
            return "STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE";
        case STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE:
            return "STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE";
        case STATUS_GRAPHICS_RESOURCES_NOT_RELATED:
            return "STATUS_GRAPHICS_RESOURCES_NOT_RELATED";
        case STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE:
            return "STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE";
        case STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE:
            return "STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE";
        case STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET:
            return "STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET";
        case STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER:
            return "STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER";
        case STATUS_GRAPHICS_NO_VIDPNMGR:
            return "STATUS_GRAPHICS_NO_VIDPNMGR";
        case STATUS_GRAPHICS_NO_ACTIVE_VIDPN:
            return "STATUS_GRAPHICS_NO_ACTIVE_VIDPN";
        case STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY:
            return "STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY";
        case STATUS_GRAPHICS_MONITOR_NOT_CONNECTED:
            return "STATUS_GRAPHICS_MONITOR_NOT_CONNECTED";
        case STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY:
            return "STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY";
        case STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE:
            return "STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE";
        case STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE:
            return "STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE";
        case STATUS_GRAPHICS_INVALID_STRIDE:
            return "STATUS_GRAPHICS_INVALID_STRIDE";
        case STATUS_GRAPHICS_INVALID_PIXELFORMAT:
            return "STATUS_GRAPHICS_INVALID_PIXELFORMAT";
        case STATUS_GRAPHICS_INVALID_COLORBASIS:
            return "STATUS_GRAPHICS_INVALID_COLORBASIS";
        case STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE:
            return "STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE";
        case STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY:
            return "STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY";
        case STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT:
            return "STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT";
        case STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE:
            return "STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE";
        case STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN:
            return "STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN";
        case STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL:
            return "STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL";
        case STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION:
            return "STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION";
        case STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED";
        case STATUS_GRAPHICS_INVALID_GAMMA_RAMP:
            return "STATUS_GRAPHICS_INVALID_GAMMA_RAMP";
        case STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED";
        case STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED";
        case STATUS_GRAPHICS_MODE_NOT_IN_MODESET:
            return "STATUS_GRAPHICS_MODE_NOT_IN_MODESET";
        case STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON:
            return "STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON";
        case STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE:
            return "STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE";
        case STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE:
            return "STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE";
        case STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS:
            return "STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS";
        case STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING:
            return "STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING";
        case STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED:
            return "STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED";
        case STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS:
            return "STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS";
        case STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT:
            return "STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT";
        case STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM:
            return "STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM";
        case STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN:
            return "STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN";
        case STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT:
            return "STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT";
        case STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED:
            return "STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED";
        case STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION:
            return "STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION";
        case STATUS_GRAPHICS_INVALID_CLIENT_TYPE:
            return "STATUS_GRAPHICS_INVALID_CLIENT_TYPE";
        case STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET:
            return "STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET";
        case STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED:
            return "STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED";
        case STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED";
        case STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER:
            return "STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER";
        case STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED:
            return "STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED";
        case STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED:
            return "STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED";
        case STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY:
            return "STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY";
        case STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED:
            return "STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED";
        case STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON:
            return "STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON";
        case STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE:
            return "STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE";
        case STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER:
            return "STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER";
        case STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED:
            return "STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED";
        case STATUS_GRAPHICS_OPM_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_OPM_NOT_SUPPORTED";
        case STATUS_GRAPHICS_COPP_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_COPP_NOT_SUPPORTED";
        case STATUS_GRAPHICS_UAB_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_UAB_NOT_SUPPORTED";
        case STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS:
            return "STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS";
        case STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST:
            return "STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST";
        case STATUS_GRAPHICS_OPM_INTERNAL_ERROR:
            return "STATUS_GRAPHICS_OPM_INTERNAL_ERROR";
        case STATUS_GRAPHICS_OPM_INVALID_HANDLE:
            return "STATUS_GRAPHICS_OPM_INVALID_HANDLE";
        case STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH:
            return "STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH";
        case STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED:
            return "STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED";
        case STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED:
            return "STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED";
        case STATUS_GRAPHICS_PVP_HFS_FAILED:
            return "STATUS_GRAPHICS_PVP_HFS_FAILED";
        case STATUS_GRAPHICS_OPM_INVALID_SRM:
            return "STATUS_GRAPHICS_OPM_INVALID_SRM";
        case STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP:
            return "STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP";
        case STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP:
            return "STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP";
        case STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA:
            return "STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA";
        case STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET:
            return "STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET";
        case STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH:
            return "STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH";
        case STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE:
            return "STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE";
        case STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS:
            return "STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS";
        case STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS:
            return "STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS";
        case STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST:
            return "STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST";
        case STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR:
            return "STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR";
        case STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS:
            return "STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS";
        case STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED";
        case STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST:
            return "STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST";
        case STATUS_GRAPHICS_I2C_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_I2C_NOT_SUPPORTED";
        case STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST:
            return "STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST";
        case STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA:
            return "STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA";
        case STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA:
            return "STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA";
        case STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED";
        case STATUS_GRAPHICS_DDCCI_INVALID_DATA:
            return "STATUS_GRAPHICS_DDCCI_INVALID_DATA";
        case STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE:
            return "STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE";
        case STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING:
            return "STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING";
        case STATUS_GRAPHICS_MCA_INTERNAL_ERROR:
            return "STATUS_GRAPHICS_MCA_INTERNAL_ERROR";
        case STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND:
            return "STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND";
        case STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH:
            return "STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH";
        case STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM:
            return "STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM";
        case STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE:
            return "STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE";
        case STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS:
            return "STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS";
        case STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED:
            return "STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED";
        case STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME:
            return "STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME";
        case STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP:
            return "STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP";
        case STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED";
        case STATUS_GRAPHICS_INVALID_POINTER:
            return "STATUS_GRAPHICS_INVALID_POINTER";
        case STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE:
            return "STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE";
        case STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL:
            return "STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL";
        case STATUS_GRAPHICS_INTERNAL_ERROR:
            return "STATUS_GRAPHICS_INTERNAL_ERROR";
        case STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS:
            return "STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS";
        case STATUS_FVE_LOCKED_VOLUME:
            return "STATUS_FVE_LOCKED_VOLUME";
        case STATUS_FVE_NOT_ENCRYPTED:
            return "STATUS_FVE_NOT_ENCRYPTED";
        case STATUS_FVE_BAD_INFORMATION:
            return "STATUS_FVE_BAD_INFORMATION";
        case STATUS_FVE_TOO_SMALL:
            return "STATUS_FVE_TOO_SMALL";
        case STATUS_FVE_FAILED_WRONG_FS:
            return "STATUS_FVE_FAILED_WRONG_FS";
        case STATUS_FVE_FS_NOT_EXTENDED:
            return "STATUS_FVE_FS_NOT_EXTENDED";
        case STATUS_FVE_FS_MOUNTED:
            return "STATUS_FVE_FS_MOUNTED";
        case STATUS_FVE_NO_LICENSE:
            return "STATUS_FVE_NO_LICENSE";
        case STATUS_FVE_ACTION_NOT_ALLOWED:
            return "STATUS_FVE_ACTION_NOT_ALLOWED";
        case STATUS_FVE_BAD_DATA:
            return "STATUS_FVE_BAD_DATA";
        case STATUS_FVE_VOLUME_NOT_BOUND:
            return "STATUS_FVE_VOLUME_NOT_BOUND";
        case STATUS_FVE_NOT_DATA_VOLUME:
            return "STATUS_FVE_NOT_DATA_VOLUME";
        case STATUS_FVE_CONV_READ_ERROR:
            return "STATUS_FVE_CONV_READ_ERROR";
        case STATUS_FVE_CONV_WRITE_ERROR:
            return "STATUS_FVE_CONV_WRITE_ERROR";
        case STATUS_FVE_OVERLAPPED_UPDATE:
            return "STATUS_FVE_OVERLAPPED_UPDATE";
        case STATUS_FVE_FAILED_SECTOR_SIZE:
            return "STATUS_FVE_FAILED_SECTOR_SIZE";
        case STATUS_FVE_FAILED_AUTHENTICATION:
            return "STATUS_FVE_FAILED_AUTHENTICATION";
        case STATUS_FVE_NOT_OS_VOLUME:
            return "STATUS_FVE_NOT_OS_VOLUME";
        case STATUS_FVE_KEYFILE_NOT_FOUND:
            return "STATUS_FVE_KEYFILE_NOT_FOUND";
        case STATUS_FVE_KEYFILE_INVALID:
            return "STATUS_FVE_KEYFILE_INVALID";
        case STATUS_FVE_KEYFILE_NO_VMK:
            return "STATUS_FVE_KEYFILE_NO_VMK";
        case STATUS_FVE_TPM_DISABLED:
            return "STATUS_FVE_TPM_DISABLED";
        case STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO:
            return "STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO";
        case STATUS_FVE_TPM_INVALID_PCR:
            return "STATUS_FVE_TPM_INVALID_PCR";
        case STATUS_FVE_TPM_NO_VMK:
            return "STATUS_FVE_TPM_NO_VMK";
        case STATUS_FVE_PIN_INVALID:
            return "STATUS_FVE_PIN_INVALID";
        case STATUS_FVE_AUTH_INVALID_APPLICATION:
            return "STATUS_FVE_AUTH_INVALID_APPLICATION";
        case STATUS_FVE_AUTH_INVALID_CONFIG:
            return "STATUS_FVE_AUTH_INVALID_CONFIG";
        case STATUS_FVE_DEBUGGER_ENABLED:
            return "STATUS_FVE_DEBUGGER_ENABLED";
        case STATUS_FVE_DRY_RUN_FAILED:
            return "STATUS_FVE_DRY_RUN_FAILED";
        case STATUS_FVE_BAD_METADATA_POINTER:
            return "STATUS_FVE_BAD_METADATA_POINTER";
        case STATUS_FVE_OLD_METADATA_COPY:
            return "STATUS_FVE_OLD_METADATA_COPY";
        case STATUS_FVE_REBOOT_REQUIRED:
            return "STATUS_FVE_REBOOT_REQUIRED";
        case STATUS_FVE_RAW_ACCESS:
            return "STATUS_FVE_RAW_ACCESS";
        case STATUS_FVE_RAW_BLOCKED:
            return "STATUS_FVE_RAW_BLOCKED";
        case STATUS_FVE_NO_FEATURE_LICENSE:
            return "STATUS_FVE_NO_FEATURE_LICENSE";
        case STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED:
            return "STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED";
        case STATUS_FVE_CONV_RECOVERY_FAILED:
            return "STATUS_FVE_CONV_RECOVERY_FAILED";
        case STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG:
            return "STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG";
        case STATUS_FVE_VOLUME_TOO_SMALL:
            return "STATUS_FVE_VOLUME_TOO_SMALL";
        case STATUS_FWP_CALLOUT_NOT_FOUND:
            return "STATUS_FWP_CALLOUT_NOT_FOUND";
        case STATUS_FWP_CONDITION_NOT_FOUND:
            return "STATUS_FWP_CONDITION_NOT_FOUND";
        case STATUS_FWP_FILTER_NOT_FOUND:
            return "STATUS_FWP_FILTER_NOT_FOUND";
        case STATUS_FWP_LAYER_NOT_FOUND:
            return "STATUS_FWP_LAYER_NOT_FOUND";
        case STATUS_FWP_PROVIDER_NOT_FOUND:
            return "STATUS_FWP_PROVIDER_NOT_FOUND";
        case STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND:
            return "STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND";
        case STATUS_FWP_SUBLAYER_NOT_FOUND:
            return "STATUS_FWP_SUBLAYER_NOT_FOUND";
        case STATUS_FWP_NOT_FOUND:
            return "STATUS_FWP_NOT_FOUND";
        case STATUS_FWP_ALREADY_EXISTS:
            return "STATUS_FWP_ALREADY_EXISTS";
        case STATUS_FWP_IN_USE:
            return "STATUS_FWP_IN_USE";
        case STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS:
            return "STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS";
        case STATUS_FWP_WRONG_SESSION:
            return "STATUS_FWP_WRONG_SESSION";
        case STATUS_FWP_NO_TXN_IN_PROGRESS:
            return "STATUS_FWP_NO_TXN_IN_PROGRESS";
        case STATUS_FWP_TXN_IN_PROGRESS:
            return "STATUS_FWP_TXN_IN_PROGRESS";
        case STATUS_FWP_TXN_ABORTED:
            return "STATUS_FWP_TXN_ABORTED";
        case STATUS_FWP_SESSION_ABORTED:
            return "STATUS_FWP_SESSION_ABORTED";
        case STATUS_FWP_INCOMPATIBLE_TXN:
            return "STATUS_FWP_INCOMPATIBLE_TXN";
        case STATUS_FWP_TIMEOUT:
            return "STATUS_FWP_TIMEOUT";
        case STATUS_FWP_NET_EVENTS_DISABLED:
            return "STATUS_FWP_NET_EVENTS_DISABLED";
        case STATUS_FWP_INCOMPATIBLE_LAYER:
            return "STATUS_FWP_INCOMPATIBLE_LAYER";
        case STATUS_FWP_KM_CLIENTS_ONLY:
            return "STATUS_FWP_KM_CLIENTS_ONLY";
        case STATUS_FWP_LIFETIME_MISMATCH:
            return "STATUS_FWP_LIFETIME_MISMATCH";
        case STATUS_FWP_BUILTIN_OBJECT:
            return "STATUS_FWP_BUILTIN_OBJECT";
        case STATUS_FWP_NOTIFICATION_DROPPED:
            return "STATUS_FWP_NOTIFICATION_DROPPED";
        case STATUS_FWP_TRAFFIC_MISMATCH:
            return "STATUS_FWP_TRAFFIC_MISMATCH";
        case STATUS_FWP_INCOMPATIBLE_SA_STATE:
            return "STATUS_FWP_INCOMPATIBLE_SA_STATE";
        case STATUS_FWP_NULL_POINTER:
            return "STATUS_FWP_NULL_POINTER";
        case STATUS_FWP_INVALID_ENUMERATOR:
            return "STATUS_FWP_INVALID_ENUMERATOR";
        case STATUS_FWP_INVALID_FLAGS:
            return "STATUS_FWP_INVALID_FLAGS";
        case STATUS_FWP_INVALID_NET_MASK:
            return "STATUS_FWP_INVALID_NET_MASK";
        case STATUS_FWP_INVALID_RANGE:
            return "STATUS_FWP_INVALID_RANGE";
        case STATUS_FWP_INVALID_INTERVAL:
            return "STATUS_FWP_INVALID_INTERVAL";
        case STATUS_FWP_ZERO_LENGTH_ARRAY:
            return "STATUS_FWP_ZERO_LENGTH_ARRAY";
        case STATUS_FWP_NULL_DISPLAY_NAME:
            return "STATUS_FWP_NULL_DISPLAY_NAME";
        case STATUS_FWP_INVALID_ACTION_TYPE:
            return "STATUS_FWP_INVALID_ACTION_TYPE";
        case STATUS_FWP_INVALID_WEIGHT:
            return "STATUS_FWP_INVALID_WEIGHT";
        case STATUS_FWP_MATCH_TYPE_MISMATCH:
            return "STATUS_FWP_MATCH_TYPE_MISMATCH";
        case STATUS_FWP_TYPE_MISMATCH:
            return "STATUS_FWP_TYPE_MISMATCH";
        case STATUS_FWP_OUT_OF_BOUNDS:
            return "STATUS_FWP_OUT_OF_BOUNDS";
        case STATUS_FWP_RESERVED:
            return "STATUS_FWP_RESERVED";
        case STATUS_FWP_DUPLICATE_CONDITION:
            return "STATUS_FWP_DUPLICATE_CONDITION";
        case STATUS_FWP_DUPLICATE_KEYMOD:
            return "STATUS_FWP_DUPLICATE_KEYMOD";
        case STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER:
            return "STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER";
        case STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER:
            return "STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER";
        case STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER:
            return "STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER";
        case STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT:
            return "STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT";
        case STATUS_FWP_INCOMPATIBLE_AUTH_METHOD:
            return "STATUS_FWP_INCOMPATIBLE_AUTH_METHOD";
        case STATUS_FWP_INCOMPATIBLE_DH_GROUP:
            return "STATUS_FWP_INCOMPATIBLE_DH_GROUP";
        case STATUS_FWP_EM_NOT_SUPPORTED:
            return "STATUS_FWP_EM_NOT_SUPPORTED";
        case STATUS_FWP_NEVER_MATCH:
            return "STATUS_FWP_NEVER_MATCH";
        case STATUS_FWP_PROVIDER_CONTEXT_MISMATCH:
            return "STATUS_FWP_PROVIDER_CONTEXT_MISMATCH";
        case STATUS_FWP_INVALID_PARAMETER:
            return "STATUS_FWP_INVALID_PARAMETER";
        case STATUS_FWP_TOO_MANY_SUBLAYERS:
            return "STATUS_FWP_TOO_MANY_SUBLAYERS";
        case STATUS_FWP_CALLOUT_NOTIFICATION_FAILED:
            return "STATUS_FWP_CALLOUT_NOTIFICATION_FAILED";
        case STATUS_FWP_DUPLICATE_AUTH_METHOD:
            return "STATUS_FWP_DUPLICATE_AUTH_METHOD";
        case STATUS_FWP_TCPIP_NOT_READY:
            return "STATUS_FWP_TCPIP_NOT_READY";
        case STATUS_FWP_INJECT_HANDLE_CLOSING:
            return "STATUS_FWP_INJECT_HANDLE_CLOSING";
        case STATUS_FWP_INJECT_HANDLE_STALE:
            return "STATUS_FWP_INJECT_HANDLE_STALE";
        case STATUS_FWP_CANNOT_PEND:
            return "STATUS_FWP_CANNOT_PEND";
        case STATUS_NDIS_CLOSING:
            return "STATUS_NDIS_CLOSING";
        case STATUS_NDIS_BAD_VERSION:
            return "STATUS_NDIS_BAD_VERSION";
        case STATUS_NDIS_BAD_CHARACTERISTICS:
            return "STATUS_NDIS_BAD_CHARACTERISTICS";
        case STATUS_NDIS_ADAPTER_NOT_FOUND:
            return "STATUS_NDIS_ADAPTER_NOT_FOUND";
        case STATUS_NDIS_OPEN_FAILED:
            return "STATUS_NDIS_OPEN_FAILED";
        case STATUS_NDIS_DEVICE_FAILED:
            return "STATUS_NDIS_DEVICE_FAILED";
        case STATUS_NDIS_MULTICAST_FULL:
            return "STATUS_NDIS_MULTICAST_FULL";
        case STATUS_NDIS_MULTICAST_EXISTS:
            return "STATUS_NDIS_MULTICAST_EXISTS";
        case STATUS_NDIS_MULTICAST_NOT_FOUND:
            return "STATUS_NDIS_MULTICAST_NOT_FOUND";
        case STATUS_NDIS_REQUEST_ABORTED:
            return "STATUS_NDIS_REQUEST_ABORTED";
        case STATUS_NDIS_RESET_IN_PROGRESS:
            return "STATUS_NDIS_RESET_IN_PROGRESS";
        case STATUS_NDIS_INVALID_PACKET:
            return "STATUS_NDIS_INVALID_PACKET";
        case STATUS_NDIS_INVALID_DEVICE_REQUEST:
            return "STATUS_NDIS_INVALID_DEVICE_REQUEST";
        case STATUS_NDIS_ADAPTER_NOT_READY:
            return "STATUS_NDIS_ADAPTER_NOT_READY";
        case STATUS_NDIS_INVALID_LENGTH:
            return "STATUS_NDIS_INVALID_LENGTH";
        case STATUS_NDIS_INVALID_DATA:
            return "STATUS_NDIS_INVALID_DATA";
        case STATUS_NDIS_BUFFER_TOO_SHORT:
            return "STATUS_NDIS_BUFFER_TOO_SHORT";
        case STATUS_NDIS_INVALID_OID:
            return "STATUS_NDIS_INVALID_OID";
        case STATUS_NDIS_ADAPTER_REMOVED:
            return "STATUS_NDIS_ADAPTER_REMOVED";
        case STATUS_NDIS_UNSUPPORTED_MEDIA:
            return "STATUS_NDIS_UNSUPPORTED_MEDIA";
        case STATUS_NDIS_GROUP_ADDRESS_IN_USE:
            return "STATUS_NDIS_GROUP_ADDRESS_IN_USE";
        case STATUS_NDIS_FILE_NOT_FOUND:
            return "STATUS_NDIS_FILE_NOT_FOUND";
        case STATUS_NDIS_ERROR_READING_FILE:
            return "STATUS_NDIS_ERROR_READING_FILE";
        case STATUS_NDIS_ALREADY_MAPPED:
            return "STATUS_NDIS_ALREADY_MAPPED";
        case STATUS_NDIS_RESOURCE_CONFLICT:
            return "STATUS_NDIS_RESOURCE_CONFLICT";
        case STATUS_NDIS_MEDIA_DISCONNECTED:
            return "STATUS_NDIS_MEDIA_DISCONNECTED";
        case STATUS_NDIS_INVALID_ADDRESS:
            return "STATUS_NDIS_INVALID_ADDRESS";
        case STATUS_NDIS_PAUSED:
            return "STATUS_NDIS_PAUSED";
        case STATUS_NDIS_INTERFACE_NOT_FOUND:
            return "STATUS_NDIS_INTERFACE_NOT_FOUND";
        case STATUS_NDIS_UNSUPPORTED_REVISION:
            return "STATUS_NDIS_UNSUPPORTED_REVISION";
        case STATUS_NDIS_INVALID_PORT:
            return "STATUS_NDIS_INVALID_PORT";
        case STATUS_NDIS_INVALID_PORT_STATE:
            return "STATUS_NDIS_INVALID_PORT_STATE";
        case STATUS_NDIS_LOW_POWER_STATE:
            return "STATUS_NDIS_LOW_POWER_STATE";
        case STATUS_NDIS_NOT_SUPPORTED:
            return "STATUS_NDIS_NOT_SUPPORTED";
        case STATUS_NDIS_OFFLOAD_POLICY:
            return "STATUS_NDIS_OFFLOAD_POLICY";
        case STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED:
            return "STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED";
        case STATUS_NDIS_OFFLOAD_PATH_REJECTED:
            return "STATUS_NDIS_OFFLOAD_PATH_REJECTED";
        case STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED:
            return "STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED";
        case STATUS_NDIS_DOT11_MEDIA_IN_USE:
            return "STATUS_NDIS_DOT11_MEDIA_IN_USE";
        case STATUS_NDIS_DOT11_POWER_STATE_INVALID:
            return "STATUS_NDIS_DOT11_POWER_STATE_INVALID";
        case STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL:
            return "STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL";
        case STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL:
            return "STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL";
        case STATUS_IPSEC_BAD_SPI:
            return "STATUS_IPSEC_BAD_SPI";
        case STATUS_IPSEC_SA_LIFETIME_EXPIRED:
            return "STATUS_IPSEC_SA_LIFETIME_EXPIRED";
        case STATUS_IPSEC_WRONG_SA:
            return "STATUS_IPSEC_WRONG_SA";
        case STATUS_IPSEC_REPLAY_CHECK_FAILED:
            return "STATUS_IPSEC_REPLAY_CHECK_FAILED";
        case STATUS_IPSEC_INVALID_PACKET:
            return "STATUS_IPSEC_INVALID_PACKET";
        case STATUS_IPSEC_INTEGRITY_CHECK_FAILED:
            return "STATUS_IPSEC_INTEGRITY_CHECK_FAILED";
        case STATUS_IPSEC_CLEAR_TEXT_DROP:
            return "STATUS_IPSEC_CLEAR_TEXT_DROP";
        case STATUS_IPSEC_AUTH_FIREWALL_DROP:
            return "STATUS_IPSEC_AUTH_FIREWALL_DROP";
        case STATUS_IPSEC_THROTTLE_DROP:
            return "STATUS_IPSEC_THROTTLE_DROP";
        case STATUS_IPSEC_DOSP_BLOCK:
            return "STATUS_IPSEC_DOSP_BLOCK";
        case STATUS_IPSEC_DOSP_RECEIVED_MULTICAST:
            return "STATUS_IPSEC_DOSP_RECEIVED_MULTICAST";
        case STATUS_IPSEC_DOSP_INVALID_PACKET:
            return "STATUS_IPSEC_DOSP_INVALID_PACKET";
        case STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED:
            return "STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED";
        case STATUS_IPSEC_DOSP_MAX_ENTRIES:
            return "STATUS_IPSEC_DOSP_MAX_ENTRIES";
        case STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED:
            return "STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED";
        case STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES:
            return "STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES";
        case STATUS_VOLMGR_MIRROR_NOT_SUPPORTED:
            return "STATUS_VOLMGR_MIRROR_NOT_SUPPORTED";
        case STATUS_VOLMGR_RAID5_NOT_SUPPORTED:
            return "STATUS_VOLMGR_RAID5_NOT_SUPPORTED";
        case STATUS_VIRTDISK_PROVIDER_NOT_FOUND:
            return "STATUS_VIRTDISK_PROVIDER_NOT_FOUND";
        case STATUS_VIRTDISK_NOT_VIRTUAL_DISK:
            return "STATUS_VIRTDISK_NOT_VIRTUAL_DISK";
        case STATUS_VHD_PARENT_VHD_ACCESS_DENIED:
            return "STATUS_VHD_PARENT_VHD_ACCESS_DENIED";
        case STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH:
            return "STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH";
        case STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED:
            return "STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED";
        case STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT:
            return "STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT";
        case STATUS_CASE_DIFFERING_NAMES_IN_DIR:
            return "STATUS_CASE_DIFFERING_NAMES_IN_DIR";
        default:
#if __has_include(<format>)
            return std::format("Status {:08x}", (uint32_t)s);
#else
            return fmt::format("Status {:08x}", (uint32_t)s);
#endif
    }
}

class ntstatus_error : public std::exception {
public:
    ntstatus_error(NTSTATUS Status) : Status(Status) {
        msg = ntstatus_to_string(Status);
    }

    const char* what() const noexcept override {
        return msg.c_str();
    }

    NTSTATUS Status;
    std::string msg;
};

class _formatted_error : public std::exception {
public:
    template<typename T, typename... Args>
    _formatted_error(const T& s, Args&&... args) {
#if __has_include(<format>)
        msg = std::format(s, std::forward<Args>(args)...);
#else
        msg = fmt::format(s, std::forward<Args>(args)...);
#endif
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    std::string msg;
};

#if __has_include(<format>)
#define formatted_error(s, ...) _formatted_error(s, ##__VA_ARGS__)
#else
#define formatted_error(s, ...) _formatted_error(FMT_COMPILE(s), ##__VA_ARGS__)
#endif

template<typename T>
T query_information(HANDLE h);

template<typename T>
class varbuf {
public:
    T* operator*() {
        return (T*)buf.data();
    }

    operator T*() {
        return (T*)buf.data();
    }

    operator const T*() const {
        return (const T*)buf.data();
    }

    std::vector<uint8_t> buf;
};

// test.cpp
unique_handle create_file(const std::u16string_view& path, ACCESS_MASK access, ULONG atts, ULONG share,
                          ULONG dispo, ULONG options, ULONG_PTR exp_info, std::optional<uint64_t> allocation = std::nullopt);

template<typename T>
std::vector<varbuf<T>> query_dir(const std::u16string& dir, std::u16string_view filter);
varbuf<FILE_ALL_INFORMATION> query_all_information(HANDLE h);
void test(const std::string& msg, const std::function<void()>& func);
void exp_status(const std::function<void()>& func, NTSTATUS Status);
std::u16string query_file_name_information(HANDLE h, bool normalized = false);
void disable_token_privileges(HANDLE token);
std::string u16string_to_string(const std::u16string_view& sv);

extern enum fs_type fstype;

// create.cpp
void test_create(HANDLE token, const std::u16string& dir);
void test_open_id(HANDLE token, const std::u16string& dir);

// supersede.cpp
void test_supersede(const std::u16string& dir);

// overwrite.cpp
void test_overwrite(const std::u16string& dir);

// io.cpp
void test_io(HANDLE token, const std::u16string& dir);
std::vector<uint8_t> random_data(size_t len);
void write_file(HANDLE h, std::span<const uint8_t> data, std::optional<uint64_t> offset = std::nullopt);
void set_end_of_file(HANDLE h, uint64_t eof);
std::vector<uint8_t> read_file(HANDLE h, ULONG len, std::optional<uint64_t> offset = std::nullopt);
void write_file_wait(HANDLE h, std::span<const uint8_t> data, std::optional<uint64_t> offset = std::nullopt);
std::vector<uint8_t> read_file_wait(HANDLE h, ULONG len, std::optional<uint64_t> offset = std::nullopt);
void set_allocation(HANDLE h, uint64_t alloc);
void set_valid_data_length(HANDLE h, uint64_t vdl);
void set_zero_data(HANDLE h, uint64_t start, uint64_t end);
unique_handle create_event();
void adjust_token_privileges(HANDLE token, const LUID_AND_ATTRIBUTES& priv);

// mmap.cpp
void test_mmap(const std::u16string& dir);
unique_handle create_section(ACCESS_MASK access, std::optional<uint64_t> max_size, ULONG prot,
                             ULONG atts, HANDLE file);
std::vector<uint8_t> pe_image(std::span<const std::byte> data);

// rename.cpp
void test_rename(const std::u16string& dir);
void test_rename_ex(HANDLE token, const std::u16string& dir);
void set_rename_information(HANDLE h, bool replace_if_exists, HANDLE root_dir, const std::u16string_view& filename);

// delete.cpp
void test_delete(const std::u16string& dir);
void test_delete_ex(HANDLE token, const std::u16string& dir);
void set_disposition_information(HANDLE h, bool delete_file);
void set_disposition_information_ex(HANDLE h, uint32_t flags);

// links.cpp
void test_links(HANDLE token, const std::u16string& dir);
void test_links_ex(HANDLE token, const std::u16string& dir);
std::vector<std::pair<int64_t, std::u16string>> query_links(HANDLE h);
void set_link_information(HANDLE h, bool replace_if_exists, HANDLE root_dir, const std::u16string_view& filename);

// oplock.cpp
void test_oplocks_i(HANDLE token, const std::u16string& dir);
void test_oplocks_ii(HANDLE token, const std::u16string& dir);
void test_oplocks_batch(HANDLE token, const std::u16string& dir);
void test_oplocks_filter(HANDLE token, const std::u16string& dir);
void test_oplocks_r(HANDLE token, const std::u16string& dir);
void test_oplocks_rw(HANDLE token, const std::u16string& dir);
void test_oplocks_rh(HANDLE token, const std::u16string& dir);
void test_oplocks_rwh(HANDLE token, const std::u16string& dir);

// cs.cpp
void test_cs(const std::u16string& dir);

// reparse.cpp
void test_reparse(HANDLE token, const std::u16string& dir);

// streams.cpp
void test_streams(const std::u16string& dir);

// ea.cpp
void test_ea(const std::u16string& dir);
void write_ea(HANDLE h, std::string_view name, std::string_view value, bool need_ea = false);

// fileinfo.cpp
void test_fileinfo(const std::u16string& dir);
void set_basic_information(HANDLE h, int64_t creation_time, int64_t last_access_time,
                           int64_t last_write_time, int64_t change_time, uint32_t attributes);

// security.cpp
void test_security(HANDLE token, const std::u16string& dir);
void set_dacl(HANDLE h, ACCESS_MASK access);
