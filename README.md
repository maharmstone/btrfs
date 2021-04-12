WinBtrfs v1.7.7
---------------

WinBtrfs is a Windows driver for the next-generation Linux filesystem Btrfs.
A reimplementation from scratch, it contains no code from the Linux kernel,
and should work on any version from Windows XP onwards. It is also included
as part of the free operating system [ReactOS](https://www.reactos.org/).

If your Btrfs filesystem is on a MD software RAID device created by Linux, you
will also need [WinMD](https://github.com/maharmstone/winmd) to get this to appear
under Windows.

See also [Quibble](https://github.com/maharmstone/quibble), an experimental
bootloader allowing Windows to boot from Btrfs, and [Ntfs2btrfs](https://github.com/maharmstone/ntfs2btrfs),
a tool which allows in-place conversion of NTFS filesystems.

First, a disclaimer:

You use this software at your own risk. I take no responsibility for any damage
it may do to your filesystem. It ought to be suitable for day-to-day use, but
make sure you take backups anyway.

Everything here is released under the GNU Lesser General Public Licence (LGPL);
see the file LICENCE for more info. You are encouraged to play about with the
source code as you will, and I'd appreciate a note (mark@harmstone.com) if you
come up with anything nifty.

See at the end of this document for copyright details of third-party code that's
included here.

Donations
---------

I've been developing this driver for fun, and in the hopes that someone out there
will find it useful. But if you want to provide some pecuniary encouragement, it'd
be very much appreciated:

* [Paypal](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=3XQVCQ6YB55L2&lc=GB&item_name=WinBtrfs%20donation&currency_code=GBP&bn=PP%2dDonationsBF%3abtn_donate_LG%2egif%3aNonHosted)

Features
--------

* Reading and writing of Btrfs filesystems
* Basic RAID: RAID0, RAID1, and RAID10
* Advanced RAID: RAID5 and RAID6
* Caching
* Discovery of Btrfs partitions, even if Windows would normally ignore them
* Getting and setting of Access Control Lists (ACLs), using the xattr
  security.NTACL
* Alternate Data Streams (e.g. :Zone.Identifier is stored as the xattr
  user.Zone.Identifier)
* Mappings from Linux users to Windows ones (see below)
* Symlinks and other reparse points
* Shell extension to identify and create subvolumes, including snapshots
* Hard links
* Sparse files
* Free-space cache
* Preallocation
* Asynchronous reading and writing
* Partition-less Btrfs volumes
* Per-volume registry mount options (see below)
* zlib compression
* LZO compression
* LXSS ("Ubuntu on Windows") support
* Balancing (including resuming balances started on Linux)
* Device addition and removal
* Creation of new filesystems with `mkbtrfs.exe` and `ubtrfs.dll`
* Scrubbing
* TRIM/DISCARD
* Reflink copy
* Subvol send and receive
* Degraded mounts
* Free space tree (compat_ro flag `free_space_cache`)
* Shrinking and expanding
* Passthrough of permissions etc. for LXSS
* Zstd compression
* Windows 10 case-sensitive directory flag
* Oplocks
* Metadata UUID incompat flag (Linux 5.0)
* Three- and four-disk RAID1 (Linux 5.5)
* New checksum types (xxhash, sha256, blake2) (Linux 5.5)

Todo
----

* Defragmentation
* Support for Btrfs quotas
* Windows 10 reserved storage
* Full transaction log support
* Support for Windows transactions (TxF)

Installation
------------

To install the driver, [download and extract the latest release](https://github.com/maharmstone/btrfs/releases),
right-click btrfs.inf, and choose Install. The driver is signed, so should work out
of the box on modern versions of Windows.

If you using Windows 10 and have Secure Boot enabled, you may have to make a Registry
change in order for the driver to be loaded - see [below](#secureboot).

There's also a [Chocolatey package](https://chocolatey.org/packages/winbtrfs) available -
if you have Chocolatey installed, try running `choco install winbtrfs`.

Uninstalling
------------

If you want to uninstall, from a command prompt run:

```
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 btrfs.inf
```

You may need to give the full path to btrfs.inf.

You can also go to Device Manager, find "Btrfs controller" under
"Storage volumes", right click and choose "Uninstall". Tick the checkbox to
uninstall the driver as well, and let Windows reboot itself.

If you need to uninstall via the registry, open regedit and set the value of
HKLM\SYSTEM\CurrentControlSet\services\btrfs\Start to 4, to disable the service.
After you reboot, you can then delete the btrfs key and remove
C:\Windows\System32\drivers\btrfs.sys.

Compilation
-----------

To compile with Visual C++ 2019, open the directory and let CMake do its thing.
If you have the Windows DDK installed correctly, it should just work.

To compile with GCC on Linux, you will need a cross-compiler set up, for either
`i686-w64-mingw32` or `x86_64-w64-mingw32`. Create a build directory, then use
either `mingw-x86.cmake` or `mingw-amd64.cmake` as CMake toolchain files to
generate your Makefile.

Mappings
--------

The user mappings are stored in the registry key
HKLM\SYSTEM\CurrentControlSet\services\btrfs\Mappings. Create a DWORD with the
name of your Windows SID (e.g. S-1-5-21-1379886684-2432464051-424789967-1001),
and the value of your Linux uid (e.g. 1000). It will take effect next time the
driver is loaded.

You can find your current SID by running `wmic useraccount get name,sid`.

Similarly, the group mappings are stored in under GroupMappings. The default
entry maps Windows' Users group to gid 100, which is usually "users" on Linux.
You can also specify user SIDs here to force files created by a user to belong
to a certain group. The setgid flag also works as on Linux.

LXSS ("Ubuntu on Windows" / "Windows Subsystem for Linux")
----------------------------------------------------------

The driver will passthrough Linux metadata to recent versions of LXSS, but you
will have to let Windows know that you wish to do this. From a Bash prompt on
Windows, edit `/etc/wsl.conf` to look like the following:

```
[automount]
enabled = true
options = "metadata"
mountFsTab = false
```

It will then take effect next time you reboot. Yes, you should be able to chroot
into an actual Linux installation, if you wish.

Commands
--------

The DLL file shellbtrfs.dll provides the GUI interface, but it can also be used
with rundll32.exe to carry out some tasks from the command line, which may be
useful if you wish to schedule something to run periodically.

Bear in mind that rundll32 provides no mechanism to return any error codes, so
any of these commands may fail silently.

* `rundll32.exe shellbtrfs.dll,CreateSubvol <path>`

* `rundll32.exe shellbtrfs.dll,CreateSnapshot <source> <destination>`

* `rundll32.exe shellbtrfs.dll,ReflinkCopy <source> <destination>`
This also accepts wildcards, and any number of source files.

The following commands need various privileges, and so must be run as Administrator
to work:

* `rundll32.exe shellbtrfs.dll,SendSubvol <source> [-p <parent>] [-c <clone subvol>] <stream file>`
The -p and -c flags are as `btrfs send` on Linux. You can specify any number of
clone subvolumes.

* `rundll32.exe shellbtrfs.dll,RecvSubvol <stream file> <destination>`

* `rundll32.exe shellbtrfs.dll,StartScrub <drive>`

* `rundll32.exe shellbtrfs.dll,StopScrub <drive>`

Troubleshooting
---------------

* How do I debug this?

On the releases page, there's zip files to download containing the PDBs. Or you
can try the symbols server http://symbols.burntcomma.com/ - in windbg, set your
symbol path to something like this:

```symsrv*symsrv.dll*C:\symbols*http://msdl.microsoft.com/download/symbols;symsrv*symsrv.dll*C:\symbols*http://symbols.burntcomma.com```

* The filenames are weird!
or
* I get strange errors on certain files or directories!

The driver assumes that all filenames are encoded in UTF-8. This should be the
default on most setups nowadays - if you're not using UTF-8, it's probably worth
looking into converting your files.

* <a name="secureboot"></a>How do I get this working with Secure Boot turned on?

For the very latest versions of Windows 10, Microsoft introduced more onerous
requirements for signing, which seemingly aren't available for open-source drivers.

To work around this, go to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy` in Regedit,
create a new DWORD value called `UpgradedSystem` and set to 1, and reboot.

Or you could always just turn off Secure Boot in your BIOS settings.

* The root of the drive isn't case-sensitive in LXSS

This is something Microsoft hardcoded into LXSS, presumably to stop people hosing
their systems by running `mkdir /mnt/c/WiNdOwS`.

* How do I change the drive letter?

With the shell extension installed, right-click the drive in Explorer, click Properties,
and go to the Btrfs tab. There should be a button which allows you to change the drive
letter.

* How do I format a partition as Btrfs?

Use the included command line program mkbtrfs.exe. We can't add Btrfs to Windows' own
dialog box, unfortunately, as its list of filesystems has been hardcoded. You can also
run `format /fs:btrfs`, if you don't need to set any Btrfs-specific options.

* I can't reformat a mounted Btrfs filesystem

If Windows' Format dialog box refuses to appear, try running format.com with the /fs
flag, e.g. `format /fs:ntfs D:`.

* I can't mount a Synology NAS

Synology seems to use LVM for its block devices. Until somebody writes an LVM driver
for Windows, you're out of luck.

* I can't mount a Thecus NAS

Thecus uses Linux's MD raid for its block devices. You will need to install [WinMD](https://github.com/maharmstone/winmd)
as well.

* The drive doesn't show up

On very old versions of Windows (XP, Server 2003?), Windows ignores Linux partitions
entirely. If this is the case for you, try running `fdisk` on Linux and changing your
partition type from 83 to 7.

Changelog
---------

v1.7.7 (2021-04-12):
* Fixed deadlock on high load
* Fixed free space issue when installing Genshin Impact
* Fixed issue when copying files with wildcards in command prompt
* Increased speed of directory lookups

v1.7.6 (2021-01-14):
* Fixed race condition when booting with Quibble
* No longer need to restart Windows after initial installation
* Forced maximum file name to 255 UTF-8 characters, to match Linux driver
* Fixed issue where directories could be created with trailing backslash
* Fixed potential deadlock when Windows calls NtCreateSection during flush
* Miscellaneous bug fixes

v1.7.5 (2020-10-31):
* Fixed text display issue in shell extension
* Added support for mingw 8
* Fixed LXSS permissions not working in new versions of Windows
* Fixed issue where truncating an inline file wouldn't change its size
* Fixed crash with Quibble where driver would try to use AVX2 before Windows had enabled it

v1.7.4 (2020-08-23):
* Fixed issue when running compressed EXEs
* Changed build system to cmake
* Upgraded zstd to version 1.4.5
* Added support for FSCTL_GET_RETRIEVAL_POINTERS
* Miscellaneous bug fixes

v1.7.3 (2020-05-24):
* Fixed crash when sending file change notifications
* Improved symlink handling with LXSS
* Added support for undocumented flag SL_IGNORE_READONLY_ATTRIBUTE
* Fixed corruption caused by edge case, where address allocated and freed in same flush
* Improved handling of free space tree
* Improved handling of very full volumes
* Fixed spurious warnings raised by GCC 10 static analyser
* Replaced multiplications and divisions with bit shift operations where appropriate
* Fixed combobox stylings in shell extension

v1.7.2 (2020-04-10):
* Added more fixes for booting from Btrfs on Windows 10
* Fixed occasional deadlock when deleting or closing files on Windows 10 1909
* Fixed crash when reading large ADSes
* Fixed occasional crash when writing files on RAID5/6
* Miscellaneous bug fixes

v1.7.1 (2020-03-02):
* Fixed crash when reading beyond end of file
* Fixed spurious checksum errors when doing unaligned read

v1.7 (2020-02-26):
* Added support for metadata_uuid incompat flag (Linux 5.0)
* Added support for three- and four-disk RAID1 (Linux 5.5)
* Added support for new checksum types: xxhash, sha256, blake2 (Linux 5.5)
* Greatly increased checksumming speed
* Greatly increased compression and decompression speed
* Fixed bug causing incorrect free-space reporting when data is DUP
* Fixed issue creating directories on LXSS when `case=dir` option set

v1.6 (2020-02-04):
* Added experimental (i.e. untested) ARM support (thanks to [DjArt](https://github.com/DjArt) for this)
* Added fixes for booting from Btrfs on Windows 10
* Volumes will now get remounted if changed while Windows is asleep or hibernating
* Fixed corruption when mounting volume that hasn't been unmounted cleanly by Linux
* Fixed crash when deleting subvolume

v1.5 (2019-11-10):
* More fixes for booting from Btrfs
* Added virtual $Root directory (see "NoRootDir" below)
* Added support for Windows XP
* Added support for renaming alternative data streams
* Added oplock support
* Fixed potential deadlock on boot
* Fixed possible crash on shutdown
* Fixed a bunch of memory leaks
* Many other miscellaneous bug fixes

v1.4 (2019-08-31):
* Added fragmentation percentage to property sheet
* Added support for Windows Server 2003 and Windows Vista
* Added pagefile support
* Improved support for file locking
* Added support for booting from Btrfs on Windows Server 2003 (see https://www.youtube.com/watch?v=-5E2CHmHEUs)
* Fixed issue where driver could open same inode twice
* Other miscellaneous bug fixes

v1.3 (2019-06-10):
* Added support for new rename and delete functions introduced to Windows 10
* Added support for Windows 10's flag for case-sensitive directories
* Changed free-space calculation method to be more like that of the Linux driver
* Added more support for 128-bit file IDs
* Fixed bug causing outdated root items
* Fixed bug preventing writing to VHDs

v1.2.1 (2019-05-06):
* Reverted commit affecting the creation of streams

v1.2 (2019-05-05):
* Dramatic speed increase when opening many small files, such as with a Git repository
* Fixed crash on surprise removals of removable devices
* Added ability to change drive letters easily
* No longer creates free-space cache for very small chunks, so as not to confuse the Linux driver
* Fixed corruption when very large file created and then immediately deleted
* Minor bug fixes

v1.1 (2018-12-15):
* Support for Zstd compression
* Passthrough of Linux metadata to LXSS
* Refactored shell extension
* Fixed memory leaks
* Many other bug fixes

v1.0.2 (2018-05-19):
* Minor bug fixes

v1.0.1 (2017-10-15):
* Fixed deadlock
* Binaries now signed
* Minor bug fixes

v1.0 (2017-09-04):
* First non-beta release!
* Degraded mounts
* New free space cache (compat_ro flag `free_space_cache`)
* Shrinking and expanding of volumes
* Registry options now re-read when changed, rather than just on startup
* Improved balancing on very full filesystems
* Fixed problem preventing user profile directory being stored on btrfs on Windows 8 and above
* Better Plug and Play support
* Miscellaneous bug fixes

v0.10 (2017-05-02):
* Reflink copy
* Sending and receiving subvolumes
* Group mappings (see Mappings section above)
* Added commands for scripting etc. (see Commands section above)
* Fixed an issue preventing mounting on non-PNP devices, such as VeraCrypt
* Fixed an issue preventing new versions of LXSS from working
* Fixed problem with the ordering of extent refs, which caused problems on Linux but wasn't picked up by `btrfs check`
* Added support for reading compressed inline extents
* Many miscellaneous bug fixes

v0.9 (2017-03-05):
* Scrubbing
* TRIM/DISCARD
* Better handling of multi-device volumes
* Performance increases when reading from RAID filesystems
* No longer lies about being NTFS, except when it has to
* Volumes will now go readonly if there is an unrecoverable error, rather than blue-screening
* Filesystems can now be created with Windows' inbuilt format.com
* Zlib upgraded to version 1.2.11
* Miscellaneous performance increases
* Miscellaneous bug fixes

v0.8 (2016-12-30):
* Volume property sheet, for:
 * Balances
 * Adding and removing devices
 * Showing disk usage, i.e. the equivalent to `btrfs fi usage`
* Checksums now calculated in parallel where appropriate
* Creation of new filesystems, with mkbtrfs.exe
* Plug and play support for RAID devices
* Disk usage now correctly allocated to processes in taskmgr
* Performance increases
* Miscellaneous bug fixes

v0.7 (2016-10-24):
* Support for RAID5/6 (incompat flag `raid56`)
* Seeding support
* LXSS ("Ubuntu on Windows") support
* Support for Windows Extended Attributes
* Improved removable device support
* Better snapshot support
* Recovery from RAID checksum errors
* Fixed issue where creating a lot of new files was taking a long time
* Miscellaneous speed increases and bug fixes

v0.6 (2016-08-21):
* Compression support (both zlib and lzo)
* Mixed groups support
* No-holes support
* Added inode property sheet to shell extension
* Many more mount options (see below)
* Better support for removable devices
* Page file support
* Many miscellaneous bug fixes

v0.5 (2016-07-24):
* Massive speed increases (from "sluggish" to "blistering")
* Massive stability improvements
* RAID support: RAID0, RAID1, and RAID10
* Asynchronous reading and writing
* Partition-less Btrfs volumes
* Windows sparse file support
* Object ID support
* Beginnings of per-volume mount options
* Security improvements
* Notification improvements
* Miscellaneous bug fixes

v0.4 (2016-05-02):
* Subvolume creation and deletion
* Snapshots
* Preallocation
* Reparse points
* Hard links
* Plug and play
* Free-space cache
* Fix problems preventing volume from being shared over the network
* Miscellaneous bug fixes

v0.3 (2016-03-25):
* Bug fixes:
 * Fixed crashes when metadata blocks were SINGLE, such as on SSDs
 * Fixed crash when splitting an internal tree
 * Fixed tree traversal failing when first item in tree had been deleted
 * Fixed emptying out of whole tree (probably only relevant to checksum tree)
 * Fixed "incorrect local backref count" message appearing in `btrfs check`
 * Miscellaneous other fixes
* Added beginnings of shell extension, which currently only changes the icon of subvolumes

v0.2 (2016-03-13):
* Bug fix release:
 * Check memory allocations succeed
 * Check tree items are the size we're expecting
 * Added rollbacks, so failed operations are completely undone
 * Fixed driver claiming all unrecognized partitions (thanks Pierre Schweitzer)
 * Fixed deadlock within `CcCopyRead`
 * Fixed changing properties of a JPEG within Explorer
 * Lie about FS type, so UAC works
 * Many, many miscellaneous bug fixes
* Rudimentary security support
* Debug log support (see below)

v0.1 (2016-02-21):
* Initial alpha release.

Debug log
---------

WinBtrfs has three levels of debug messages: errors and FIXMEs, warnings, and traces.
The release version of the driver only displays the errors and FIXMEs, which it logs
via `DbgPrint`. You can view these messages via the Microsoft program DebugView, available
at https://technet.microsoft.com/en-gb/sysinternals/debugview.

If you want to report a problem, it'd be of great help if you could also attach a full
debug log. To do this, you will need to use the debug versions of the drivers; copy the files
in Debug\x64 or Debug\x86 into x64 or x86. You will also need to set the registry entries in
HKLM\SYSTEM\CurrentControlSet\Services\btrfs:

* `DebugLogLevel` (DWORD): 0 for no messages, 1 for errors and FIXMEs, 2 for warnings also,
and 3 for absolutely everything, including traces.
* `LogDevice` (string, optional): the serial device you want to output to, such as
`\Device\Serial0`. This is probably only useful on virtual machines.
* `LogFile` (string, optional): the file you wish to output to, if `LogDevice` isn't set.
Bear in mind this is a kernel filename, so you'll have to prefix it with "\\??\\" (e.g.,
"\\??\\C:\\btrfs.log"). It probably goes without saying, but don't store this on a volume the
driver itself is using, or you'll cause an infinite loop.

Mount options
-------------

The driver will create subkeys in the registry under HKLM\SYSTEM\CurrentControlSet\Services\btrfs
for each mounted filesystem, named after its UUID. If you're unsure which UUID refers to which
volume, you can check using `btrfs fi show` on Linux. You can add per-volume mount options to this
subkey, which will take effect on reboot. If a value is set in the key above this, it will use this
by default.

* `Ignore` (DWORD): set this to 1 to tell the driver not to attempt loading this filesystem. With the
`Readonly` flag, this is probably redundant.

* `Readonly` (DWORD): set this to 1 to tell the driver not to allow writing to this volume. This is
the equivalent of the `ro` flag on Linux.

* `Compress` (DWORD): set this to 1 to tell the driver to write files as compressed by default. This is
the equivalent of the `compress` flag on Linux.

* `CompressForce` (DWORD): set this to 1 to force compression, i.e. to ignore the `nocompress` inode
flag and even attempt compression of incompressible files. This isn't a good idea, but is the equivalent
of the `compress-force` flag on Linux.

* `CompressType` (DWORD): set this to 1 to prefer zlib compression, 2 to prefer lzo compression, or 3
to prefer zstd compression. The default is 0, which uses zstd or lzo compression if the incompat flags
are set, and zlib otherwise.

* `FlushInterval` (DWORD): the interval in seconds between metadata flushes. The default is 30, as on Linux -
the parameter is called `commit` there.

* `ZlibLevel` (DWORD): a number between -1 and 9, which determines how much CPU time is spent trying to
compress files. You might want to fiddle with this if you have a fast CPU but a slow disk, or vice versa.
The default is 3, which is the hard-coded value on Linux.

* `MaxInline` (DWORD): the maximum size that will be allowed for "inline" files, i.e. those stored in the
metadata. The default is 2048, which is also the default on modern versions of Linux - the parameter is
called `max_inline` there. It will be clipped to the maximum value, which unless you've changed your node
size will be a shade under 16 KB.

* `SubvolId` (QWORD): the ID of the subvolume that we will attempt to mount as the root. If it doesn't
exist, this parameter will be silently ignored. The subvolume ID can be found on the inode property
sheet; it's in hex there, as opposed to decimal on the Linux tools. The default is whatever has been set
via `btrfs subvolume set-default`; or, failing that, subvolume 5. The equivalent parameter on Linux is
called `subvolid`.

* `SkipBalance` (DWORD): set to 1 to tell the driver not to attempt resuming a balance which was running
when the system last powered down. The default is 0. The equivalent parameter on Linux is `skip_balance`.

* `NoPNP` (DWORD): useful for debugging only, this forces any volumes to appear rather than exposing them
via the usual Plug and Play method.

* `ZstdLevel` (DWORD): Zstd compression level, default 3.

* `NoTrim` (DWORD): set this to 1 to disable TRIM support.

* `AllowDegraded` (DWORD): set this to 1 to allow mounting a degraded volume, i.e. one with a device
missing. You are strongly advised not to enable this unless you need to.

* `NoRootDir` (DWORD): if you have changed your default subvolume, either natively or by a registry option,
there will be a hidden directory called $Root which points to where the root would normally be. Set this
value to 1 to prevent this appearing.

Contact
-------

I'd appreciate any feedback you might have, positive or negative:
mark@harmstone.com.

Copyright
---------

This code contains portions of the following software:

### Zlib

  Copyright (C) 1995-2017 Jean-loup Gailly and Mark Adler

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

### LZO

WinBtrfs contains portions of an early version of lzo, which is copyright 1996
Markus Oberhumer. Modern versions are licensed under the GPL, but this was
licensed under the LGPL, so I believe it is okay to use.

### Zstd

Copyright (c) 2016-present, Facebook, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

 * Neither the name Facebook nor the names of its contributors may be used to
   endorse or promote products derived from this software without specific
   prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### BLAKE2

[https://github.com/BLAKE2/BLAKE2](https://github.com/BLAKE2/BLAKE2) (public domain)

### SHA256

[https://github.com/amosnier/sha-2](https://github.com/amosnier/sha-2) (public domain)
