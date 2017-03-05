WinBtrfs v0.9
-------------

WinBtrfs is a Windows driver for the next-generation Linux filesystem Btrfs. The
aim is for it to be feature-complete, with only a few features still
outstanding. It is a reimplementation from scratch, and contains no code from the
Linux kernel. First, a disclaimer:

This software is in active development - YOU USE IT AT YOUR OWN RISK. I take NO
RESPONSIBILITY for any damage it may do to your filesystem. DO NOT USE THIS
DRIVER UNLESS YOU HAVE FULL AND UP-TO-DATE BACKUPS OF ALL YOUR DATA. Do not rely
on Btrfs' internal mechanisms: SNAPSHOTS ARE NOT BACKUPS, AND DO NOT RULE OUT
THE POSSIBILITY OF SILENT CORRUPTION.

In other words, assume that the driver is going to corrupt your entire
filesystem, and you'll be pleasantly surprised when it doesn't.

However, having said that, it ought to be suitable for day-to-day use, especially
when mounted readonly.

Everything here is released under the GNU Lesser General Public Licence (LGPL);
see the file LICENCE for more info. You are encouraged to play about with the
source code as you will, and I'd appreciate a note (mark@harmstone.com) if you
come up with anything nifty. On top of that, I'm open to relicensing the code if
you've a burning desire to use it on a GPL or commercial project, or what have
you - drop me a line and we'll talk.

See at the end of this document for copyright details of third-party code that's
included here.

Features
--------

* Reading and writing of Btrfs filesystems
* Basic RAID: RAID0, RAID1, and RAID10
* Advanced RAID: RAID5 and RAID6 (incompat flag `raid56`)
* Caching
* Discovery of Btrfs partitions, even if Windows would normally ignore them
* Getting and setting of Access Control Lists (ACLs), using the xattr
  security.NTACL
* Alternate Data Streams (e.g. :Zone.Identifier is stored as the xattr
  user.Zone.Identifier)
* Supported incompat flags: `mixed_backref`, `default_subvol`, `big_metadata`,
  `extended_iref`, `skinny_metadata`.
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
* LZO compression (incompat flag `compress_lzo`)
* Misc incompat flags: `mixed_groups`, `no_holes`
* LXSS ("Ubuntu on Windows") support
* Balancing (including resuming balances started on Linux)
* Device addition and removal
* Creation of new filesystems with `mkbtrfs.exe` and `ubtrfs.dll`
* Scrubbing
* TRIM/DISCARD

Todo
----

* Reflink copy
* Subvol send and receive
* Degraded mounts
* New (Linux 4.5) free space cache (compat_ro flag `free_space_cache`)
* Passthrough of permissions etc. for LXSS

Installation
------------

The driver is self-signed at the moment, meaning that if you're using a 64-bit
version of Windows you'll have to tell it to boot up in Test Mode if you want it
to work. To do this, launch an admin command prompt (right-click on "Command
Prompt" and click "Run as administrator"), and run the following command:

    bcdedit -set TESTSIGNING ON

Reboot, and you should see "Test Mode" on the bottom right of the Desktop.

If you just want to test the driver out, run loader.exe as an Administrator.
Despite what it says, you can close it - the driver will stay in memory until
you shutdown. Be warned that currently running programs, including the Desktop,
might not display your Btrfs partition until they're restarted - your drive
might not appear in My Computer, but if you run E:\ (for example), it'll show
up.

If you're feeling adventurous and want to install the driver permanently,
right-click btrfs.inf, click Install, and reboot.

Compilation
-----------

You will need Microsoft Visual C++ if you want to compile the driver; I used the
2008 edition, but later versions should work too. I've not been able to get it
to work with GCC; it worked for a while, then suddenly stopped when the code
got to a certain size. If you've got any clues about what this is all about, I'd
appreciate it if you sent me an e-mail.

You'll also need a copy of the Windows DDK; I placed mine in C:\WinDDK. If yours
is somewhere else, you'll need to edit the project settings. You'll also need to
edit the post-build steps for the 64-bit versions, which are set up to
self-sign using my own certificate.

User mappings
-------------

The user mappings are stored in the registry key
HKLM\SYSTEM\CurrentControlSet\services\btrfs\Mappings. Create a DWORD with the
name of your Windows SID (e.g. S-1-5-21-1379886684-2432464051-424789967-1001),
and the value of your Linux uid (e.g. 1000). It will take effect next time the
driver is loaded.

Troubleshooting
---------------

* My drive doesn't show up!

If you're on 64-bit Windows, check that you're running in Test Mode ("Test Mode" appears
in the bottom right of the Desktop).

* My drive is readonly

Check that you've not got the new free space cache enabled, which isn't yet supported.

* The filenames are weird!
or
* I get strange errors on certain files or directories!

The driver assumes that all filenames are encoded in UTF-8. This should be the
default on most setups nowadays - if you're not using UTF-8, it's probably worth
looking into converting your files.

* `btrfs check` reports errors in the extent tree

There's a bug in btrfs-progs v4.7, which causes it to return false positives when
using prealloc extents - this'll also manifest itself with filesystems from the
official driver. If you still get the same errors when using btrfs-check v4.6, please
e-mail me what it says.

* The root of the drive isn't case-sensitive in LXSS

This is something Microsoft hardcoded into LXSS, presumably to stop people hosing
their systems by running `mkdir /mnt/c/WiNdOwS`.

* Disk Management doesn't work properly, e.g. unable to change drive letter

Try changing the type of your partition in Linux. For MBR partitions, this should be
type 7 in `fdisk`. For GPT partitions, this should be type 6 in `fdisk` ("Microsoft
basic data"), or 0700 in `gdisk`. We have to do some chicanery to get Linux partitions
to appear in the first place, but unfortunately this confuses diskmgmt.msc too much.

* How do I format a partition as Btrfs?

Use the included command line program mkbtrfs.exe. We can't add Btrfs to Windows' own
dialog box, unfortunately, as its list of filesystems has been hardcoded. You can also
run `format /fs:btrfs`, if you don't need to set any Btrfs-specific options.

* I can't reformat a mounted Btrfs filesystem

If Windows' Format dialog box refuses to appear, try running format.com with the /fs
flag, e.g. `format /fs:ntfs D:`.

Changelog
---------

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
* Checksums now calulated in parallel where appropriate
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
Bear in mind this is a kernel filename, so you'll have to prefix it with "\??\" (e.g.,
"\??\C:\btrfs.log"). It probably goes without saying, but don't store this on a volume the
driver itself is using, or you'll cause an infinite loop.

Mount options
-------------

The driver will create subkeys in the registry under HKLM\SYSTEM\CurrentControlSet\Services\btrfs
for each mounted filesystem, named after its UUID. If you're unsure which UUID refers to which
volume, you can check using `btrfs fi show` on Linux. You can add per-volume mount options to this
subkey, which will take effect on reboot. If a value is set in the key above this, it will use this
by default.

* `Ignore` (DWORD): set this to 1 to tell the driver not to attempt loading this filesystem. With the
`Readonly flag, this is probably redundant.

* `Readonly` (DWORD): set this to 1 to tell the driver not to allow writing to this volume. This is
the equivalent of the `ro` flag on Linux.

* `Compress` (DWORD): set this to 1 to tell the driver to write files as compressed by default. This is
the equivalent of the `compress` flag on Linux.

* `CompressForce` (DWORD): set this to 1 to force compression, i.e. to ignore the `nocompress` inode
flag and even attempt compression of incompressible files. This isn't a good idea, but is the equivalent
of the `compress-force` flag on Linux.

* `CompressType` (DWORD): set this to 1 to prefer zlib compression, and 2 to prefer lzo compression. The
default is 0, which uses lzo compression if the incompat flag is set, and zlib otherwise.

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

Contact
-------

I'd appreciate any feedback you might have, positive or negative:
mark@harmstone.com.

Copyright
---------

This code also contains portions of zlib, which is licensed as follows:

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

It also contains portions of an early version of lzo, which is copyright 1996
Markus Oberhumer. Modern versions are licensed under the GPL, but this was
licensed under the LGPL, so I believe it is okay to use.

