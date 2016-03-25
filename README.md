WinBtrfs v0.2
-------------

WinBtrfs is a Windows driver for the next-generation Linux filesystem Btrfs. The
ultimate aim is for it to be feature-complete, but most of the basics are there
already. It is a reimplementation from scratch, and contains no code from the
Linux kernel. First, a disclaimer:

This software is in active development - YOU USE IT AT YOUR OWN RISK. I take NO
RESPONSIBILITY for any damage it may do to your filesystem. DO NOT USE THIS
DRIVER UNLESS YOU HAVE FULL AND UP-TO-DATE BACKUPS OF ALL YOUR DATA. Do not rely
on Btrfs' internal mechanisms: SNAPSHOTS ARE NOT BACKUPS, AND DO NOT RULE OUT
THE POSSIBILITY OF SILENT CORRUPTION.

In other words, assume that the driver is going to corrupt your entire
filesystem, and you'll be pleasantly surprised when it doesn't.

Everything here is released under the GNU Lesser General Public Licence (LGPL);
see the file LICENCE for more info. You are encouraged to play about with the
source code as you will, and I'd appreciate a note (mark@harmstone.com) if you
come up with anything nifty. On top of that, I'm open to relicensing the code if
you've a burning desire to use it on a GPL or commercial project, or what have
you - drop me a line and we'll talk.

Features
--------

* Reading and writing of Btrfs filesystems
* Caching
* Discovery of Btrfs partitions, even if Windows would normally ignore them
* Getting and setting of Access Control Lists (ACLs), using the xattr
  security.NTACL
* Alternate Data Streams (e.g. :Zone.Identifier is stored as the xattr
  user.Zone.Identifier)
* Supported incompat flags: `mixed_backref`, `default_subvol`, `big_metadata`,
  `extended_iref`, `skinny_metadata`.
* Mappings from Linux users to Windows ones (see below)
* Symlinks
* Shell extension to identify subvolumes

Todo
----

* Basic RAID: RAID0, RAID1, and RAID10
* RAID5 and RAID6 (incompat flag `raid56`)
* zlib compression
* LZO compression (incompat flag `compress_lzo`)
* Old free space cache
* New (Linux 4.5) free space cache (compat_ro flag free_space_cache)
* Preallocation
* Misc incompat flags: `mixed_groups`, `no_holes`
* Add creation of new subvolumes, etc. to userspace helper
* Asynchronous reading and writing
* Actually obeying security (add ACCESS_MASK checks)
* Get all of Wine's ntdll tests to pass
* Allow creation of hard links
* Arbitrary reparse points
* Probably a bunch of other bugs

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

Check:

a) If on 64-bit Windows, you're running in Test Mode ("Test Mode" appears in the
bottom right of the Desktop).

b) You're not trying to mount a multi-device filesystem, which isn't supported
yet.

c) You're not trying to mount a filesystem with unsupported flags. On Linux,
type:

    ls /sys/fs/btrfs/*/features/

If you see any of the flags listed above as being unsupported, it won't work.

* I can't read from or write to a particular file!

Make sure it's not compressed, which isn't yet supported.

* The filenames are weird!
or
* I get strange errors on certain files or directories!

The driver assumes that all filenames are encoded in UTF-8. This should be the
default on most setups nowadays - if you're not using UTF-8, it's probably worth
looking into converting your files.

* Windows thinks it's an NTFS volume

Unfortunately we have to lie about this - the function MPR!MprGetConnection checks
the filesystem type against an internal whitelist, and fails if it's not found, which
prevents UAC from working. Thanks Microsoft!

Changelog
---------

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

Contact
-------

I'd appreciate any feedback you might have, positive or negative:
mark@harmstone.com.
