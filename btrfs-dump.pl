#!/usr/bin/perl

# Quick and dirty btrfs tree dumper. Great for diff'ing, which btrfs-debug-tree isn't...
# Do something like:
#
# qemu-nbd -r -n -c /dev/nbd0 ~/vms/win7/win7-32.img ; sleep 1 ; chmod 666 /dev/nbd0p3
# ./btrfs-dump.pl /dev/nbd0p3 > dump2.txt
# diff -u dump1.txt dump2.txt > diff2.txt

# Like btrfs.h, I'm disclaiming any copyright on this file, but I'd appreciate
# hearing about what you do with it: mark@harmstone.com.

use Data::Dumper;
use strict;

if (scalar(@ARGV) < 1) {
    my @dp=split(/\//,$0);

    print "Usage: ".$dp[$#dp]." [BLOCKDEVICE]\n";
    exit;
}

my %devs=();
for (my $i = 1; $i <= $#ARGV; $i++) {
    my ($file,$sb);

    open($file, $ARGV[$i]) || die "Error opening ".$ARGV[$i].": $!";
    binmode($file);

    seek($file,0x10000,0);
    read($file,$sb,0x1000);
    my @b=unpack("Vx28A16QQA8QQQQQQQQQVVVVVQQQQvCCCA98A256QQx240a2048a672",$sb);

    if ($b[4] ne "_BHRfS_M") {
        die $ARGV[$i].": not Btrfs";
    }

    my @di = unpack("QQQVVVQQQVCCA16A16",$b[27]);
    $devs{$di[0]}=$file;
}

my ($f,$chunktree,$roottree,$logtree,$nodesize);

open($f,$ARGV[0]) || die "Error opening ".$ARGV[0].": $!";
binmode($f);

my %roots=();
my %logroots=();
my @l2p=();
my @l2p_bs=();
my $csum_type;

read_superblock($f);

print "CHUNK: \n";
dump_tree($chunktree, "", 1);
print "\n";

print "ROOT: \n";
dump_tree($roottree, "", 0);
print "\n";

if ($logtree != 0) {
    print "LOG: \n";
    dump_tree($logtree, "", 0);
    print "\n";
}

my @rs=sort { $a <=> $b } (keys(%roots));

foreach my $r (@rs) {
	printf("Tree %x:\n",$r);
	dump_tree($roots{$r}, "");
	print "\n";
}

my @lrs=sort { $a <=> $b } (keys(%logroots));

foreach my $lr (@lrs) {
	printf("Tree %x (log):\n",$lr);
	dump_tree($logroots{$lr}, "");
	print "\n";
}

close($f);

sub incompat_flags {
    my ($f)=@_;
    my @l;

    if ($f & 0x1) {
        push @l,"mixed_backref";
        $f &= ~0x1;
    }

    if ($f & 0x2) {
        push @l,"default_subvol";
        $f &= ~0x2;
    }

    if ($f & 0x4) {
        push @l,"mixed_groups";
        $f &= ~0x4;
    }

    if ($f & 0x8) {
        push @l,"compress_lzo";
        $f &= ~0x8;
    }

    if ($f & 0x10) {
        push @l,"compress_zstd";
        $f &= ~0x10;
    }

    if ($f & 0x20) {
        push @l,"big_metadata";
        $f &= ~0x20;
    }

    if ($f & 0x40) {
        push @l,"extended_iref";
        $f &= ~0x40;
    }

    if ($f & 0x80) {
        push @l,"raid56";
        $f &= ~0x80;
    }

    if ($f & 0x100) {
        push @l,"skinny_metadata";
        $f &= ~0x100;
    }

    if ($f & 0x200) {
        push @l,"no_holes";
        $f &= ~0x200;
    }

    if ($f & 0x400) {
        push @l,"metadata_uuid";
        $f &= ~0x400;
    }

    if ($f & 0x800) {
        push @l,"raid1c34";
        $f &= ~0x800;
    }

    if ($f!=0 || $#l==-1) {
        push @l,sprintf("%x",$f);
    }

    return join(',',@l);
}

sub compat_ro_flags {
    my ($f)=@_;
    my @l;

    if ($f&1) {
        push @l,"space_tree";
        $f&=~1;
    }

    if ($f&2) {
        push @l,"space_tree_valid";
        $f&=~2;
    }

    if ($f&4) {
        push @l,"verity";
        $f&=~4;
    }

    if ($f!=0 || $#l==-1) {
        push @l,sprintf("%x",$f);
    }

    return join(',',@l);
}

sub read_superblock {
	my ($f)=@_;
	my ($sb, @b, @b2, @di, $csum);

	seek($f,0x10000,0);
	read($f,$sb,0x1000);
	($roottree, $chunktree, $logtree)=unpack("x80QQQ",$sb);
	@b = unpack("A32A16QQA8QQQQQQQQQVVVVVQQQQvCCCA98A256QQA16x224a2048a672",$sb);
    @di = unpack("QQQVVVQQQVCCA16A16",$b[27]);

	$csum_type = $b[23];

	if ($csum_type == 1) {
		$csum = sprintf("%016x", unpack("Q", $b[0]));
	} elsif ($csum_type == 2 || $csum_type == 3) {
		$csum = sprintf("%016x%016x%016x%016x", unpack("QQQQ", $b[0]));
	} else {
		$csum = sprintf("%08x", unpack("V", $b[0]));
	}

	printf("superblock csum=%s fsuuid=%s physaddr=%x flags=%x magic=%s gen=%x roottree=%x chunktree=%x logtree=%x log_root_transid=%x total_bytes=%x bytes_used=%x root_dir_objectid=%x num_devices=%x sectorsize=%x nodesize=%x leafsize=%x stripesize=%x n=%x chunk_root_generation=%x compat_flags=%x compat_ro_flags=%s incompat_flags=%s csum_type=%x root_level=%x chunk_root_level=%x log_root_level=%x (dev_item id=%x numbytes=%x bytesused=%x ioalign=%x iowidth=%x sectorsize=%x type=%x gen=%x startoff=%x devgroup=%x seekspeed=%x bandwidth=%x devid=%s fsid=%s) label=%s cache_gen=%x uuid_tree_gen=%x metadata_uuid=%s\n", $csum, format_uuid($b[1]), $b[2], $b[3], $b[4], $b[5], $b[6], $b[7], $b[8], $b[9], $b[10], $b[11], $b[12], $b[13], $b[14], $b[15], $b[16], $b[17], $b[18], $b[19], $b[20], compat_ro_flags($b[21]), incompat_flags($b[22]), $b[23], $b[24], $b[25], $b[26], $di[0], $di[1], $di[2], $di[3], $di[4], $di[5], $di[6], $di[7], $di[8], $di[9], $di[10], $di[11], format_uuid($di[12]), format_uuid($di[13]), $b[28], $b[29], $b[30], format_uuid($b[31]));

	my $devid=format_uuid($di[12]);

	$nodesize = $b[15];

	$devs{$di[0]}=$f;

	my $bootstrap=substr($b[32],0,$b[18]);

	while (length($bootstrap)>0) {
		#print Dumper($bootstrap)."\n";
		@b2=unpack("QCQ",$bootstrap);
		printf("bootstrap %x,%x,%x\n", @b2[0], @b2[1], @b2[2]);
		$bootstrap=substr($bootstrap,0x11);

		my @c=unpack("QQQQVVVvvQQA16",$bootstrap);
		dump_item(0xe4, substr($bootstrap,0,0x30+($c[7]*0x20)), "", 0);

		$bootstrap=substr($bootstrap,0x30+($c[7]*0x20));

		my %obj;

		$obj{'physoffset'}=$c[10];
		$obj{'offset'}=$b2[2];
		$obj{'size'}=$c[0];
		$obj{'type'}=$c[3];
		$obj{'num_stripes'}=$c[7];
		$obj{'devid'}=$c[9];

		# FIXME - second stripes etc.

		push @l2p_bs,\%obj;
	}

	my $backups=$b[33];

    while (length($backups)>0) {
        my $backup=substr($backups,0,168);
        $backups=substr($backups,168);

        my @b3=unpack("QQQQQQQQQQQQQQQx32CCCCCCx10",$backup);

        printf("backup tree_root=%x tree_root_gen=%x chunk_root=%x chunk_root_gen=%x extent_root=%x extent_root_gen=%x fs_root=%x fs_root_gen=%x dev_root=%x dev_root_gen=%x csum_root=%x csum_root_gen=%x total_bytes=%x bytes_used=%x num_devices=%x tree_root_level=%x chunk_root_level=%x extent_root_level=%x fs_root_level=%x dev_root_level=%x csum_root_level=%x\n", @b3);
    }

	print "\n";
}

sub format_uuid {
	my ($s)=@_;
	my @b=unpack("VVVV",$s);

	return sprintf("%08x%08x%08x%08x", $b[3], $b[2], $b[1], $b[0]);
}

sub format_time {
	my ($t,$ns)=@_;

	my @tb=gmtime($t);

	return sprintf("%04u-%02u-%02uT%02u:%02u:%02u",$tb[5]+1900,$tb[4]+1,$tb[3],$tb[2],$tb[1],$tb[0]);
}

sub inode_flags {
    my ($flags)=@_;
    my @l=();

    if ($flags & 1) {
        push @l,"nodatasum";
        $flags &= ~1;
    }

    if ($flags & 2) {
        push @l,"nodatacow";
        $flags &= ~2;
    }

    if ($flags & 4) {
        push @l,"readonly";
        $flags &= ~4;
    }

    if ($flags & 8) {
        push @l,"nocompress";
        $flags &= ~8;
    }

    if ($flags & 16) {
        push @l,"prealloc";
        $flags &= ~16;
    }

    if ($flags & 32) {
        push @l,"sync";
        $flags &= ~32;
    }

    if ($flags & 64) {
        push @l,"immutable";
        $flags &= ~64;
    }

    if ($flags & 128) {
        push @l,"append";
        $flags &= ~128;
    }

    if ($flags & 256) {
        push @l,"nodump";
        $flags &= ~256;
    }

    if ($flags & 512) {
        push @l,"noatime";
        $flags &= ~512;
    }

    if ($flags & 1024) {
        push @l,"dirsync";
        $flags &= ~1024;
    }

    if ($flags & 2048) {
        push @l,"compress";
        $flags &= ~2048;
    }

    if ($flags & 4294967296) {
        push @l,"ro_verity";
        $flags &= ~4294967296;
    }

    if ($flags != 0) {
        push @l,sprintf("%x",$flags);
    }

    if ($#l > -1) {
        return join(',',@l);
    } else {
        return 0;
    }
}

sub format_balance {
	my ($s)=@_;
	my (@b,$flags,@f,$fl,$t);

	@b=unpack("QVVQQQQQQQVVVV",$s);

	$flags=$b[9];

# #define BTRFS_BALANCE_ARGS_PROFILES	(1ULL << 0)
# #define BTRFS_BALANCE_ARGS_USAGE	(1ULL << 1)
# #define BTRFS_BALANCE_ARGS_DEVID	(1ULL << 2)
# #define BTRFS_BALANCE_ARGS_DRANGE	(1ULL << 3)
# #define BTRFS_BALANCE_ARGS_VRANGE	(1ULL << 4)
# #define BTRFS_BALANCE_ARGS_LIMIT	(1ULL << 5)
# #define BTRFS_BALANCE_ARGS_LIMIT_RANGE	(1ULL << 6)
# #define BTRFS_BALANCE_ARGS_STRIPES_RANGE (1ULL << 7)
# #define BTRFS_BALANCE_ARGS_USAGE_RANGE	(1ULL << 10)

	$t=sprintf("profiles=%x",$b[0]);

	if ($flags & (1 << 10)) {
		$t.=sprintf(" usage=%x",($b[2] << 32) | $b[1]);
	} elsif ($flags & (1 << 1)) {
		$t.=sprintf(" usage=%x..%x",$b[1],$b[2]);
	}

	$t.=sprintf(" devid=%x pstart=%x pend=%x vstart=%x vend=%x target=%x",$b[3],$b[4],$b[5],$b[6],$b[7],$b[8]);

	@f=();
	$fl=$flags;
	if ($fl & (1 << 0)) {
		push @f,"profiles";
		$fl &= ~(1 << 0);
	}
	if ($fl & (1 << 1)) {
		push @f,"usage";
		$fl &= ~(1 << 1);
	}
	if ($fl & (1 << 2)) {
		push @f,"devid";
		$fl &= ~(1 << 2);
	}
	if ($fl & (1 << 3)) {
		push @f,"drange";
		$fl &= ~(1 << 3);
	}
	if ($fl & (1 << 4)) {
		push @f,"vrange";
		$fl &= ~(1 << 4);
	}
	if ($fl & (1 << 5)) {
		push @f,"limit";
		$fl &= ~(1 << 5);
	}
	if ($fl & (1 << 6)) {
		push @f,"limitrange";
		$fl &= ~(1 << 6);
	}
	if ($fl & (1 << 7)) {
		push @f,"stripesrange";
		$fl &= ~(1 << 7);
	}
	if ($fl & (1 << 8)) {
		push @f,"convert";
		$fl &= ~(1 << 8);
	}
	if ($fl & (1 << 9)) {
		push @f,"soft";
		$fl &= ~(1 << 9);
	}
	if ($fl & (1 << 10)) {
		push @f,"usagerange";
		$fl &= ~(1 << 10);
	}

	if ($fl != 0 || $#f == -1) {
		push @f,$fl;
	}

	$t.=sprintf(" flags=%s",join(',',@f));

	if ($flags & (1 << 5)) {
		$t.=sprintf(" limit=%x",($b[11] << 32) | $b[10]);
	} elsif ($flags & (1 << 6)) {
		$t.=sprintf(" limit=%x..%x",$b[11],$b[10]);
	}

	if ($flags & (1 << 7)) {
		$t.=sprintf(" stripes=%x..%x",$b[12],$b[13]);
	}

	return $t;
}

sub qgroup_status_flags {
	my ($f)=@_;
	my (@l);

	if ($f & 1) {
		push @l, "on";
		$f &= ~1;
	}

	if ($f & 2) {
		push @l, "rescan";
		$f &= ~2;
	}

	if ($f & 4) {
		push @l, "inconsistent";
		$f &= ~4;
	}

	if ($f != 0) {
		push @l, $f;
	}

	return join(',',@l);
}

sub dump_item {
	my ($type,$s,$pref,$id,$off)=@_;
	my (@b);

	my $unrecog = 0;

	print $pref;
	if ($type == 0x1 || $type == 0x84) { # INODE_ITEM or ROOT_ITEM
		if (length($s) < 0xa0) {
			$s.= chr(0) x (0xa0 - length($s));
		}
		@b=unpack("QQQQQVVVVQQQx32QVQVQVQV",$s);
		$s=substr($s,0xa0);

		if ($type==0x84) {
			print "root_item";
		} else {
			print "inode_item";
		}

		printf(" gen=%x transid=%x size=%x blocks=%x blockgroup=%x nlink=%x uid=%x gid=%x mode=%o rdev=%x flags=%s seq=%x atime=%s ctime=%s mtime=%s otime=%s", $b[0], $b[1], $b[2], $b[3], $b[4], $b[5], $b[6], $b[7], $b[8], $b[9], inode_flags($b[10]), $b[11], format_time($b[12], $b[13]), format_time($b[14], $b[15]), format_time($b[16], $b[17]), format_time($b[18], $b[19]));

		if ($type != 0x1) {
			@b=unpack("QQQQQQQVQCQCC",$s);
			$s=substr($s,0x4f);

			#print Dumper(@b)."\n";
			printf("; expgen=%x objid=%x blocknum=%x bytelimit=%x bytesused=%x snapshotgen=%x flags=%x numrefs=%x dropprogress=%x,%x,%x droplevel=%x rootlevel=%x", @b);

			@b=unpack("QA16A16A16QQQQQVQVQVQV",$s);
			$s=substr($s,0xc8); # above + 64 blank bytes

			printf(" gen2=%x uuid=%s par_uuid=%s rec_uuid=%s ctransid=%x otransid=%x stransid=%x rtransid=%x ctime=%s otime=%s stime=%s rtime=%s", $b[0], format_uuid($b[1]), format_uuid($b[2]), format_uuid($b[3]), $b[4], $b[5], $b[6], $b[7], format_time($b[8],$b[9]), format_time($b[10],$b[11]), format_time($b[12],$b[13]), format_time($b[14],$b[15]));
		}
	} elsif ($type == 0xc) { # INODE_REF
		printf("inode_ref");

		do {
			@b=unpack("Qv",$s);
			$s=substr($s,0xa);
			my $name=substr($s,0,$b[1]);
			$s=substr($s,$b[1]);

			printf(" index=%x n=%x name=%s",$b[0],$b[1],$name);
		} while (length($s)>0);
	} elsif ($type == 0xd) { # INODE_EXTREF
		printf("inode_extref");

		do {
			@b=unpack("QQv",$s);
			$s=substr($s,0x12);
			my $name=substr($s,0,$b[2]);
			$s=substr($s,$b[2]);

			printf(" dir=%x index=%x n=%x name=%s",$b[0],$b[1],$b[2],$name);
		} while (length($s)>0);
	} elsif ($type == 0x18 || $type == 0x54 || $type == 0x60) { # XATTR_ITEM, DIR_ITEM or DIR_INDEX
		print $type==0x54?"dir_item":($type==0x18?"xattr_item":"dir_index");

		while (length($s)>0) {
			@b=unpack("QCQQvvC",$s);
			$s=substr($s,0x1e);

			my $name=substr($s,0,$b[5]);
			$s=substr($s,$b[5]);

			my $name2=substr($s,0,$b[4]);
			$s=substr($s,$b[4]);

			printf(" key=%x,%x,%x transid=%x m=%x n=%x type=%x name=%s%s",$b[0],$b[1],$b[2],$b[3],$b[4],$b[5],$b[6],$name,$name2 eq ""?"":(" name2=".$name2));
		}
    } elsif ($type == 0x24) { # VERITY_DESC_ITEM
		printf("verity_desc_item");

		if ($off == 0) {
			@b=unpack("Qx16C",$s);
			$s=substr($s,25);

			printf(" size=%x enc=%x", $b[0], $b[1]);
		} else {
			while (length($s)>0) {
				@b=unpack("C",$s);
				printf(" %02x", $b[0]);
				$s = substr($s,1);
			}
		}
	} elsif ($type == 0x25) { # VERITY_MERKLE_ITEM
		while (length($s)>0) {
			@b=unpack("NNNNNNNN",$s);
			printf(" %008x%008x%008x%008x%008x%008x%008x%008x", $b[0], $b[1], $b[2], $b[3], $b[4], $b[5], $b[6], $b[7]);
			$s = substr($s,32);
		}
	} elsif ($type == 0x30) { # ORPHAN_ITEM
		printf("orphan_item");
	} elsif ($type == 0x6c) { # EXTENT_DATA
		@b=unpack("QQCCvC",$s);
		$s=substr($s,0x15);

		printf("extent_data gen=%x size=%x comp=%s enc=%s otherenc=%s type=%s", $b[0], $b[1], $b[2], $b[3], $b[4], $b[5]);

		if ($b[5] != 0) {
			@b=unpack("QQQQ",$s);
			$s=substr($s,0x20);

			printf(" ea=%x es=%x o=%x s=%x",@b);
		} else {
			$s=substr($s,$b[1]);
		}
	} elsif ($type == 0x80) { # EXTENT_CSUM
		print "extent_csum";

		if ($csum_type == 1) { # xxhash
			while (length($s)>0) {
				printf(" %016x",unpack("Q",$s));
				$s=substr($s,8);
			}
		} elsif ($csum_type == 2 || $csum_type == 3) { # sha256 or blake2
			while (length($s)>0) {
				printf(" %016x%016x%016x%016x",unpack("QQQQ",$s));
				$s=substr($s,32);
			}
		} else {
			while (length($s)>0) {
				printf(" %08x",unpack("V",$s));
				$s=substr($s,4);
			}
		}
	} elsif ($type == 0x90 || $type == 0x9c) { # ROOT_BACKREF or ROOT_REF
		@b=unpack("QQv",$s);
		$s=substr($s,18);

		my $name=substr($s,0,$b[2]);
		$s=substr($s,$b[2]);

		printf("%s id=%x seq=%x n=%x name=%s", $type==0x90?"root_backref":"root_ref", $b[0], $b[1], $b[2], $name);
	} elsif ($type == 0xa8 || $type == 0xa9) { # EXTENT_ITEM_KEY or METADATA_ITEM_KEY
		# FIXME - TREE_BLOCK is out by one byte (why?)
		if (length($s)==4) {
			@b=unpack("L",$s);
			$s=substr($s,4);
			printf("extent_item_v0 refcount=%x",$b[0]);
		} else {
			@b=unpack("QQQ",$s);
			printf("%s refcount=%x gen=%x flags=%x ",$type == 0xa9 ? "metadata_item_key" : "extent_item_key",$b[0],$b[1],$b[2]);

			$s=substr($s,24);

			my $refcount=$b[0];
			if ($b[2]&2 && $type != 0xa9) {
				@b=unpack("QCQC",$s);
				printf("key=%x,%x,%x level=%u ",$b[0],$b[1],$b[2],$b[3]);
				$s=substr($s,18);
			}

			while (length($s)>0) {
				my $irt=unpack("C",$s);
				$s = substr($s,1);

				if ($irt == 0xb0) {
					@b=unpack("Q",$s);
					$s=substr($s,8);
					printf("tree_block_ref root=%x ",$b[0]);
				} elsif ($irt == 0xb2) {
					@b=unpack("QQQv",$s);
					$s=substr($s,28);
					printf("extent_data_ref root=%x objid=%x offset=%x count=%x ",@b);
					$refcount-=$b[3]-1;
				} elsif ($irt == 0xb6) {
					@b=unpack("Q",$s);
					$s=substr($s,8);
					printf("shared_block_ref offset=%x",$b[0]);
				} elsif ($irt == 0xb8) {
					@b=unpack("Qv",$s);
					$s=substr($s,12);
					printf("shared_data_ref offset=%x count=%x ",@b);
					$refcount-=$b[1]-1;
				} else {
					printf("unknown %x (length %u)", $irt, length($s));
				}
			}
		}
	} elsif ($type == 0xb0) { # TREE_BLOCK_REF
		printf("tree_block_ref ");
	} elsif ($type == 0xb2) { # EXTENT_DATA_REF
		@b=unpack("QQQv",$s);
		$s=substr($s,28);
		printf("extent_data_ref root=%x objid=%x offset=%x count=%x ",@b);
	} elsif ($type == 0xb4) { # EXTENT_REF_V0
		@b=unpack("QQQv",$s);
		$s=substr($s,28);

		printf("extent_ref_v0 root=%x gen=%x objid=%x count=%x",@b);
	} elsif ($type == 0xb6) { # SHARED_BLOCK_REF
		printf("shared_block_ref ");
	} elsif ($type == 0xb8) { # SHARED_DATA_REF
		@b=unpack("v",$s);
		$s=substr($s,4);

		printf("shared_data_ref count=%x",@b);
	} elsif ($type == 0xc0) { # BLOCK_GROUP_ITEM
		@b=unpack("QQQ",$s);
		$s=substr($s,0x18);
		printf("block_group_item size=%x chunktreeid=%x flags=%x",$b[0],$b[1],$b[2]);
        } elsif ($type == 0xc6) { # FREE_SPACE_INFO
		@b=unpack("VV",$s);
		$s=substr($s,0x8);
		printf("free_space_info count=%x flags=%x",$b[0],$b[1]);
	} elsif ($type == 0xc7) { # FREE_SPACE_EXTENT
		printf("free_space_extent");
	} elsif ($type == 0xc8) { # FREE_SPACE_BITMAP
		printf("free_space_bitmap"); # FIXME - print contents
	} elsif ($type == 0xcc) { # DEV_EXTENT
		@b=unpack("QQQQA16",$s);
		$s=substr($s,0x30);
		printf("dev_extent chunktree=%x, chunkobjid=%x, logaddr=%x, size=%x, chunktreeuuid=%s", $b[0], $b[1], $b[2], $b[3], format_uuid($b[4]));
	} elsif ($type == 0xd8) { # DEV_ITEM
		@b=unpack("QQQVVVQQQVCCA16A16",$s);
		printf("dev_item id=%x numbytes=%x bytesused=%x ioalign=%x iowidth=%x sectorsize=%x type=%x gen=%x startoff=%x devgroup=%x seekspeed=%x bandwidth=%x devid=%s fsid=%s", $b[0], $b[1], $b[2], $b[3], $b[4], $b[5], $b[6], $b[7], $b[8], $b[9], $b[10], $b[11], format_uuid($b[12]), format_uuid($b[13]));
		$s=substr($s,0x62);
	} elsif ($type == 0xe4) { # CHUNK_ITEM
		@b=unpack("QQQQVVVvv",$s);
		printf("chunk_item size=%x root=%x stripelength=%x type=%x ioalign=%x iowidth=%x sectorsize=%x numstripes=%x substripes=%x",$b[0],$b[1],$b[2],$b[3],$b[4],$b[5],$b[6],$b[7],$b[8]);
		$s=substr($s,0x30);

		my $numstripes=$b[7];
		for (my $i=0;$i<$numstripes;$i++) {
			@b=unpack("QQA16",$s);
			$s=substr($s,0x20);

			printf(" stripe(%u) devid=%x offset=%x devuuid=%s",$i,$b[0],$b[1],format_uuid($b[2]));
		}
	} elsif ($type == 0xf0) { # QGROUP_STATUS
		@b=unpack("QQQQ", $s);
		printf("qgroup_status version=%x generation=%x flags=%s rescan=%x",$b[0],$b[1],qgroup_status_flags($b[2]),$b[3]);
		$s=substr($s,0x20);
	} elsif ($type == 0xf2) { # QGROUP_INFO
		@b=unpack("QQQQQ", $s);
		printf("qgroup_info generation=%x rfer=%x rfer_cmpr=%x excl=%x excl_cmpr=%x",$b[0],$b[1],$b[2],$b[3],$b[4]);
		$s=substr($s,0x28);
	} elsif ($type == 0xf4) { # QGROUP_LIMIT
		@b=unpack("QQQQQ", $s);
		printf("qgroup_limit flags=%x max_rfer=%x max_excl=%x rsv_rfer=%x rsv_excl=%x",$b[0],$b[1],$b[2],$b[3],$b[4]);
		$s=substr($s,0x28);
	} elsif ($type == 0xf8 && $id == 0xfffffffffffffffc) { # balance
		my ($fl,@f);

		@b=unpack("Q",$s);
		$s=substr($s,8);

		$fl=$b[0];
		@f=();
		if ($fl & (1 << 0)) {
			push @f,"data";
			$fl &= ~(1 << 0);
		}
		if ($fl & (1 << 1)) {
			push @f,"system";
			$fl &= ~(1 << 1);
		}
		if ($fl & (1 << 2)) {
			push @f,"metadata";
			$fl &= ~(1 << 2);
		}
		if ($fl!=0 || $#f==-1) {
			push @f,$fl;
		}

		printf("balance flags=%s data=(%s) metadata=(%s) sys=(%s)",join(',',@f),format_balance(substr($s,0,0x88)),format_balance(substr($s,0x88,0x88)),format_balance(substr($s,0x110,0x88)));

		$s=substr($s,0x1b8);
	} elsif ($type == 0xf9) { # DEV_STATS
		print "dev_stats";

		while (length($s)>0) {
			printf(" %x",unpack("Q",$s));
			$s=substr($s,8);
		}
	} elsif ($type == 0xfb) { # UUID_SUBVOL
		print "uuid_subvol";

		while (length($s)>0) {
			printf(" %x",unpack("Q",$s));
			$s=substr($s,8);
		}
	} elsif ($type == 0xfc) { # UUID_REC_SUBVOL
		print "uuid_rec_subvol";

		while (length($s)>0) {
			printf(" %x",unpack("Q",$s));
			$s=substr($s,8);
		}
    } elsif ($type == 0 && $id == 0xfffffffffffffff5) { # free space
        @b=unpack("QCQQQQ",$s);
        $s=substr($s,0x29);

        printf("free_space key=(%x,%x,%x) gen=%x num_entries=%x num_bitmaps=%x",@b);
	} else {
		printf STDERR ("ERROR - unknown type %x (size=%x, tell=%x)\n", $type, length($s), tell($f));
		printf("unknown (size=%x)", length($s));
		$unrecog = 1;
	}

	if ($unrecog == 0 && length($s) > 0) {
		printf(" (left=%x)",length($s));
	}

	print "\n";
}

sub read_data {
	my ($addr,$size,$bs)=@_;
	my (@arr,$f,$data,$stripeoff,$parity,$stripe,$physstripe,$physoff);

	if ($bs==1) {
		@arr=@l2p_bs;
	} else {
		@arr=@l2p;
	}

	foreach my $obj (@arr) {
		if ($obj->{'offset'}<=$addr&&($addr-$obj->{'offset'})<$obj->{'size'}) {
			if ($obj->{'type'} & 0x80) { # RAID5
				$stripeoff=($addr-$obj->{'offset'})%0x20000;
				$parity=(int(($addr-$obj->{'offset'})/0x20000)+2)%3;
				$stripe=int($stripeoff/0x10000);
				$physstripe=($parity+$stripe+1)%3;

				if ($physstripe==0) {
					$f=$devs{$obj->{'devid'}};
					$physoff=$obj->{'physoffset'}+(int(($addr-$obj->{'offset'})/0x20000)*0x10000)+($stripeoff%0x10000);
				} elsif ($physstripe==1) {
					$f=$devs{$obj->{'devid2'}};
					$physoff=$obj->{'physoffset2'}+(int(($addr-$obj->{'offset'})/0x20000)*0x10000)+($stripeoff%0x10000);
				} elsif ($physstripe==2) {
					$f=$devs{$obj->{'devid3'}};
					$physoff=$obj->{'physoffset3'}+(int(($addr-$obj->{'offset'})/0x20000)*0x10000)+($stripeoff%0x10000);
				}

				seek($f,$physoff,0);
				read($f,$data,$size);
			} elsif ($obj->{'type'} & 0x100) { # RAID6
				$stripeoff=($addr-$obj->{'offset'})%0x20000;
				$parity=(int(($addr-$obj->{'offset'})/0x20000)+3)%4;
				$stripe=int($stripeoff/0x10000);
				$physstripe=($parity+$stripe+1)%4;

				if ($physstripe==0) {
					$f=$devs{$obj->{'devid'}};
					$physoff=$obj->{'physoffset'}+(int(($addr-$obj->{'offset'})/0x20000)*0x10000)+($stripeoff%0x10000);
				} elsif ($physstripe==1) {
					$f=$devs{$obj->{'devid2'}};
					$physoff=$obj->{'physoffset2'}+(int(($addr-$obj->{'offset'})/0x20000)*0x10000)+($stripeoff%0x10000);
				} elsif ($physstripe==2) {
					$f=$devs{$obj->{'devid3'}};
					$physoff=$obj->{'physoffset3'}+(int(($addr-$obj->{'offset'})/0x20000)*0x10000)+($stripeoff%0x10000);
				} elsif ($physstripe==3) {
					$f=$devs{$obj->{'devid4'}};
					$physoff=$obj->{'physoffset4'}+(int(($addr-$obj->{'offset'})/0x20000)*0x10000)+($stripeoff%0x10000);
				}

				seek($f,$physoff,0);
				read($f,$data,$size);
			} elsif ($obj->{'type'} & 0x40) { # RAID10
				$stripeoff=($addr-$obj->{'offset'})%0x20000;
				$stripe=int($stripeoff/0x10000);

				if ($stripe==0) {
					$f=$devs{$obj->{'devid'}};
					$physoff=$obj->{'physoffset'}+(int(($addr-$obj->{'offset'})/0x20000)*0x10000)+($stripeoff%0x10000);
				} else {
					$f=$devs{$obj->{'devid3'}};
					$physoff=$obj->{'physoffset3'}+(int(($addr-$obj->{'offset'})/0x20000)*0x10000)+($stripeoff%0x10000);
				}

				seek($f,$physoff,0);
				read($f,$data,$size);
			} elsif ($obj->{'type'} & 0x8) { # RAID0
				$stripeoff=($addr-$obj->{'offset'})%0x20000;
				$stripe=int($stripeoff/0x10000);

				if ($stripe==0) {
					$f=$devs{$obj->{'devid'}};
					$physoff=$obj->{'physoffset'}+(int(($addr-$obj->{'offset'})/0x20000)*0x10000)+($stripeoff%0x10000);
				} else {
					$f=$devs{$obj->{'devid2'}};
					$physoff=$obj->{'physoffset2'}+(int(($addr-$obj->{'offset'})/0x20000)*0x10000)+($stripeoff%0x10000);
				}

				seek($f,$physoff,0);
				read($f,$data,$size);
			} else { # SINGLE, DUP, RAID1
				seek($devs{$obj->{'devid'}},$obj->{'physoffset'}+$addr-$obj->{'offset'},0);
				read($devs{$obj->{'devid'}},$data,$size);
			}

			return $data;
		}
	}
}

sub dump_tree {
	my ($addr, $pref, $bs)=@_;
	my ($head, @headbits, $level, $treenum, $tree, $csum);

	$tree = read_data($addr, $nodesize, $bs);

	@headbits=unpack("A32A16QQA16QQVC",$tree);
	if ($headbits[2] != $addr) {
		printf STDERR sprintf("Address mismatch: expected %llx, got %llx\n", $addr, $headbits[2]);
		exit;
	}

	if ($csum_type == 1) {
		$csum = sprintf("%016x", unpack("Q", $headbits[0]));
	} elsif ($csum_type == 2 || $csum_type == 3) {
		$csum = sprintf("%016x%016x%016x%016x", unpack("QQQQ", $headbits[0]));
	} else {
		$csum = sprintf("%08x", unpack("V", $headbits[0]));
	}

	print $pref;
	printf("header csum=%s fsid=%s addr=%x flags=%x chunk=%s gen=%x tree=%x numitems=%x level=%x\n", $csum, format_uuid($headbits[1]), $headbits[2], $headbits[3], format_uuid($headbits[4]), $headbits[5], $headbits[6], $headbits[7], $headbits[8]);

	$level=$headbits[8];
	$treenum=$headbits[6];

	my $numitems=$headbits[7];

	if ($level==0) {
		my $headaddr=tell($f);
		for (my $i=0;$i<$numitems;$i++) {
# 			read($f, my $itemhead, 0x19);
			my $itemhead=substr($tree,0x65+($i*0x19),0x19);

			my @ihb=unpack("QCQVV",$itemhead);

			#print Dumper(@ihb)."\n";
			print $pref;
			printf("%x,%x,%x\n",$ihb[0],$ihb[1],$ihb[2]);

			my $item=substr($tree,0x65+$ihb[3],$ihb[4]);
			dump_item($ihb[1],$item,$pref,$ihb[0],$ihb[2]);

			if ($treenum==3&&$ihb[1]==0xe4) {
				my @b=unpack("QQQQVVVvv",$item);
				my $stripes=substr($item,48);
				my %obj;

				my $numstripes=$b[7];

				my @cis=unpack("QQA16",$stripes);
				$stripes=substr($stripes,32);

				$obj{'physoffset'}=$cis[1];
				$obj{'offset'}=$ihb[2];
				$obj{'size'}=$b[0];
				$obj{'type'}=$b[3];
				$obj{'num_stripes'}=$b[7];
				$obj{'devid'}=$cis[0];

				if ($b[7] > 1) {
					my @cis=unpack("QQA16",$stripes);
					$stripes=substr($stripes,32);

					$obj{'physoffset2'}=$cis[1];
					$obj{'devid2'}=$cis[0];
				}

				if ($b[7] > 2) {
					my @cis=unpack("QQA16",$stripes);
					$stripes=substr($stripes,32);

					$obj{'physoffset3'}=$cis[1];
					$obj{'devid3'}=$cis[0];
				}

				if ($b[7] > 3) {
					my @cis=unpack("QQA16",$stripes);
					$stripes=substr($stripes,32);

					$obj{'physoffset4'}=$cis[1];
					$obj{'devid4'}=$cis[0];
				}

				push @l2p,\%obj;

# 				print Dumper(@l2p);
            }

			if ($ihb[1] == 0x84) {
				if ($treenum == 1) {
					$roots{$ihb[0]}=unpack("x176Q",$item);
				} elsif ($treenum == 0xfffffffffffffffa && $ihb[0] == 0xfffffffffffffffa) {
					$logroots{$ihb[2]}=unpack("x176Q",$item);
				}
			}
		}
	} else {
		for (my $i=0;$i<$numitems;$i++) {
			my $itemhead=substr($tree,0x65+($i*0x21),0x21);

			my @ihb=unpack("QCQQQ",$itemhead);

			print $pref;
			printf("%x,%x,%x block=%x gen=%x\n",$ihb[0],$ihb[1],$ihb[2],$ihb[3],$ihb[4]);

			dump_tree($ihb[3], " ".$pref, $bs);
		}
	}
}
