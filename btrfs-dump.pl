#!/usr/bin/perl

# Quick and dirty btrfs tree dumper. Great for diff'ing, which btrfs-debug-tree isn't...
# Do something like:
#
# qemu-nbd -r -n -c /dev/nbd0 ~/vms/win7/win7-32.img ; sleep 1 ; chmod 666 /dev/nbd0p3
# ./btrfs-dump.pl > dump2.txt
# diff -u dump1.txt dump2.txt > diff2.txt

# Like btrfs.h, I'm disclaiming any copyright on this file, but I'd appreciate
# hearing about what you do with it: mark@harmstone.com.

use Data::Dumper;

# open($f,"/root/btrfs-test4");
open($f,"/dev/nbd0p3");
binmode($f);

%roots=();
my @l2p=();
my @l2p_bs=();

read_superblock($f);

print "CHUNK: \n";
dump_tree($f, $chunktree, "", 1);
print "\n";

print "ROOT: \n";
dump_tree($f, $roottree, "", 0);
print "\n";

if ($logtree != 0) {
    print "LOG: \n";
    dump_tree($f, $logtree, "", 0);
    print "\n";
}

@rs=sort { $a <=> $b } (keys(%roots));

foreach my $r (@rs) {
	printf("Tree %x:\n",$r);
	dump_tree($f, $roots{$r}, "");
	print "\n";
}
	
close($f);

sub incompat_flags {
    my ($f)=@_;
    my @l;
    
    if ($f&1) {
        push @l,"mixed_backref";
        $f&=~1;
    }
    
    if ($f&2) {
        push @l,"default_subvol";
        $f&=~2;
    }
    
    if ($f&4) {
        push @l,"mixed_groups";
        $f&=~4;
    }
    
    if ($f&8) {
        push @l,"compress_lzo";
        $f&=~8;
    }
    
    if ($f&16) {
        push @l,"compress_lzov2";
        $f&=~16;
    }
    
    if ($f&32) {
        push @l,"big_metadata";
        $f&=~32;
    }
    
    if ($f&64) {
        push @l,"extended_iref";
        $f&=~64;
    }
    
    if ($f&128) {
        push @l,"raid56";
        $f&=~128;
    }
    
    if ($f&256) {
        push @l,"skinny_metadata";
        $f&=~256;
    }
    
    if ($f&512) {
        push @l,"no_holes";
        $f&=~512;
    }
    
    if ($f!=0 || $#l==-1) {
        push @l,sprintf("%x",$f);
    }
    
    return join(',',@l);
}

sub read_superblock {
	my ($f)=@_;
	my ($sb, @b, @b2, @di);
	
	seek($f,0x10000,0);
	read($f,$sb,0x1000);
	($roottree, $chunktree, $logtree)=unpack("x80QQQ",$sb);
	@b = unpack("Vx28A16QQA8QQQQQQQQQVVVVVQQQQvCCCA98A256QQx240a2048a672",$sb);
    @di = unpack("QQQVVVQQQVCCA16A16",$b[27]);
    
	printf("superblock csum=%x fsuuid=%s physaddr=%x flags=%x magic=%s gen=%x roottree=%x chunktree=%x logtree=%x log_root_transid=%x total_bytes=%x bytes_used=%x root_dir_objectid=%x num_devices=%x sectorsize=%x nodesize=%x leafsize=%x stripesize=%x n=%x chunk_root_generation=%x compat_flags=%x compat_ro_flags=%x incompat_flags=%s csum_type=%x root_level=%x chunk_root_level=%x log_root_level=%x (dev_item id=%x numbytes=%x bytesused=%x ioalign=%x iowidth=%x sectorsize=%x type=%x gen=%x startoff=%x devgroup=%x seekspeed=%x bandwidth=%x devid=%s fsid=%s) label=%s cache_gen=%x uuid_tree_gen=%x\n", $b[0], format_uuid($b[1]), $b[2], $b[3], $b[4], $b[5], $b[6], $b[7], $b[8], $b[9], $b[10], $b[11], $b[12], $b[13], $b[14], $b[15], $b[16], $b[17], $b[18], $b[19], $b[20], $b[21], incompat_flags($b[22]), $b[23], $b[24], $b[25], $b[26], $di[0], $di[1], $di[2], $di[3], $di[4], $di[5], $di[6], $di[7], $di[8], $di[9], $di[10], $di[11], format_uuid($di[12]), format_uuid($di[13]), $b[28], $b[29], $b[30]);
	$devid=format_uuid($di[12]);
	
	my $bootstrap=substr($b[31],0,$b[18]);
	
	while (length($bootstrap)>0) {
		#print Dumper($bootstrap)."\n";
		@b2=unpack("QCQ",$bootstrap);
		printf("bootstrap %x,%x,%x\n", @b2[0], @b2[1], @b2[2]);
		$bootstrap=substr($bootstrap,0x11);
        
		my @c=unpack("QQQQVVVvvQQA16",$bootstrap);
		dump_item(0xe4, substr($bootstrap,0,0x30+($c[7]*0x20)), "");
		
		$bootstrap=substr($bootstrap,0x30+($c[7]*0x20));
		
		my %obj;

		$obj{'physoffset'}=$c[10];
		$obj{'offset'}=$b2[2];
		$obj{'size'}=$c[0];
		push @l2p_bs,\%obj;
	}
	
	my $backups=$b[32];
    
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

    if ($flags != 0) {
        push @l,sprintf("%x",$flags);
    }

    if ($#l > -1) {
        return join(',',@l);
    } else {
        return 0;
    }
}

sub dump_item {
	my ($type,$s,$pref,$id)=@_;
	my (@b);

	my $unrecog = 0;
	
	print $pref;
	if ($type == 0x1 || $type == 0x84) { # INODE_ITEM or ROOT_ITEM
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
		
		# FIXME
		while (length($s)>0) {
			printf(" %08x",unpack("V",$s));
			$s=substr($s,4);
		}
	} elsif ($type == 0x90 || $type == 0x9c) { # ROOT_BACKREF or ROOT_REF
		@b=unpack("QQv",$s);
		$s=substr($s,18);
		
		my $name=substr($s,0,$b[2]);
		$s=substr($s,$b[2]);
		
		printf("%s id=%x seq=%x n=%x name=%s", $type==0x90?"root_backref":"root_ref", $b[0], $b[1], $b[2], $name);
	} elsif ($type == 0xa8 || $type == 0xa9) { # EXTENT_ITEM_KEY or METADATA_ITEM_KEY
		# FIXME - TREE_BLOCK is out by one byte (why?)
		@b=unpack("QQQ",$s);
		printf("%s refcount=%x gen=%x flags=%x ",$type == 0xa9 ? "metadata_item_key" : "extent_item_key",$b[0],$b[1],$b[2]);
		
		$s=substr($s,24);
		
		my $refcount=$b[0];
		if ($b[2]&2 && $type != 0xa9) {
			@b=unpack("QCQC",$s);
			printf("key=%x,%x,%x level=%u ",$b[0],$b[1],$b[2],$b[3]);
			$s=substr($s,18);
		}
		
		for (my $i=0;$i<$refcount;$i++) {
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
				$refcount+=$b[3]-1;
			} elsif ($irt == 0xb8) {
				@b=unpack("Qv",$s);
				$s=substr($s,12);
				printf("shared_data_ref offset=%x count=%x ",@b);
				$refcount+=$b[1]-1;
			} else {
				printf("unknown %x (length %u)", $irt, length($s));
			}
			# FIXME - SHARED_BLOCK_REF
		}
	} elsif ($type == 0xb4) { # EXTENT_REF_V0
		@b=unpack("QQQv",$s);
		$s=substr($s,28);
		
		printf("extent_ref_v0 root=%x gen=%x objid=%x count=%x",@b);
	} elsif ($type == 0xc0) { # BLOCK_GROUP_ITEM
		@b=unpack("QQQ",$s);
		$s=substr($s,0x18);
		printf("block_group_item size=%x chunktreeid=%x flags=%x",$b[0],$b[1],$b[2]);
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
	} elsif ($type == 0xf9) { # DEV_STATS
		print "dev_stats";
		
		while (length($s)>0) {
			printf(" %x",unpack("Q",$s));
			$s=substr($s,8);
		}
	} elsif ($type == 0xfb) { # UUID_SUBVOL
		print "uuid_subvol";
		
		# FIXME
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

sub log_to_phys {
	my ($addr,$bs)=@_;
	my @arr;
	
	if ($bs==1) {
		@arr=@l2p_bs;
	} else {
		@arr=@l2p;
	}
	
	foreach my $obj (@arr) {
		if ($obj->{'offset'}<=$addr&&($addr-$obj->{'offset'})<$obj->{'size'}) {
			return $obj->{'physoffset'}+$addr-$obj->{'offset'};
		}
	}
}

sub dump_tree {
	my ($f, $addr, $pref, $bs)=@_;
	my ($physaddr, $head, @headbits, $level, $treenum);
	
	$physaddr = log_to_phys($addr, $bs);
	
	seek($f, $physaddr, 0);
	
	read($f, $head, 0x65);
	
	@headbits=unpack("Vx28A16QQA16QQVC",$head);
	#print Dumper(@headbits)."\n";
	print $pref;
	printf("header csum=%08x fsid=%s addr=%x flags=%x chunk=%s gen=%x tree=%x numitems=%x level=%x\n", $headbits[0], format_uuid($headbits[1]), $headbits[2], $headbits[3], format_uuid($headbits[4]), $headbits[5], $headbits[6], $headbits[7], $headbits[8]);
	
	$level=$headbits[8];
	$treenum=$headbits[6];
	
	my $numitems=$headbits[7];
	
	if ($level==0) {
		my $headaddr=tell($f);
		for (my $i=0;$i<$numitems;$i++) {
			read($f, my $itemhead, 0x19);
			
			my @ihb=unpack("QCQVV",$itemhead);
			
			#print Dumper(@ihb)."\n";
			print $pref;
			printf("%x,%x,%x\n",$ihb[0],$ihb[1],$ihb[2]);
			
			my $curpos=tell($f);
			seek($f, $headaddr+$ihb[3], 0);
			read($f,my $item,$ihb[4]);
			dump_item($ihb[1],$item,$pref,$ihb[0]);
			seek($f, $curpos, 0);
			
			if ($treenum==3&&$ihb[1]==0xe4) {
				my @b=unpack("QQQQVVVvv",$item);
				my $stripes=substr($item,48);
				my %obj;
				
				my $numstripes=$b[7];
				
				for (my $j=0;$j<$numstripes;$j++) {
					my @cis=unpack("QQA16",$stripes);
					$stripes=substr($stripes,32);
					
					if (format_uuid($cis[2]) eq $devid) {
						#print STDERR join(',',@cis)."\n";
						$obj{'physoffset'}=$cis[1];
						$obj{'offset'}=$ihb[2];
						$obj{'size'}=$b[0];
						push @l2p,\%obj;
						break;
					}
				}
				
# 				print Dumper(@l2p);
            }
			
			if ($treenum==1&&$ihb[1]==0x84) {
				$roots{$ihb[0]}=unpack("x176Q",$item);
			}
		}
	} else {
		for (my $i=0;$i<$numitems;$i++) {
			read($f, my $itemhead, 0x21);
			
			my @ihb=unpack("QCQQQ",$itemhead);
			
			print $pref;
			printf("%x,%x,%x block=%x gen=%x\n",$ihb[0],$ihb[1],$ihb[2],$ihb[3],$ihb[4]);
			
			my $curpos=tell($f);
			dump_tree($f, $ihb[3], " ".$pref, $bs);
			seek($f,$curpos,0);
		}
	}
}