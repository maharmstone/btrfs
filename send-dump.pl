#!/usr/bin/perl

# Dumper for btrfs send streams.
# Released under the same terms, or lack thereof, as btrfs-dump.pl.

open($f,$ARGV[0]) or die "Error opening ".$ARGV[0].": ".$!;
binmode($f);

while (!eof($f)) {
    do_stream($f);

    if (!eof($f)) {
        print "---\n";
    }
}

close($f);

sub do_stream {
    my ($f)=@_;

    read($f,$a,0x11);
    ($magic,$ver)=unpack("a13V",$a);

    if ($magic ne "btrfs-stream\0") {
        printf STDERR "Not a send file.\n";
        close($f);
        exit;
    }

    if ($ver != 1 && $ver != 2) {
        printf STDERR "Version $ver not supported.\n";
        close($f);
        exit;
    }

    $type = 0;
    while (!eof($f) && $type != 21) {
        read($f,$a,0xa);
        ($len,$type,$crc)=unpack("VvV",$a);

        if ($type == 1) {
            printf("subvol, %x, %08x\n", $len, $crc);
        } elsif ($type == 2) {
            printf("snapshot, %x, %08x\n", $len, $crc);
        } elsif ($type == 3) {
            printf("mkfile, %x, %08x\n", $len, $crc);
        } elsif ($type == 4) {
            printf("mkdir, %x, %08x\n", $len, $crc);
        } elsif ($type == 5) {
            printf("mknod, %x, %08x\n", $len, $crc);
        } elsif ($type == 6) {
            printf("mkfifo, %x, %08x\n", $len, $crc);
        } elsif ($type == 7) {
            printf("mksock, %x, %08x\n", $len, $crc);
        } elsif ($type == 8) {
            printf("symlink, %x, %08x\n", $len, $crc);
        } elsif ($type == 9) {
            printf("rename, %x, %08x\n", $len, $crc);
        } elsif ($type == 10) {
            printf("link, %x, %08x\n", $len, $crc);
        } elsif ($type == 11) {
            printf("unlink, %x, %08x\n", $len, $crc);
        } elsif ($type == 12) {
            printf("rmdir, %x, %08x\n", $len, $crc);
        } elsif ($type == 13) {
            printf("set_xattr, %x, %08x\n", $len, $crc);
        } elsif ($type == 14) {
            printf("remove_xattr, %x, %08x\n", $len, $crc);
        } elsif ($type == 15) {
            printf("write, %x, %08x\n", $len, $crc);
        } elsif ($type == 16) {
            printf("clone, %x, %08x\n", $len, $crc);
        } elsif ($type == 17) {
            printf("truncate, %x, %08x\n", $len, $crc);
        } elsif ($type == 18) {
            printf("chmod, %x, %08x\n", $len, $crc);
        } elsif ($type == 19) {
            printf("chown, %x, %08x\n", $len, $crc);
        } elsif ($type == 20) {
            printf("utimes, %x, %08x\n", $len, $crc);
        } elsif ($type == 21) {
            printf("end, %x, %08x\n", $len, $crc);
        } elsif ($type == 22) {
            printf("update-extent, %x, %08x\n", $len, $crc);
        } elsif ($type == 23) {
            printf("fallocate, %x, %08x\n", $len, $crc);
        } elsif ($type == 24) {
            printf("fileattr, %x, %08x\n", $len, $crc);
        } elsif ($type == 25) {
            printf("encoded-write, %x, %08x\n", $len, $crc);
        } else {
            printf("unknown(%x), %x, %08x\n", $type, $len, $crc);
        }

        read($f,$b,$len);
        print_tlvs($b);
    }
}

sub btrfstime {
    my ($t)=@_;

    my $ut = unpack("Q",$t);
    my @lt = localtime($ut);

    return sprintf("%04u-%02u-%02u %02u:%02u:%02u",$lt[5]+1900,$lt[4]+1,$lt[3],$lt[2],$lt[1],$lt[0]);
}

sub print_tlvs {
    my ($b)=@_;

    while (length($b)>0) {
        my ($t,$l)=unpack("vv",$b);

        if ($t == 1) {
            printf("  uuid: %08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x\n", unpack("NnnnCCCCCC",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 2) {
            printf("  transid: %x\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 3) {
            printf("  inode: %x\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 4) {
            printf("  size: %x\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 5) {
            printf("  mode: %o\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 6) {
            printf("  uid: %u\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 7) {
            printf("  gid: %u\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 8) {
            printf("  rdev: %x\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 9) {
            printf("  ctime: %s\n", btrfstime(substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 10) {
            printf("  mtime: %s\n", btrfstime(substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 11) {
            printf("  atime: %s\n", btrfstime(substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 12) {
            printf("  otime: %s\n", btrfstime(substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 13) {
            printf("  xattr_name: \"%s\"\n", substr($b,4,$l));
            $b=substr($b,$l+4);
        } elsif ($t == 14) {
            printf("  xattr_data: \"%s\"\n", substr($b,4,$l));
            $b=substr($b,$l+4);
        } elsif ($t == 15) {
            printf("  path: \"%s\"\n", substr($b,4,$l));
            $b=substr($b,$l+4);
        } elsif ($t == 16) {
            printf("  path_to: \"%s\"\n", substr($b,4,$l));
            $b=substr($b,$l+4);
        } elsif ($t == 17) {
            printf("  path_link: \"%s\"\n", substr($b,4,$l));
            $b=substr($b,$l+4);
        } elsif ($t == 18) {
            printf("  offset: %x\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 19) {
            if ($ver == 2) {
                printf("  data: (%x bytes)\n", length($b) - 2); # FIXME
                $b="";
            } else {
                printf("  data: (%x bytes)\n", $l);
                $b=substr($b,$l+4);
            }
        } elsif ($t == 20) {
            printf("  clone_uuid: %08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x\n", unpack("NnnnCCCCCC",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 21) {
            printf("  clone_transid: %x\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 22) {
            printf("  clone_path: \"%s\"\n", substr($b,4,$l));
            $b=substr($b,$l+4);
        } elsif ($t == 23) {
            printf("  clone_offset: %x\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 24) {
            printf("  clone_len: %x\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 25) {
            printf("  fallocate_mode: %x\n", unpack("V",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 26) {
            printf("  fileattr: %x\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 27) {
            printf("  unencoded_file_len: %x\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 28) {
            printf("  unencoded_len: %x\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 29) {
            printf("  unencoded_offset: %x\n", unpack("Q",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 30) {
            printf("  compression: %x\n", unpack("V",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } elsif ($t == 31) {
            printf("  encryption: %x\n", unpack("V",substr($b,4,$l)));
            $b=substr($b,$l+4);
        } else {
            printf("  unknown(%u),%x\n",$t,$l);
            $b=substr($b,$l+4);
        }
    }
}
