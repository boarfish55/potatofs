#!/usr/bin/perl
#
# Copyright (C) 2020-2022 Pascal Lalonde <plalonde@overnet.ca>
#
# This file is part of PotatoFS, a FUSE filesystem implementation.
#
# PotatoFS is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;
use Getopt::Std;
use JSON;
use POSIX;

use vars qw/ %opts /;
our $opts;

my $appname = "mgr.pl";
my $passphrase = "some_passphrase";
my $skicka = "/usr/local/go/bin/skicka -quiet";
my $backend_prefix = "potatofs";

use constant {
	E_OK             => 0,
	# On E_ERR, the JSON output on stderr should contain a "status"
	# field with one of the predefined errors.
	E_ERR            => 1,
	# When exiting with BAD_INVOCATION, there should be no JSON
	# output.
	E_BAD_INVOCATION => 2,
};

sub usage
{
	print("Usage: $appname [-h] <command>\n");
	print("\n");
	print("       $appname df\n");
	print("\n");
	print("           Output is <used bytes> / <total available bytes>\n");
	print("\n");
	print("       $appname get <slab name> <local path> <inode> <base>\n");
	print("\n");
	print("           <slab name> is the file name, local path is the \n" .
	      "           absolute path of the slab file.\n");
	print("\n");
	print("       $appname put <local path> <slab name>\n");
}

sub main
{
	getopts("h", \%opts) or do {
		usage();
		exit(E_BAD_INVOCATION);
	};

	if (defined($opts{'h'})) {
		usage();
		exit(E_BAD_INVOCATION);
	}

	my $JSON = JSON->new->utf8;
	$JSON->convert_blessed(1);

	my $op = shift @ARGV;

	if ($op eq 'df') {
		open(DF, "$skicka df |") or do {
			print(STDERR "failed to run $skicka df: $!\n");
			exit(E_ERR);
		};
		my $capacity = 0;
		my $free = 0;
		my @units = (qw(B KiB MiB GiB TiB PiB));
		while (my $line = <DF>) {
			if ($line =~ /^Capacity\s+(\d+\.\d+)\s+(.iB)$/) {
				$capacity = scalar($1);
				for my $u (@units) {
					last if ($2 eq $u);
					$capacity *= 1024.0;
				}
			} elsif ($line =~ /^Free space\s+(\d+\.\d+)\s+(.iB) .*$/) {
				$free = $1;
				for my $u (@units) {
					last if ($2 eq $u);
					$free *= 1024;
				}
			}
		}
		close(DF);

		if ($? != 0) {
			print("{ \"status\": \"ERR\" }\n");
			exit(E_ERR);
		}

		my $j = {
			'status' => 'OK',
			'used_bytes' => ceil($capacity - $free),
			'total_bytes' => ceil($capacity)
		};
		print($JSON->encode($j) . "\n");
	} elsif ($op eq "get") {
		my $slab = shift @ARGV;
		my $local_path = shift @ARGV;

		$ENV{"SKICKA_PASSPHRASE"} = $passphrase;

		my $err;
		my $cmd = "$skicka download " .
			"$backend_prefix/$slab.aes256 $local_path";
		open(GET, "$cmd 2>&1 |") or do {
			my $j = {
				'status' => 'ERR',
				'msg' => "failed to run $cmd: $!",
			};
			print($JSON->encode($j) . "\n");
			exit(E_ERR);
		};
		$err = <GET>;
		close(GET);

		if ($? != 0) {
			$err =~ s/^\s+(.*)\s+$/\1/;
			my $j = { 'status' => 'ERR', 'msg' => $err };
			if ($err =~ / not found /) {
				$j->{'status'} = 'ERR_NOENT';
			}
			print($JSON->encode($j) . "\n");
			exit(E_ERR);
		}

		my @st = stat($local_path);
		my $j = {
			'status' => 'OK',
			'in_bytes' => $st[7],
		};
		print($JSON->encode($j) . "\n");
	} elsif ($op eq "put") {
		my $local_path = shift @ARGV;
		my $slab = shift @ARGV;

		$ENV{"SKICKA_PASSPHRASE"} = $passphrase;

		my @st = stat($local_path);

		my $err;
		my $cmd = "$skicka upload -encrypt $local_path " .
			"$backend_prefix/$slab";
		open(PUT, "$cmd 2>&1 |") or do {
			my $j = {
				'status' => 'ERR',
				'msg' => "failed to run $cmd: $!",
			};
			print($JSON->encode($j) . "\n");
			exit(E_ERR);
		};
		$err = <PUT>;
		close(PUT);
		if ($? != 0) {
			$err =~ s/^\s+(.*)\s+$/\1/;
			my $j = { 'status' => 'ERR', 'msg' => $err };
			print($JSON->encode($j) . "\n");
			exit(E_ERR);
		}
		my $j = {
			'status' => 'OK',
			'out_bytes' => $st[7],
		};
		print($JSON->encode($j) . "\n");
	} else {
		usage();
		exit(E_BAD_INVOCATION);
	}
}

main();

exit(E_OK);
