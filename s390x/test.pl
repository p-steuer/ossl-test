#!/usr/bin/env perl
#Author: Patrick Steuer <patrick.steuer@de.ibm.com>

use strict;
use warnings;
use Test::More;
use config qw (get_env_var get_env_list get_config_list get_perlasm);

my @config_list=get_config_list();
my @env_list=get_env_list();
my @perlasm=get_perlasm();
my $var=get_env_var();;
my ($path)=split("\n",`pwd`);
my $osslpath=$ARGV[0];
my $testno=0;
my $date=`date --rfc-3339=seconds`;

sub make {
	my $fd=shift;

	my $out=`make 2>&1`;
	die() if ($?);

	print({$fd}"make: ");
	if (index($out,'warning')!=-1) {
                my @warnings=join("\n",grep({/warning/}split(/\n/,$out)));
                print({$fd}"Warnings...\n\n");
                print({$fd}@warnings);
                print({$fd}"\n\n");
		return 0;
	}
	print({$fd}"No warnings.\n\n");
	return 1;
};

sub make_test {
	my $fd=shift;
	my $env=shift;

	my $out=`env $var=$env make test 2>&1`;

	print({$fd}"env $var=$env make test: ");
	if (index($out,'Failed')!=-1) {
		print({$fd}"Some tests failed...\n");
		print({$fd}"$out\n\n");
		return 0;
	}
	print({$fd}"All tests passed.\n");
	return 1;
};

if (($#ARGV!=0)||($ARGV[0]eq'help')) {
	print("Usage: ./test.pl [PATH/openssl]\n");
	exit;
}

my $tmp=$date;
chomp($tmp);
$tmp=~s/\s/_/g;
$tmp=~s/:/-/g;
$tmp=~s/\+.*$//g;

$tmp=$path."/$tmp.log";
die() if (!open(my $fd,">",$tmp));

die() if (!chdir($osslpath));

print({$fd}"Start: $date\n");

for my $conf (@config_list) {
	my $options=$conf;
	$options=~tr{ }{\n};
	$testno++;

	print({$fd}"-- TEST $testno --\n\n");
	print({$fd}"Configure options...\n\n$options\n\n");

	subtest "\n$options" => sub {
		`rm -f $_` for (@perlasm);
		print(`make distclean &> /dev/null`);

		print(`/usr/bin/perl ./Configure $conf > /dev/null`);
		die() if ($?);

		ok(make($fd),"make");
		ok(make_test($fd,""),"make test");
		ok(make_test($fd,@{$_}[2]),"env $var=@{$_}[2] make test") for (@env_list);
	};
}

$date=`date --rfc-3339=seconds`;
print({$fd}"Stop: $date\n");

close($fd);

done_testing($#config_list+1);
