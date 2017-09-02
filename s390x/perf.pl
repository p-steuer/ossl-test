#!/usr/bin/env perl
#Author: Patrick Steuer <patrick.steuer@de.ibm.com>

use strict;
use warnings;
use config qw (get_env_var get_env_list);

if (($#ARGV!=0)||($ARGV[0]eq'help')) {
	print("Usage: ./perf.pl [PATH/openssl]\n");
	exit;
}

my $ossl=$ARGV[0];
my $var=get_env_var();
my @list=get_env_list();
my @types=(16,64,256,1024,8192,16384);
my ($primitive,$codepath,$env,$out);

print("The 'numbers' are in 1000s of bytes per second processed.\n");
print("type        ");
printf("%7d bytes",$_) for (@types);
print("  codepath\n");

for (@list) {
	($primitive,$codepath,$env)=@{$_};
	$out=`env $var=$env $ossl speed -evp $primitive 2> /dev/null`;
	die() if ($?);
	($out)=grep({/^$primitive/}split("\n",$out));
	print("$out  $codepath\n");
}
