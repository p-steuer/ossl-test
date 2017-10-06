#!/usr/bin/env perl

use strict;
use warnings;

my $file='conf.h';
my $cpuinfo=`cat /proc/cpuinfo`;
my ($mhz)=$cpuinfo=~m/cpu MHz dynamic : (\d+)/;
my $osslinfo=`openssl version -a`;
my ($seed)=$osslinfo=~m/Seeding source: (.*)$/;
my $out=<<__;
#ifndef CONF_H
# define CONF_H

# define MHZ		$mhz
# define SEED		"$seed"

#endif
__

open(my $fd,'>',$file)||die("$file: $!");
print({$fd}$out);
close($fd);
