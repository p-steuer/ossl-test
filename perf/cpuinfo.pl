#!/usr/bin/env perl

use strict;
use warnings;

my $file='cpuinfo.h';
my $cpuinfo=`cat /proc/cpuinfo`;
my ($mhz)=$cpuinfo=~m/cpu MHz dynamic : (\d+)/;
my $out=<<__;
#ifndef CPUINFO_H
# define CPUINFO_H

# define MHZ	$mhz

#endif
__

open(my $fd,'>',$file)||die("$file: $!");
print({$fd}$out);
close($fd);
