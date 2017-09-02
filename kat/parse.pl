#!/usr/bin/env perl
# Patrick Steuer <patrick.steuer@de.ibm.com>

use strict;
use warnings;

my @testvectors=
(
"gcmDecrypt128.rsp",
"gcmDecrypt192.rsp",
"gcmDecrypt256.rsp",
"gcmEncryptExtIV128.rsp",
"gcmEncryptExtIV192.rsp",
"gcmEncryptExtIV256.rsp",
);
my $source="http://csrc.nist.gov/groups/STM/cavp/block-cipher-modes.html"
    ."#test-vectors";

my ($in,$fdin);
my ($out,$fdout)=("testvec.c");

my ($keylen,$keylenre)=(0,'^\[Keylen = (128|192|256)\]');
my ($ivlen,$ivlenre)=(0,'^\[IVlen = (\d+)\]');
my ($ptlen,$ptlenre)=(0,'^\[PTlen = (\d+)\]');
my ($aadlen,$aadlenre)=(0,'^\[AADlen = (\d+)\]');
my ($taglen,$taglenre)=(0,'^\[Taglen = (\d+)\]');

my ($count,$countre)=("",'^Count = (\d+)');
my ($key,$keyre)=("",'^Key = ([0-9a-f]*)');
my ($iv,$ivre)=("",'^IV = ([0-9a-f]*)');
my ($ct,$ctre)=("",'^CT = ([0-9a-f]*)');
my ($aad,$aadre)=("",'^AAD = ([0-9a-f]*)');
my ($tag,$tagre)=("",'^Tag = ([0-9a-f]*)');
my ($pt,$ptre)=("",'^PT = ([0-9a-f]*)');
my ($fail,$failre)=(0,'^FAIL');

my ($enc,$encre)=("ENC","Encrypt");
my ($dec,$decre)=("DEC","Decrypt");

my $toggle=0;
my ($buf,$line,$dir,$i);

sub tocarray {
	my $ret="";
	my $i;
	my $str=shift;

	return "NULL" if ($str eq "");

	$str="0".$str if (length($str)%2!=0);
	for $i (0..(length($str)/2-1)) {
		$ret.="0x${\substr($str,2*$i,2)},";
		if (($i+1)%13==0) {
			$ret.="\n";
		} else {
			$ret.=" ";
		}
	}
	$ret=~s/\s$//;
	return "(unsigned char []){\n".$ret."\n}";
}

open($fdout,'>',$out) || die("Couldn't open $out ($!).");

$i=0;

$buf=<<__;
/*
 * parse-nist.pl auto-generated
 *
 * test-vectors:
__
print({$fdout}$buf);
for (@testvectors) {
	print({$fdout}" *   $_\n");
}
$buf=<<__;
 * source:
 *   $source
 */

#include "testvec.h"

const struct aead_tv AES_GCM_TV[] = {
__
print({$fdout}$buf);

for (@testvectors) {

$in=$_;

if ($in=~/Encrypt/) {
	$dir=$enc;
} elsif ($in=~/Decrypt/) {
	$dir=$dec;
} else {
	die("Neither $enc nor $dec found in $out.");
}

open($fdin,'<',$in) || die("Couldn't open $in ($!).");

while ($line=<$fdin>) {
	chomp($line);

	$keylen=$1 if ($line=~/$keylenre/);
	$ivlen=$1 if ($line=~/$ivlenre/);
	$ptlen=$1 if ($line=~/$ptlenre/);
	$aadlen=$1 if ($line=~/$aadlenre/);
	$taglen=$1 if ($line=~/$taglenre/);

#	next if ($ivlen!=96);	# parse 96-bit IV testvectors only

	if ($line=~/$countre/) {	# new test-vector
		$toggle=1;
		$count=$1;
		$key="";
		$iv="";
		$ct="";
		$aad="";
		$tag="";
		$pt="";
		$fail="SUCC";
	}
	$key=$1 if ($line=~/$keyre/);
	$iv=$1 if ($line=~/$ivre/);
	$ct=$1 if ($line=~/$ctre/);
	$aad=$1 if ($line=~/$aadre/);
	$tag=$1 if ($line=~/$tagre/);
	$pt=$1 if ($line=~/$ptre/);
	$fail="FAIL" if ($line=~/$failre/);

	if (($line=~/^\s+/)&&($toggle)) {
		$toggle=0;
		$key=tocarray($key);
		$iv=tocarray($iv);
		$ct=tocarray($ct);
		$aad=tocarray($aad);
		$tag=tocarray($tag);
		$pt=tocarray($pt);

		($buf=qq{
		{
		.i = $i,
		.dir = $dir,
		.count = $count,
		.keylen = $keylen / 8,
		.ivlen = $ivlen / 8,
		.len = $ptlen / 8,
		.aadlen = $aadlen / 8,
		.taglen = $taglen / 8,
		.key = $key,
		.iv = $iv,
		.pt = $pt,
		.aad = $aad,
		.tag = $tag,
		.ct = $ct,
		.rv = $fail,
		},
		})=~s/^\s*//mg;
		print({$fdout}$buf);

		$i=$i+1;
	}
}
close($fdin);
}
$buf=<<__;
};

const size_t AES_GCM_TV_LEN = sizeof(AES_GCM_TV) / sizeof(AES_GCM_TV[0]);
__
print({$fdout}$buf);
close($fdout);
