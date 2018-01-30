#!/usr/bin/env perl
# Patrick Steuer <patrick.steuer@de.ibm.com>

use strict;
use warnings;

my @testvectors=
(
"ccmVNT128.rsp",
"ccmVNT192.rsp",
"ccmVNT256.rsp",
);

my ($in,$fdin);
my ($out,$fdout)=("testvec-ccmVNT.c");

my ($alen,$alenre)=(0,'^Alen = (\d+)');
my ($plen,$plenre)=(0,'^Plen = (\d+)');
my ($tlen,$tlenre)=(0,'^Tlen = (\d+)');

my ($nlen,$nlenre)=(0,'^\[Nlen = (\d+)\]');

my ($key,$keyre,$keylen)=("",'^Key = ([0-9a-f]*)',0);

my ($count,$countre)=("",'^Count = (\d+)');
my ($nonce,$noncere)=("",'^Nonce = ([0-9a-f]*)');
my ($adata,$adatare)=("",'^Adata = ([0-9a-f]*)');
my ($payload,$payloadre)=("",'^Payload = ([0-9a-f]*)');
my ($ct,$ctre)=("",'^CT = ([0-9a-f]*)');

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
#include "testvec.h"

const struct aes_ccm_tv AES_CCM_TV_VNT[] = {
__
print({$fdout}$buf);

for (@testvectors) {

$in=$_;

open($fdin,'<',$in) || die("Couldn't open $in ($!).");

while ($line=<$fdin>) {
	chomp($line);

	$alen=$1 if ($line=~/$alenre/);
	$plen=$1 if ($line=~/$plenre/);
	$tlen=$1 if ($line=~/$tlenre/);

	$nlen=$1 if ($line=~/$nlenre/);
	if ($line=~/$keyre/) {
		$key=$1;
		$keylen=length($key)/2;
		$key=tocarray($key);
	}

	if ($line=~/$countre/) {	# new test-vector
		$toggle=1;
		$count=$1;
		$nonce="";
		$adata="";
		$ct="";
		$payload="";
	}
	$dir="ENC";
	$nonce=$1 if ($line=~/$noncere/);
	$adata=$1 if ($line=~/$adatare/);
	$ct=$1 if ($line=~/$ctre/);
	$payload=$1 if ($line=~/$payloadre/);

	if (($line=~/^\s*$/)&&($toggle)) {
		$toggle=0;
		$nonce=tocarray($nonce);
		$adata=tocarray($adata);
		$ct=tocarray($ct);
		$payload=tocarray($payload);

		($buf=qq{
		{
		.i = $i,
		.dir = $dir,
		.keylen = $keylen,

		.alen = $alen,
		.plen = $plen,
		.nlen = $nlen,
		.tlen = $tlen,

		.key = $key,

		.count = $count,
		.nonce = $nonce,
		.adata = $adata,
		.ct = $ct,
		.rv = SUCC,
		.payload = $payload,
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

const size_t AES_CCM_TV_VNT_LEN = sizeof(AES_CCM_TV_VNT) / sizeof(AES_CCM_TV_VNT[0]);
__
print({$fdout}$buf);
close($fdout);
