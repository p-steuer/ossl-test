#!/usr/bin/env perl
#Author: Patrick Steuer <patrick.steuer@de.ibm.com>

package config;

use strict;
use warnings;
use Exporter qw(import);

our @EXPORT_OK		= qw(get_abi get_env_var get_env_list get_config_list get_perlasm);

my $abi			= 64;
my $env_var		= 'OPENSSL_s390xcap';
my @env_list		= (
['sha1','KIMD-SHA-1[-]','.~0x4000000000000000'],
['sha1','KIMD-SHA-1[+]',''],

['sha256','KIMD-SHA-256[-]','.~0x2000000000000000'],
['sha256','KIMD-SHA-256[+]',''],

['sha512','KIMD-SHA-512[-]','.~0x1000000000000000'],
['sha512','KIMD-SHA-512[+]',''],

['aes-128-cbc','KMC-AES-128[-]','.::::~0x200000000000'],
['aes-128-cbc','KMC-AES-128[+]',''],

['aes-192-cbc','KMC-AES-192[-]','.::::~0x100000000000'],
['aes-192-cbc','KMC-AES-192[+]',''],

['aes-256-cbc','KMC-AES-256[-]','.::::~0x80000000000'],
['aes-256-cbc','KMC-AES-256[+]',''],

['aes-128-ctr','KMA-GCM-AES-128[-],KM-AES-128[-]','.::~0x200000000000::::::::::::::~0x200000000000'],
['aes-128-ctr','KMA-GCM-AES-128[+],KM-AES-128[-]','.::~0x200000000000'],
['aes-128-ctr','KMA-GCM-AES-128[-],KM-AES-128[+]','.::::::::::::::::~0x200000000000'],
['aes-128-ctr','KMA-GCM-AES-128[+],KM-AES-128[+]',''],

['aes-192-ctr','KMA-GCM-AES-192[-],KM-AES-192[-]','.::~0x100000000000::::::::::::::~0x100000000000'],
['aes-192-ctr','KMA-GCM-AES-192[+],KM-AES-192[-]','.::~0x100000000000'],
['aes-192-ctr','KMA-GCM-AES-192[-],KM-AES-192[+]','.::::::::::::::::~0x100000000000'],
['aes-192-ctr','KMA-GCM-AES-192[+],KM-AES-192[+]',''],

['aes-256-ctr','KMA-GCM-AES-256[-],KM-AES-256[-]','.::~0x80000000000::::::::::::::~0x80000000000'],
['aes-256-ctr','KMA-GCM-AES-256[+],KM-AES-256[-]','.::~0x80000000000'],
['aes-256-ctr','KMA-GCM-AES-256[-],KM-AES-256[+]','.::::::::::::::::~0x80000000000'],
['aes-256-ctr','KMA-GCM-AES-256[+],KM-AES-256[+]',''],

['aes-128-gcm','KMA-GCM-AES-128[-],KIMD-GHASH[-],KM-AES-128[-]','.:~0x4000000000000000:~0x200000000000::::::::::::::~0x200000000000'],
['aes-128-gcm','KMA-GCM-AES-128[-],KIMD-GHASH[+],KM-AES-128[-]','.::~0x200000000000::::::::::::::~0x200000000000'],
['aes-128-gcm','KMA-GCM-AES-128[-],KIMD-GHASH[-],KM-AES-128[+]','.:~0x4000000000000000:::::::::::::::~0x200000000000'],
['aes-128-gcm','KMA-GCM-AES-128[-],KIMD-GHASH[+],KM-AES-128[+]','.::::::::::::::::~0x200000000000'],
['aes-128-gcm','KMA-GCM-AES-128[+],KIMD-GHASH[-],KM-AES-128[-]','.:~0x4000000000000000:~0x200000000000'],
['aes-128-gcm','KMA-GCM-AES-128[+],KIMD-GHASH[+],KM-AES-128[-]','.::~0x200000000000'],
['aes-128-gcm','KMA-GCM-AES-128[+],KIMD-GHASH[-],KM-AES-128[+]','.:~0x4000000000000000'],
['aes-128-gcm','KMA-GCM-AES-128[+],KIMD-GHASH[+],KM-AES-128[+]',''],

['aes-192-gcm','KMA-GCM-AES-192[-],KIMD-GHASH[-],KM-AES-192[-]','.:~0x4000000000000000:~0x100000000000::::::::::::::~0x100000000000'],
['aes-192-gcm','KMA-GCM-AES-192[-],KIMD-GHASH[+],KM-AES-192[-]','.::~0x100000000000::::::::::::::~0x100000000000'],
['aes-192-gcm','KMA-GCM-AES-192[-],KIMD-GHASH[-],KM-AES-192[+]','.:~0x4000000000000000:::::::::::::::~0x100000000000'],
['aes-192-gcm','KMA-GCM-AES-192[-],KIMD-GHASH[+],KM-AES-192[+]','.::::::::::::::::~0x100000000000'],
['aes-192-gcm','KMA-GCM-AES-192[+],KIMD-GHASH[-],KM-AES-192[-]','.:~0x4000000000000000:~0x100000000000'],
['aes-192-gcm','KMA-GCM-AES-192[+],KIMD-GHASH[+],KM-AES-192[-]','.::~0x100000000000'],
['aes-192-gcm','KMA-GCM-AES-192[+],KIMD-GHASH[-],KM-AES-192[+]','.:~0x4000000000000000'],
['aes-192-gcm','KMA-GCM-AES-192[+],KIMD-GHASH[+],KM-AES-192[+]',''],

['aes-256-gcm','KMA-GCM-AES-256[-],KIMD-GHASH[-],KM-AES-256[-]','.:~0x4000000000000000:~0x80000000000::::::::::::::~0x80000000000'],
['aes-256-gcm','KMA-GCM-AES-256[-],KIMD-GHASH[+],KM-AES-256[-]','.::~0x80000000000::::::::::::::~0x80000000000'],
['aes-256-gcm','KMA-GCM-AES-256[-],KIMD-GHASH[-],KM-AES-256[+]','.:~0x4000000000000000:::::::::::::::~0x80000000000'],
['aes-256-gcm','KMA-GCM-AES-256[-],KIMD-GHASH[+],KM-AES-256[+]','.::::::::::::::::~0x80000000000'],
['aes-256-gcm','KMA-GCM-AES-256[+],KIMD-GHASH[-],KM-AES-256[-]','.:~0x4000000000000000:~0x80000000000'],
['aes-256-gcm','KMA-GCM-AES-256[+],KIMD-GHASH[+],KM-AES-256[-]','.::~0x80000000000'],
['aes-256-gcm','KMA-GCM-AES-256[+],KIMD-GHASH[-],KM-AES-256[+]','.:~0x4000000000000000'],
['aes-256-gcm','KMA-GCM-AES-256[+],KIMD-GHASH[+],KM-AES-256[+]',''],

['aes-128-xts','KM-XTS-AES-128[-],KM-AES-128[-]','.::~0x200000002000'],
['aes-128-xts','KM-XTS-AES-128[-],KM-AES-128[+]','.::~0x2000'],
['aes-128-xts','KM-XTS-AES-128[+],KM-AES-128[+]',''],

['aes-256-xts','KM-XTS-AES-256[-],KM-AES-256[-]','.::~0x80000000800'],
['aes-256-xts','KM-XTS-AES-256[-],KM-AES-256[+]','.::~0x800'],
['aes-256-xts','KM-XTS-AES-256[+],KM-AES-256[+]',''],

['aes-128-ccm','KMA-GCM-AES-128[-],KMAC-AES-128[-],KM-AES-128[-]','.::~0x200000000000::::~0x200000000000::::::::::~0x200000000000'],
['aes-128-ccm','KMA-GCM-AES-128[-],KMAC-AES-128[+],KM-AES-128[-]','.::~0x200000000000::::::::::::::~0x200000000000'],
['aes-128-ccm','KMA-GCM-AES-128[-],KMAC-AES-128[-],KM-AES-128[+]','.::::::~0x20000000000::::::::::~0x2000000000000'],
['aes-128-ccm','KMA-GCM-AES-128[-],KMAC-AES-128[+],KM-AES-128[+]','.::::::::::::::::~0x200000000000'],
['aes-128-ccm','KMA-GCM-AES-128[+],KMAC-AES-128[-],KM-AES-128[-]','.::~0x200000000000::::~0x200000000000'],
['aes-128-ccm','KMA-GCM-AES-128[+],KMAC-AES-128[+],KM-AES-128[-]','.::~0x200000000000'],
['aes-128-ccm','KMA-GCM-AES-128[+],KMAC-AES-128[-],KM-AES-128[+]','.::::::~0x200000000000'],
['aes-128-ccm','KMA-GCM-AES-128[+],KMAC-AES-128[+],KM-AES-128[+]',''],

['aes-192-ccm','KMA-GCM-AES-192[-],KMAC-AES-192[-],KM-AES-192[-]','.::~0x100000000000::::~0x100000000000::::::::::~0x100000000000'],
['aes-192-ccm','KMA-GCM-AES-192[-],KMAC-AES-192[+],KM-AES-192[-]','.::~0x100000000000::::::::::::::~0x100000000000'],
['aes-192-ccm','KMA-GCM-AES-192[-],KMAC-AES-192[-],KM-AES-192[+]','.::::::~0x10000000000::::::::::~0x1000000000000'],
['aes-192-ccm','KMA-GCM-AES-192[-],KMAC-AES-192[+],KM-AES-192[+]','.::::::::::::::::~0x100000000000'],
['aes-192-ccm','KMA-GCM-AES-192[+],KMAC-AES-192[-],KM-AES-192[-]','.::~0x100000000000::::~0x100000000000'],
['aes-192-ccm','KMA-GCM-AES-192[+],KMAC-AES-192[+],KM-AES-192[-]','.::~0x100000000000'],
['aes-192-ccm','KMA-GCM-AES-192[+],KMAC-AES-192[-],KM-AES-192[+]','.::::::~0x100000000000'],
['aes-192-ccm','KMA-GCM-AES-192[+],KMAC-AES-192[+],KM-AES-192[+]',''],

['aes-256-ccm','KMA-GCM-AES-256[-],KMAC-AES-256[-],KM-AES-256[-]','.::~0x80000000000::::~0x80000000000::::::::::~0x80000000000'],
['aes-256-ccm','KMA-GCM-AES-256[-],KMAC-AES-256[+],KM-AES-256[-]','.::~0x80000000000::::::::::::::~0x80000000000'],
['aes-256-ccm','KMA-GCM-AES-256[-],KMAC-AES-256[-],KM-AES-256[+]','.::::::~0x8000000000::::::::::~0x800000000000'],
['aes-256-ccm','KMA-GCM-AES-256[-],KMAC-AES-256[+],KM-AES-256[+]','.::::::::::::::::~0x80000000000'],
['aes-256-ccm','KMA-GCM-AES-256[+],KMAC-AES-256[-],KM-AES-256[-]','.::~0x80000000000::::~0x80000000000'],
['aes-256-ccm','KMA-GCM-AES-256[+],KMAC-AES-256[+],KM-AES-256[-]','.::~0x80000000000'],
['aes-256-ccm','KMA-GCM-AES-256[+],KMAC-AES-256[-],KM-AES-256[+]','.::::::~0x80000000000'],
['aes-256-ccm','KMA-GCM-AES-256[+],KMAC-AES-256[+],KM-AES-256[+]',''],

['aes-128-ofb','KMO-AES-128[-],KM-AES-128[-]','.::~0x200000000000::::::::~0x200000000000'],
['aes-128-ofb','KMO-AES-128[+],KM-AES-128[-]','.::~0x200000000000'],
['aes-128-ofb','KMO-AES-128[-],KM-AES-128[+]','.::::::::::~0x200000000000'],
['aes-128-ofb','KMO-AES-128[+],KM-AES-128[+]',''],

['aes-192-ofb','KMO-AES-192[-],KM-AES-192[-]','.::~0x100000000000::::::::~0x100000000000'],
['aes-192-ofb','KMO-AES-192[+],KM-AES-192[-]','.::~0x100000000000'],
['aes-192-ofb','KMO-AES-192[-],KM-AES-192[+]','.::::::::::~0x100000000000'],
['aes-192-ofb','KMO-AES-192[+],KM-AES-192[+]',''],

['aes-256-ofb','KMO-AES-256[-],KM-AES-256[-]','.::~0x80000000000::::::::~0x80000000000'],
['aes-256-ofb','KMO-AES-256[+],KM-AES-256[-]','.::~0x80000000000'],
['aes-256-ofb','KMO-AES-256[-],KM-AES-256[+]','.::::::::::~0x80000000000'],
['aes-256-ofb','KMO-AES-256[+],KM-AES-256[+]',''],

['aes-128-cfb','KMF-AES-128[-],KM-AES-128[-]','.::~0x200000000000::::::::::~0x200000000000'],
['aes-128-cfb','KMF-AES-128[+],KM-AES-128[-]','.::~0x200000000000'],
['aes-128-cfb','KMF-AES-128[-],KM-AES-128[+]','.::::::::::::~0x200000000000'],
['aes-128-cfb','KMF-AES-128[+],KM-AES-128[+]',''],

['aes-192-cfb','KMF-AES-192[-],KM-AES-192[-]','.::~0x100000000000::::::::::~0x100000000000'],
['aes-192-cfb','KMF-AES-192[+],KM-AES-192[-]','.::~0x100000000000'],
['aes-192-cfb','KMF-AES-192[-],KM-AES-192[+]','.::::::::::::~0x100000000000'],
['aes-192-cfb','KMF-AES-192[+],KM-AES-192[+]',''],

['aes-256-cfb','KMF-AES-256[-],KM-AES-256[-]','.::~0x80000000000::::::::::~0x80000000000'],
['aes-256-cfb','KMF-AES-256[+],KM-AES-256[-]','.::~0x80000000000'],
['aes-256-cfb','KMF-AES-256[-],KM-AES-256[+]','.::::::::::::~0x80000000000'],
['aes-256-cfb','KMF-AES-256[+],KM-AES-256[+]',''],

['aes-128-cfb8','KMF-AES-128[-],KM-AES-128[-]','.::~0x200000000000::::::::::~0x200000000000'],
['aes-128-cfb8','KMF-AES-128[+],KM-AES-128[-]','.::~0x200000000000'],
['aes-128-cfb8','KMF-AES-128[-],KM-AES-128[+]','.::::::::::::~0x200000000000'],
['aes-128-cfb8','KMF-AES-128[+],KM-AES-128[+]',''],

['aes-192-cfb8','KMF-AES-192[-],KM-AES-192[-]','.::~0x100000000000::::::::::~0x100000000000'],
['aes-192-cfb8','KMF-AES-192[+],KM-AES-192[-]','.::~0x100000000000'],
['aes-192-cfb8','KMF-AES-192[-],KM-AES-192[+]','.::::::::::::~0x100000000000'],
['aes-192-cfb8','KMF-AES-192[+],KM-AES-192[+]',''],

['aes-256-cfb8','KMF-AES-256[-],KM-AES-256[-]','.::~0x80000000000::::::::::~0x80000000000'],
['aes-256-cfb8','KMF-AES-256[+],KM-AES-256[-]','.::~0x80000000000'],
['aes-256-cfb8','KMF-AES-256[-],KM-AES-256[+]','.::::::::::::~0x80000000000'],
['aes-256-cfb8','KMF-AES-256[+],KM-AES-256[+]',''],

['chacha20','VX[-]','::~0x4000000000000000'],
['chacha20','VX[+]',''],

['chacha20-poly1305','VX[-]','::~0x4000000000000000'],
['chacha20-poly1305','VX[+]','::~0x'],
);
my @config_list64		= (
'linux64-s390x enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers enable-external-tests enable-tls1_3 enable-unit-test enable-md2 enable-rc5 enable-heartbeats -Wa,--noexecstack --strict-warnings -Wno-error',
'linux64-s390x enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers enable-external-tests enable-tls1_3 enable-unit-test enable-md2 enable-rc5 enable-heartbeats no-shared -Wa,--noexecstack --strict-warnings -Wno-error',
);
my @config_list32		= (	# no-afalgeng: afalgeng crashes on 32bit, enable-tls1_3: hangs on 32bit
'linux32-s390x enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers enable-external-tests enable-unit-test enable-md2 enable-rc5 enable-heartbeats no-afalgeng -Wa,--noexecstack --strict-warnings -Wno-error',
'linux32-s390x enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers enable-external-tests enable-unit-test enable-md2 enable-rc5 enable-heartbeats no-afalgeng no-shared -Wa,--noexecstack --strict-warnings -Wno-error',
);
my @perlasm			= (
'crypto/aes/aes-s390x.S',
'crypto/modes/ghash-s390x.S',
'crypto/chacha/chacha-s390x.S',
'crypto/poly1305/poly1305-s390x.S',
'crypto/sha/sha1-s390x.S',
'crypto/sha/sha256-s390x.S',
'crypto/sha/sha512-s390x.S',
'crypto/rc4/rc4-s390x.s',
'crypto/bn/s390x-gf2m.s',
'crypto/bn/s390x-mont.s',
);

sub get_abi {
	return $abi;
}

sub get_env_var {
	return $env_var;
}

sub get_env_list {
	return @env_list;
}

sub get_config_list {
	return $abi==64?@config_list64:@config_list32;
}

sub get_perlasm {
	return @perlasm;
}

1;
