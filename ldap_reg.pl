#!/usr/bin/perl -w
# sample program that demonstrates how one could keep an
# LDAP directory updated from the endpoint registrations
use strict;

use IO::Socket;
use Net::LDAP qw(:all);

if (@ARGV != 1) {
	print "usage: ldap_reg.pl <gatekeeper_host>\n";
	exit(1);
}

my $gk_host = $ARGV[0];
my $gk_port = 7000;
my %calls,
my %caller;

my $sock = IO::Socket::INET->new(	PeerAddr => $gk_host,
									PeerPort => $gk_port,
									Proto    => 'tcp');
if (!defined $sock) {
	die "Can't connect to gatekeeper at $gk_host:$gk_port";
}

while (!$sock->eof()) {
	my $msg = $sock->getline();
	$msg = (split(/;/, $msg))[0];	# remove junk at end of line
	my $msgtype = (split(/\|/, $msg))[0];
	if ($msgtype eq "RCF") {
		my ($ipaddr, $aliases, $epid) = (split(/\|/, $msg))[1,2,4];
		print "Endpoint $epid has logged in from $ipaddr als $aliases\n";
	}
	if ($msgtype eq "UCF") {
		my ($epid) = (split(/\|/, $msg))[2];
		print "Endpoint $epid has logged out\n";
	}
}

