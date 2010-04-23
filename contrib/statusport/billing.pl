#!/usr/bin/perl
# sample program that demonstrates how one could attach a
# billing interface to the OpenH323 Gatekeeper via the status port
# use the CDR records for real billing applications !
use strict;

use IO::Socket;

print "THIS IS NOT A REAL BILLING APPLICATION, JUST A DEMO OF HOW TO CONNECT TO THE GATEKEEPER.\nWRITE YOUR OWN CLIENT AND USE [StatusAcct] MESSAGES!\n\n";

if (@ARGV != 1) {
	print "usage: billing.pl <gatekeeper_host>\n";
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
	my $msgtype = (split(/\|/, $msg))[0];	# what message type is it ?
	# TODO: use [StatusAcct] instead of ACF and CDR messages!
	if ($msgtype eq "ACF") {
		my ($calling, $called, $callid) = (split(/\|/, $msg))[2,4,7];
		$caller{$callid} = $calling;
		$calls{$callid} = time();
		print "User $calling started call $callid with $called\n";
	}
	if ($msgtype eq "CDR") {
		my ($callid, $calltime) = (split(/\|/, $msg))[2,3];
		$callid =~ s/\s+/-/g;
		my $initiator = $caller{$callid};
		print "Call $callid ended after $calltime seconds\n";
		print "Charging $initiator for $calltime seconds\n";
	}
}

