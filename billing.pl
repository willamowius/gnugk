#!/usr/bin/perl
# sample program that demonstrates how one could attach a
# billing interface to the OpenH323 Gatekeeper via the status port
# use the CDR records for real billing applications !
use strict;

use IO::Socket;

print "THIS IS NO REAL BILLING APPLICATION, JUST A DEMO HOW TO CONNECT TO THE GATEKEEPER.\nWRITE YOUR OWN CLIENT TO USE THE CDR MESSAGES!\n";

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
	if ($msgtype eq "ACF") {
		my ($calling, $callref, $called) = (split(/\|/, $msg))[2,3,4];
		$caller{$callref} = $calling;
		$calls{$callref} = time();
		print "User $calling started call $callref with $called\n";
	}
	if ($msgtype eq "CDR") {
		my ($callref, $calltime) = (split(/\|/, $msg))[1,2];
		my $initiator = $caller{$callref};
		print "Call $callref ended after $calltime seconds\n";
		print "Charging $initiator for $calltime seconds\n";
	}
}

