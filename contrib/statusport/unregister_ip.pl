#!/usr/bin/perl -w
use strict;

use IO::Socket;

if (@ARGV < 1) {
	print "usage: unregister_ip.pl <ip> <gatekeeper_host>\n";
	exit(1);
}

my $ip = $ARGV[0];
my $gk_host = $ARGV[1] || "localhost";
my $gk_port = 7000;

my $sock = IO::Socket::INET->new(	PeerAddr => $gk_host,
									PeerPort => $gk_port,
									Proto    => 'tcp');
if (!defined $sock) {
	die "Can't connect to gatekeeper at $gk_host:$gk_port";
}

print $sock "unregisterip $ip\n";
$sock->getline();
print $sock "quit\n";
$sock->getline();

close($sock);

