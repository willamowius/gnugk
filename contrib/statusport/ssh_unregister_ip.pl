#!/usr/bin/perl
use strict;
use warnings;

use Net::SSH::Expect;

if (@ARGV < 1) {
	print "usage: ssh_unregister_ip.pl <ip> <gatekeeper_host>\n";
	exit(1);
}

my $ip = $ARGV[0];
my $gk_host = $ARGV[1] || "localhost";
my $gk_port = 7000;

my $ssh = Net::SSH::Expect->new(host => $gk_host, port => $gk_port,
            user => 'admin', password=> 'secret', raw_pty => 1);

my $login_output = $ssh->login();
if ($login_output !~ /Gatekeeper/) {
	die "GnuGk login has failed. Output was $login_output";
} else {
	print "GnuGk login OK\n";
}

$ssh->exec("unregisterip $ip");
print "Command sent\n";

# Net::SSH:Expect will croak() when the remote side closes the connection
eval {
	$ssh->exec("quit");
	$ssh->close();
}

