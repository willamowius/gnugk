#!/usr/bin/perl

###
# Wrapper for gnugk (openh323gk)
# Forks and executes gnguk in one fork branch and restarts gnugk proccess if it terminated.
# Other fork branch monitors gnugk status port and kills it if gnugk frozen or smth.
# Usage: ./gnugk_wrapper.pl [gnugk options]
# This script uses gnugk options to extract path to config file and home IP address.
# It extracts Home IP address and status port number from config file.
# -i or --interface option overrides home IP address in config file
# Default Home IP address is 127.0.0.1, and status port is 7000
# you should take a look to some configuration variables below.
# (c) Data Tech Labs
###

### CVS
# RCS filename:			$RCSfile$
# Author:				$Author$
# File version:			$Revision$
# Last changes (GMT):	$Date$
# Branch (or tag):		$Name$
###



# modules
use strict;
use Time::localtime;
use Net::Telnet;



### Configure options ###

# path to gnugk executeable
my $gnugk = "/usr/local/bin/gnugk";
#my $gnugk = "/usr/home/valdiic/dev/gnugk_utils/gnugk_status_port_simulator.pl";

# set to 1 if you want to see additonal debug messages
# set to 0 to disable any kind of output
my $debug = 1;

# set to 1 to log
my $logGnugkRestarts = 1;

# set to 1 to run this script as a daemon (in background)
# set to 0 to run this script in foreground
my $runInBackground = 1;

# set to 1 to check status port
my $checkStatusPort = 1;

#gnugk telnet (status) port checking interval in seconds
my $statusPortCheckInterval = 60;

# socket timeout in seconds
my $socketTimeout = 10;

# set to 1 to check maximum number of blank lines; set to 0 to disable checking
my $sockCheckMaxBlankLines = 1;

# maximum number of blank (contain non-usable chracters only) lines
#   that is allowed from gnugk status port during process of
#   getting long (ends with semicolon (;)) message from status port
my $sockMaxBlankLines = 100;

# script pid file directory
my $pidFileDir = "/usr/local/var/run";

# gnugk pid file directory
my $gnugkPidFileDir = "/usr/local/var/run";

# set to 1 to enable copying core file to core file directory
my $copyCore = 1;

# core file directory
my $coreFileDirectory = "/usr/local/var/crash";

# log file directory
my $logFileDir = "/usr/local/var/log";

# path to log file
my $logFile = "$logFileDir/gnugk_wrapper.log";


### DO NOT EDIT ANYTHING BELOW THIS LINE!!! ###


# print script usage
# input: none
# output: none
sub usage
{
	my $str = <<EEE;
Gnugk (openh323gk) wrapper.
Usage:
  execute gnugk wrapper with all neccessary gnugk options:
    ./gnugk_wrapper [gnugk_options]
  print this help:
    ./gnugk_wrapper -h
	./gnugk_wrapper --help
EEE
	print $str;
};



#gets paramaters from STDIN
#input: (array) cmd line arguments
#output: (hash) configuration values
sub getConfStdin
{
	my @input = @{$_[0]};
	my $i = @input; # num of items in ARGV
	my $j = 0;
	my %conf = (
		'path_to_gnugk_conf_file' => '',
		'home_ip_address' => '',
		'main_section_name' => '[Gatekeeper::Main]',
	);
	
	#set parameters
	for ($j = 0; $j < $i; $j++)
	{
		# get path to gnugk config file from gnugk options
		if (($input[$j] eq '-c' || $input[$j] eq '--config') && $input[$j+1] ne '')
		{
			$conf{'path_to_gnugk_conf_file'} = $input[$j+1];
		}
		# get path to gnugk config file from gnugk options
		elsif (($input[$j] eq '-i' || $input[$j] eq '--interface') && $input[$j+1] ne '')
		{
			$conf{'home_ip_address'} = $input[$j+1];
		}
		# get main config file section name
		elsif (($input[$j] eq '-s' || $input[$j] eq '--section') && $input[$j+1] ne '')
		{
			$conf{'main_section_name'} = $input[$j+1];
		}
		#print usage (help)
		elsif ($input[$j] eq '-h' || $input[$j] eq '--help')
		{	
			usage();
			exit(0);
		};
	};
	
	return %conf;
};



# get gnugk home ip address from gnugk config file
# gnugk has to be attached to some kind of IP address
# input: (string) path to gnugk config file, (string) home IP address from stdin
# output: (string) Home IP address, (int) status port number
sub getConfFromFile
{
	my $pathToConfFile = shift;
	my $homeIpAddressStdin = shift;
	my $mainSectionName = shift;
	my $defaultHomeIpAddress = "127.0.0.1";
	my $defaultStatusPort = "7000";
	my $homeIpAddress = $defaultHomeIpAddress;
	my $statusPort = $defaultStatusPort;
	
	print "---\n\n" if ($debug);
	print "Searching for gnugk home IP address and status port\n" if ($debug);
	print "  Path to config file: $pathToConfFile\n  Main section name: $mainSectionName\n" if ($debug);
	print "  Default home IP address and status port: $defaultHomeIpAddress:$defaultStatusPort\n" if ($debug);
	
	# return default values if no config file path given
	if ($pathToConfFile eq '')
	{	
		print "  No config file path received. Returning default values...\n" if ($debug);
		return ($homeIpAddress, $statusPort);
	};
	if ($mainSectionName eq '')
	{
		print "  No config file main section name received. Returning default values...\n" if ($debug);
		return ($homeIpAddress, $statusPort);
	};
	
	# open file
	eval
	{
		open (CF, "<$pathToConfFile") or die "Error: can not open gnugk config file $pathToConfFile\n  $!";
	};
	if ($@)
	{
		print $@ if ($debug);
		return ($homeIpAddress, $statusPort);
	};
	
	# read all from file in array
	my @file = <CF>;
	# close file
	close(CF);
	
	# search for IP address
	my $row = '';
	my $i = 0;
	my $numRows = @file;
	my $sectionGatekeeperMain = 0; # shows if config file section Gatekeeper::Main is found
	for ($i = 0; $i < $numRows; $i++)
	{
		$row = $file[$i];
		$row = (split(/#|;/, $row))[0]; #read row from file, cut out comments
		$row =~ s/ |\n|\t//g; # cut out whitespaces, tabs, newlines
		
		#search for IP address definition
		if (length($row) > 0)
		{
			# find Gatekeeper::Main section in config file
			if ($row =~ m/\Q$mainSectionName\E/)
			{
				print "  Found section [Gatekeeper::Main] in line $i\n" if ($debug);
				$sectionGatekeeperMain = 1;
			}
			# set section Gatekeeper::Main identificator to 0 if other section found
			elsif ($row =~ m/\[[A-Z_a-z]+[:]{0,2}[A-Z_a-z]+]/)
			{
				#print "  Found section $row in line $i\n" if ($debug);
				$sectionGatekeeperMain = 0;
			}
			# set home IP address
			elsif ($row =~ m/Home=/ && $sectionGatekeeperMain)
			{
				print "  Home IP address found in line $i\n" if ($debug);
				$homeIpAddress = (split("=", $row))[1];
			}
			# set status port
			elsif ($row =~ m/StatusPort=/ && $sectionGatekeeperMain)
			{
				print "  Status port number found in line $i\n" if ($debug);
				$statusPort = (split("=", $row))[1];
			};
		};
	};
	
	# replace detected home IP with the one from cmd line if nececssary
	if ($homeIpAddressStdin)
	{
		print "  Replacing home IP from config file ($homeIpAddress)\n" if ($debug);
		print "    with the one supplied from cmd line ($homeIpAddressStdin)\n" if ($debug);
		$homeIpAddress = $homeIpAddressStdin;
	};
	
	# check IP address against format
	if (!checkIpv4Address($homeIpAddress))
	{
		print "  Home IP address format invalid - replacing with default value\n" if ($debug);
		$homeIpAddress = $defaultHomeIpAddress;
	};
	
	# check port number aginst format
	$statusPort = int($statusPort);
	$statusPort = $defaultStatusPort if ($statusPort <= 0);
	
	print "  Gnugk home IP and port found: $homeIpAddress:$statusPort\n" if ($debug);
	return ($homeIpAddress, $statusPort);
};



# checks IP V4 address format
# input: (string) IP V4 address
# output: (int) 1 - valid; 0 - invalid
sub checkIpv4Address
{
	my $ip = shift;
	my $ret = 0;
	
	# check if there are four octets with numbers
	if ($ip =~ m/([0-9]{1,3}\.){3}[0-9]{1,3}/)
	{
		my @numbers = split('\.', $ip);
		my $numElements = @numbers;
		my $i = 0;
		for ($i = 0 ; $i < $numElements; $i++)
		{
			$numbers[$i] = int($numbers[$i]);
			
			# generally all numbers in all octets must be >0 and <255
			if ($numbers[$i] < 0 || $numbers[$i] >= 255)
			{
				$ret = 0;
				last;
			}
			# number in first octet must be >0
			elsif ($numbers[$i] <= 0 && $i == 0)
			{
				$ret = 0;
				last;
			}
			# everything ok
			else
			{
				$ret = 1;
			};
		};
	}
	else
	{
		$ret = 0;
	};
	
	return $ret;
};



# write pid to file
# input: (string) path to pid file, (int) pid
# output: (none)
sub writePidFile
{
	my $pidFile = shift;
	my $pid = shift;
	
	return 0 if (!$pidFile);
	
	# open file for appending by default
	my $openMode = ">>";
	# open for rewriting if initial open
	$openMode = ">" if (!$pid);

	# open file
	eval
	{
		open (GKPID, "$openMode$pidFile") or die "Error: can not open gnugk wrapper pid file $pidFile\n  $!";
	};
	if ($@)
	{
		print $@ if ($debug);
		return 0;
	};
	
	#  write pid
	if ($pid)
	{
		print GKPID "$pid\n";
	};
	close (GKPID);
	return 1;
};



# get gnugk pid from process list
# input: (string) path to gnugk pid file
# output: (int) gnugk pid (default: 0 if unsuccessful)
sub getGnugkPid
{
	my $gnugkPidFile = shift;
	my $gnugkPid = 0;
	
	return $gnugkPid if ($gnugkPidFile eq '');
	
	print "  Searching for gnugk pid in file: $gnugkPidFile\n" if ($debug);
	
	# read file
	eval
	{
		open (PIDFILE, "<$gnugkPidFile") or die "Error: can not open gnugk pid file $gnugkPidFile\n  $!";
	};
	if ($@)
	{
		print $@ if ($debug);
		return $gnugkPid;
	};
	my @file = <PIDFILE>;
	close (PIDFILE);
	
	# extract first appearing positive integer from file
	foreach (@file)
	{
		$_ = int ($_); # get integer value from line
		
		# set gnugk pid to $_ integer value and break loop
		if ($_ > 0)
		{
			$gnugkPid = $_;
			last;
		};
	};
	
	print "    Gnugk pid detected: $gnugkPid\n" if ($debug);
	return $gnugkPid;
};



# kill gnugk process
# input: (int) gnugk pid
# output: none
sub killGnugk
{
	my $pid = shift;
	return if ($pid <= 0);
		
	print "  Killing gnugk... " if ($debug);
	my $nKilledProc = kill ('KILL', $pid);
	print "  killed $nKilledProc process(es)\n" if ($debug);
};



# adds leading zeros
# input: (int) number, (int) necessary length
# output: (string) number with leading zeros
sub addLeadingZeros
{
	my ($number, $length) = @_;
	my $ret;

	return $number if (length($number) >= $length);
	my $zeros = "0" x $length;

	return substr($zeros.$number, -$length);
};



# check directory if it exists, is a directory and is writeable
# create new directory if neccessary or die
# die if file exists and is not a directory or writeable
# input: (string) directory path
# output: (int) 1 - is ok; 0 - failure
sub checkDir
{
	my $dirName = shift;
	return 0 if ($dirName eq '');
	
	# check if exists, create if not exist
	if (!(-e $dirName))
	{
		print "$dirName direcotory doesn't exist. Creating...\n";
		if (system ("mkdir -p '$dirName'") != 0)
		{
			print "Can not make directory $dirName\n  $!";
			return 0;
		};
	};
	# check if it is directory, writeable and executeable
	if (!(-w $dirName) || !(-d $dirName) || !(-x $dirName))
	{
		print "$dirName not writeable, executeable or is not directory at all";
		return 0;
	};
	return 1;
};




### main ###

# check global variables
if ($gnugk eq '')
{
	die "No path to gnugk executeable set. Exiting...";
};
if (!(-x $gnugk))
{
	die "Gnugk executeable $gnugk not found or not executeable. Exiting";
};
if ($statusPortCheckInterval <= 0)
{
	print "Status port check interval ivalid: $statusPortCheckInterval\n";
	print "  Setting to default: 60 sec.\n";
	$statusPortCheckInterval = 60;
};
if ($socketTimeout <= 0)
{
	print "Socket timeout value invalid: $socketTimeout\n";
	print "  Setting to default: 10 sec.\n";
	$socketTimeout = 10;
};

# check directories
die "Directory $pidFileDir check unsuccessful" unless checkDir($pidFileDir);
die "Directory $gnugkPidFileDir check unsuccessful" unless checkDir($gnugkPidFileDir);
if ($copyCore)
{
	die "Directory $coreFileDirectory check unsuccessful" unless checkDir($coreFileDirectory);
};
if ($logGnugkRestarts)
{	
	die "Directory $logFileDir check unsuccessful" unless checkDir($logFileDir);
	if (-e $logFile && !(-w $logFile))
	{
		die "Log file $logFile not writeable";
	};
};


# get config values from cmd line
my %conf = getConfStdin(\@ARGV); #get configuration from STDIN
# get home IP address and port (needed for checking if gnugk is frozen)
my ($homeIpAddress, $statusPort) = getConfFromFile(
		$conf{'path_to_gnugk_conf_file'}, $conf{'home_ip_address'}, $conf{'main_section_name'}
	);

# check gnugk home IP address and port
if ((!$homeIpAddress || !$statusPort) && $checkStatusPort)
{
	die "Can not detect gnugk home IP address and port\n";
};


### FORK ###
# create child process and exit from parent process
# run in background as a daemon
my $mainProcId = 0;
if ($runInBackground)
{
	print "Daemonizing...\n";
	exit if ($mainProcId = fork());
}
else
{
	$mainProcId = $$;
};

#print "Main process pid after forking: $mainProcId\n";

# create pid file, clear old one if exists
my $pidFile = "$pidFileDir/gnugk_wrapper_$homeIpAddress.pid";
if (!writePidFile($pidFile, ""))
{
	# set $pidFile to empty string to avoid trying to write to the file if
	#   this attempt failed
	$pidFile = "";
};

# set path to gnugk pid file
my $gnugkPidFile = "$gnugkPidFileDir/gnugk_$homeIpAddress.pid";

# get gnugk execution string (command that executes gnugk)
# concatenate all script arguments into one string
my $argvStr = "";
foreach (@ARGV)
{
	$argvStr .= "$_ ";
};
# cut trailing space
$argvStr =~ s/ $//;
my $gnugkExecStr = "$gnugk $argvStr --pid $gnugkPidFile > /dev/null 2>&1";


### FORK ###
# create child process which will have to run gnugk
# the other one will check if gnugk is ok
my $secondaryProcId = 0;
$secondaryProcId = fork();

# secondary proccess		
# run gnugk in child process
if ($secondaryProcId == 0)
{	
	# write current process pid to pid file
	writePidFile($pidFile, $$);
	
	# neverending loop for executing gnugk
	my $i = 0;
	my $gnugkExitCode = 0;
	while(1)
	{
		$i++;
		print "---\n\n" if ($debug);
		print "Executing gnugk (attempt: $i):\n" if ($debug);
		print "  $gnugkExecStr\n" if ($debug);
		$gnugkExitCode = system("$gnugkExecStr");
		print "  gnugk exited with code $gnugkExitCode\n. Restarting gnugk process\n" if($debug);
		
		# prepare current time
		my $timeNow = localtime->year+1900;
		$timeNow .= addLeadingZeros(localtime->mon, 2);
		$timeNow .= addLeadingZeros(localtime->mday, 2);
		$timeNow .= "_";
		$timeNow .= addLeadingZeros(localtime->hour, 2);
		$timeNow .= addLeadingZeros(localtime->min, 2);
		$timeNow .= addLeadingZeros(localtime->sec, 2);
		
		# copy gnugk core to core file directory
		if ($copyCore && -e './gnugk.core')
		{
			
			my $coreName = "gnugk_$timeNow.core";
			print "  Copying ./gnugk.core to $coreFileDirectory/$coreName\n";
			system ("cp ./gnugk.core $coreFileDirectory/$coreName");
		};
		
		# log restarting event to log file
		if ($logGnugkRestarts)
		{
			# open file
			eval
			{
				open (LOGFILE, ">>$logFile") or die "Error: can not open log file $logFile\n  $!";
			};
			# print error
			if ($@)
			{
				print $@ if ($debug);
			}
			# print message to log file
			else
			{
				print LOGFILE "[$timeNow] $homeIpAddress gnugk exited with code $gnugkExitCode\n";
				close (LOGFILE);
			};
		};
	};
	
}
# primary process
# check gnugk if it is ok
# kill gnugk proccess if needed
else
{	
	# write current process pid to pid file
	writePidFile($pidFile, $$);
	
	# Exit if status port checking disabled
	if (!$checkStatusPort)
	{
		print "Status port checking disabled\n" if ($debug);
		exit(0);
	};
	
	# neverending loop for checking status port
	my $sockMsg = ""; # output from socket
	my $sock = undef; # socket
	my $goodChars = 'A-Za-z0-9_;'; # character that are allowed to appear as normal status port output
	while (1)
	{
		# set variables to defaults
		$sock = undef;
		$sockMsg = "";
		
		sleep ($statusPortCheckInterval);
		print "---\n\n" if ($debug);
		print "Checking gnugk status port\n" if($debug);
		
		# open socket
		$sock = new Net::Telnet (
					Timeout		=> $socketTimeout,
					Host		=> $homeIpAddress,
					Port		=> $statusPort,
#					Prompt		=> '',
					Errmode		=> 'return',
					Telnetmode	=> 0,
				);
		$sock->open();
		
		# check socket
		if ($sock && !$sock->errmsg())
		{	
			print "  Socket opened successfully...\n" if ($debug);
			
			#read data from sock
			$sockMsg = "";
			my $blankLines = 0;
			# read from socket until buffer is empty, timeout occured or there is semicolon only in the line
			while (!$sock->eof() && !$sock->timed_out)
			{
				my $msg = $sock->getline(); # get one line
				$msg =~ s/^[^$goodChars]+|[^$goodChars]+$//; # cut out all non-good characters
				$sockMsg .= $msg;
				$blankLines++ if ($msg eq '' &&  $sockCheckMaxBlankLines); # increase number of blank lines if line from status port is blank
				last if ($blankLines >= $sockMaxBlankLines &&  $sockCheckMaxBlankLines); # break loop if max number of blank lines received
				last if ($msg eq ';'); # consider that message is received if there is semicolon only in current line
			};
			print "  Got from socket:\n" if ($debug);
			print "    $sockMsg\n"	if ($debug);
			
			# If socked timed out kill gnugk and skip all other checks
			if ($sock->timed_out)
			{
				print "  Socket timed out\n" if ($debug);
				$sock->close();
				killGnugk(getGnugkPid($gnugkPidFile));
				next;
			};
			# If access forbidden kill gnugk and skip all other checks
			if ($sockMsg =~ m/Access forbidden/i)
			{
				print "  Access forbidden to gnugk status port\n" if ($debug);
				$sock->close();
				killGnugk(getGnugkPid($gnugkPidFile));
				next;
			};
			# If no data received from gnugk kill gnugk and skip all other checks
			if ($sockMsg eq '')
			{
				print "  No message received from gnugk status port\n" if ($debug);
				$sock->close();
				killGnugk(getGnugkPid($gnugkPidFile));
				next;
			};
			# If max numbewr of blank lines received kill gnugk and skip all other checks
			if ($blankLines >= $sockMaxBlankLines &&  $sockCheckMaxBlankLines)
			{
				print "  Maximum number of blank lines from status port received\n" if ($debug);
				$sock->close();
				killGnugk(getGnugkPid($gnugkPidFile));
				next;
			};
			
			# set gnugk status port trace level to 0 to enable only direct responses to commands
			print "  Setting status port trace level to 0...\n" if ($debug);
			if(!$sock->put("trace 0\r\n"))
			{
				print "  Trace level adjusting unsuccessful\n" if ($debug);
				$sock->close();
				killGnugk(getGnugkPid($gnugkPidFile));
				next;
			};
			print "    Trace level set: ".$sock->getline() if ($debug);
			
			# clear sockets input buffer to be sure that no unwanted input is stored in it
			$sock->buffer_empty;
			
			# try to get version string from gnugk
			# kill gnugk if unsuccessful
			print "  Trying to get gnugk version from status port...\n" if($debug);
			if (!$sock->put("Version\r\n"))
			{
				print "  Sending \"Version\" request unsuccessful\n" if ($debug);
				$sock->close();
				killGnugk(getGnugkPid($gnugkPidFile));
				next;
			};
			
			#read data from sock
			$sockMsg = "";
			$blankLines = 0;
			# read from socket until buffer is empty, timeout occured or there is semicolon only in the line
			while (!$sock->eof() && !$sock->timed_out)
			{
				my $msg = $sock->getline(); # get one line
				$msg =~ s/^[^$goodChars]+|[^$goodChars]+$//; # cut out all non-good characters
				$sockMsg .= $msg;
				$blankLines++ if ($msg eq '' &&  $sockCheckMaxBlankLines); # increase number of blank lines if line from status port is blank
				last if ($blankLines >= $sockMaxBlankLines &&  $sockCheckMaxBlankLines); # break loop if max number of blank lines received
				last if ($msg eq ';'); # consider that message is received if there is semicolon only in current line
			};	
			
			print "  Got from socket:\n" if ($debug);
			print "    $sockMsg\n"	if ($debug);
			
			# If socked timed out kill gnugk and skip all other checks
			if ($sock->timed_out)
			{
				print "  Socket timed out\n" if ($debug);
				$sock->close();
				killGnugk(getGnugkPid($gnugkPidFile));
				next;
			};
			# If no data received from gnugk kill gnugk and skip all other checks
			if ($sockMsg eq '')
			{
				print "  No message received from gnugk status port\n" if ($debug);
				$sock->close();
				killGnugk(getGnugkPid($gnugkPidFile));
				next;
			};
			# If max numbewr of blank lines received kill gnugk and skip all other checks
			if ($blankLines >= $sockMaxBlankLines &&  $sockCheckMaxBlankLines)
			{
				print "  Maximum number of blank lines from status port received\n" if ($debug);
				$sock->close();
				killGnugk(getGnugkPid($gnugkPidFile));
				next;
			};
			
			$sock->close();
		}
		# report error and killgnugk
		else
		{
			print "  Could not create socket\n    $!\n" if ($debug);
			killGnugk(getGnugkPid($gnugkPidFile));
		};
	};
};
