#!/usr/bin/env perl
# a basic but useful net checker by @sha0coder
# sudo perl net.pl

#config this#
$remote_icmp = '8.8.8.8';  
$remote_dns = '@8.8.8.8';
$remote_name = 'dogpile.com';
$timeout = 15;
############


sub good {
	print "[Ok]\n";
}

sub normal {
	($msg) = @_;
	print "[??] ($msg)\n";
}

sub bad {
	($msg) = @_;
	print "[!!] ($msg)\n";
	exit 1;
}


@ifaces=`cat /proc/net/dev | awk '{ print \$1 }' | grep -v face | grep -v Inter | cut -d ':' -f 1`;
$user=`whoami`;
chomp $user;

$i=1;
foreach (@ifaces) {
	print "$i) $_";
	$i++;
}

print "Which interface to check? ";
$if=<STDIN>;
chomp $if;
$if--;

if ($if < 0 || $#ifaces < $if) {
	print "bad option.\n";
	exit 1;	
}

$iface = $ifaces[$if];
chop $iface;

print "Checking $iface:\n";

if ($user eq 'root') {
	print "- link ";

	$link=`mii-tool $iface 2>/dev/null`;  # this require root

	if ($link =~ /link ok/) {
		good();
	} else {
		normal('no link');
	}

} else {
	print "only root can check the link, skipping his step.\n";
}


print "- configured gateway ";

@gws=`route -n | grep $iface | awk '{ print \$2 }' | sort -u | grep -v 0.0.0.0`;

if ($#gws == -1) {
	bad('no gw configured');
} else {
	good();
}

print "- internet conectivity ";
$ping=`ping -c 1 -W $timeout  $remote_icmp 2>/dev/null`;
if ($ping =~ /ttl=/) {
	good();
} else {
	bad("couldn't connect on $timeout secs.");
}

print '- remote dns resolution ';
$dns=`dig $remote_dns $remote_name | grep -v ';' | grep $remote_name  2>/dev/null`;
@ips=($dns =~/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/g);

if ($#ips == -1) {
	bad('');
} else {
	good();
}

print '- remote tcp ';
$nc=`nc $ips[0] 80 -vv -z 2>&1`;
#print "nc $ips[0] 80 -vv -z 2>&1\n";

if ($nc =~ /(open|succeeded)/) {
	good();
} else {
	bad();
}

print '- local dns resolution ';
$dns=`dig $remote_name | grep -v ';' | grep $remote_name  2>/dev/null`;
@ips=($dns =~/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/g);

if ($#ips == -1) {
	bad('incorrect dns configuration');
} else {
	good();
}

print '- external ip: ';
$ip = `curl -ks ifconfig.co`;
chomp $ip;

print $ip."\n";

print "\n* $iface network Ok!!\n\n";

