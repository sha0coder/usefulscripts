#!/usr/bin/env perl
# a basic but useful net checker by @sha0coder

#config this#
$remote_icmp = '8.8.8.8';  
$remote_dns = '@8.8.8.8';
$remote_name = 'dogpile.com';
$timeout = 10;
############


sub good {
	print "[Ok]\n";
}

sub bad {
	($msg) = @_;
	print "[!!] ($msg)\n";
	exit 1;
}


@ifaces=`cat /proc/net/dev | awk '{ print \$1 }' | grep -v face | grep -v Inter | cut -d ':' -f 1`;


$i=0;
foreach (@ifaces) {
	print "$i) $_";
	$i++;
}

print "Which interface to check? ";
$if=<STDIN>;
chop $if;
$iface = $ifaces[$if];
chop $iface;

print "Checking $iface:\n";
print "- link ";

$link=`sudo mii-tool $iface 2>/dev/null`;

if ($link =~ /link ok/) {
	good();
} else {
	bad('no link');
}


print "- configured gateway ";

@gws=`route -n | grep $iface | awk '{ print \$2 }' | sort -u | grep -v 0.0.0.0`;

if (length(@gws) == 0) {
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

if (length(@ips) > 0) {
	good();
} else {
	bad('');
}

print '- remote tcp ';
$nc=`nc $ips[0] 80 -vv -z 2>&1`;

if ($nc =~ /succeeded/) {
	good();
} else {
	bad();
}

print "\n* $iface network ok!!\n";





