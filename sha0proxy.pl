#!/usr/bin/perl -w

#Proxy MultiProtocolo
#sha0proxy.pl  v2.0 coded by sha0@badchecksum.net

#TODO: capturar SIGINT
#      ncurses para modificar los bytes directamente
#      formato shellcode
#      logear
#      fuzz
#      quit
#      capturar paketes y retransmitirlos fuzeados


#perl -MCPAN -e shell
#cpan>install threads
#...
#cpan>install IO::Socket
#...
#cpan>install IO::Select
#...

use IO::Socket;
use IO::Select;

my %color=(
	red=>"\x1b[31;01m",
	green=>"\x1b[32;02m",
	yellow=>"\x1b[33;01m",
	blue=>"\x1b[34;01m",
	magenta=>"\x1b[35;01m",
	cyan=>"\x1b[36;01m",
	white=>"\x1b[37;00m"
);


die "$0 <tcp/udp> <lport> <rhost> <rport> <mode>\nmodes: view trap fuzz\ntrap sample: where>3A1 what>AAA\\x00 (enter for change nothing)\ntrap also can be used inline with extra params: <packet number> <where> <what>\nor: <replacements file>\nfuzz: not tested!\n" if (@ARGV!=5 && @ARGV !=6 && @ARGV!=8);

die "Valid modes are:  view, trap & fuzz\n" if ($ARGV[4] ne 'view' && $ARGV[4] ne 'trap' && $ARGV[4] ne 'fuzz');


#Constants
my $UDP_MAX_DGRAM_SIZE = 100;
my $UDP_RECV_TIMEOUT = 5;


#my $lport=(int(rand(500))+10000);
my $proto=lc($ARGV[0]);
my $lport=$ARGV[1];
my $rport=$ARGV[3];
my $rhost=$ARGV[2];
my $buff;
my $vulnerable=0;
my $mode=lc($ARGV[4]);
my @sended;

my $packet_num=1;
my @inline_num;
my @inline_where;
my @inline_what;

if (@ARGV == 8) {
	push @inline_num, $ARGV[5];
	push @inline_where, $ARGV[6];
	push @inline_what, $ARGV[7];
}

if (@ARGV == 6) {
	$file = $ARGV[5];
	print "loading $file\n";
	open F,"<$file";
	while (<F>) {
		chomp;
		next if (/^\#/);	
		if (/(.*)[ \t]([0-9a-f]{1,5})[ \t](.*)/i) {
			push @inline_num, $1;
			push @inline_where, $2;
			push @inline_what, $3;
		}
	}
}

sub doFuzz {
	print "NOT IMPLEMENTED!!";
}



sub TCP_Proxy {

	my $out;
	my $in=IO::Socket::INET->new (
		LocalAddr=>'0.0.0.0',
		LocalPort=>$lport,
		Proto=>'tcp',
		Listen=>1,
		Reuse=>100
	) or die "cannot open port $!\n";

	print "listening $lport port\n";


	while (my $welcome=$in->accept()) {
		$out=IO::Socket::INET->new (
			PeerAddr=>$rhost,
			PeerPort=>$rport,
			Timeout=>20
		) or die "cannot connect $!\n";

		print "connected to $rhost:$rport\n";


		#proxy
		if (!fork()) {
			$out->blocking(1);
			$welcome->blocking(1);
			$out->autoflush(1);
			$welcome->autoflush(1);

			$s=IO::Select->new($out, $welcome);
		proxy:
    			while(1) {
      				my @ready = $s->can_read;
				foreach my $ready (@ready) {
        				if($ready == $welcome) {
          					my $data;
	          				$welcome->recv($data, 81920);
						last proxy if (! length($data));
						last proxy if(!$out || !$out->connected);
						&muestra($data,1);
						push @sended, $data;
						$data=&changeData($data,1);
						$packet_num++;
	          				eval { $out->send($data); };
	          				last proxy if $@;
	        			} elsif ($ready == $out) {
	          				my $data;
				        	$out->recv($data, 81920);
						last proxy if(!length($data));
				        	last proxy if(!$welcome || !$welcome->connected);
						&muestra($data,0);
						$data=&changeData($data,0);
						$packet_num++;
				        	eval { $welcome->send($data); };
				        	last proxy if $@;
	        			}
				}#foreach
			
				if (!$welcome || !$out) {
					close $out;
					close $welcome;
					return;
				}

      			}# endless loop engine
    		} #fork

	} #while accep t

}

sub changeData {
	my $data = $_[0];
	my $alserver = $_[1];
	my $changes=0;

	my $what='';
	my $where=0;

	#print "-------------------";
	for (local $z=0; $z<= $#inline_num; $z++) {
		if ($inline_num[$z] == $packet_num || $inline_num[$z] eq '*') {
			$where = hex($inline_where[$z]);
			$what = $inline_what[$z];
			$data = &reemplaza($data,$alserver,$where,$what);
			$changes=1;
			#print "we ".$where." ".$what." ".$data."\n";
			#&muestra($data);
		}
	}
	#print "fin-------------";

	if ($mode eq 'trap') {
		print "where>";	
		$where = <stdin>;
		chomp $where;
		$where = hex($where);
		print "what>";
		$what = <stdin>;
		chomp $what;
		$data = &reemplaza($data,$alserver,$where,$what);
		$changes = 1 if ($what);
	}
	
	&muestra($data,$alserver) if ($changes);
	return $data;
}

sub reemplaza () {
	my $d=0;
	my $cleanwtf;
	my ($data,$alserver,$where,$what) = @_;

	@databytes = split('',$data);
	@wtf = split('',$what);
	$cleanwtf='';
	for ($i = 0; $i < length($what); $i++) {
		#If user enter byte mode
		if ($wtf[$i] eq '\\' && $wtf[$i+1] eq 'x') {
			#print "byte".chr(hex($wtf[$i+2].$wtf[$i+3]))."\n";
			$cleanwtf.=chr(hex($wtf[$i+2].$wtf[$i+3]));
			$i+=3;
		} else {
			$cleanwtf.=$wtf[$i];
		}
	}

	@wtf = split('',$cleanwtf);
	
	for ($i = 0; $i < length($cleanwtf); $i++) {
		$databytes[$i+$where] = $wtf[$i];
	}
	$data = join('',@databytes);


	return $data;
}


sub muestra {
	my $data = $_[0];
	my @bytes = split(//,$data);
	my $b;
	my $alserver = $_[1];
	my $count=0;
	my $str="";
	my $lin=1;
	print $color{white};
	$banner=">"x33 if ($alserver);
	$banner="<"x33 if (!$alserver);
	printf "\n%d%s",$packet_num,$banner;
	print "\n   |00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f |";
	print "\n---+------------------------------------------------+---\n";

	print "000|";
	foreach $b (@bytes) {
		print $color{green}  if (($b ge 'a' && $b le 'z') ||($b ge 'A' && $b le 'Z') || $b eq "\x20"); 
		print $color{blue}   if ($b ge '0' && $b le '9');
		print $color{red}    if ($b eq "\x00");
		print $color{cyan}   if ($b eq "\x0a" || $b eq "\x0d");
		printf "%.2x ",ord($b);
		print $color{white};

		$b = "." if ($b lt "\x20" || $b gt "\x7e");
	
		$count++;
		$str.=$b;
		if ($count==16) {
			#$str=~s/[^a-z^A-Z^0-9^#^@^:^]/\./ig;
			printf "%s\n%.3x|",$str,$count*$lin;
			$lin++;
			$str="";
			$count = 0;
		}
	}
	$str=~s/[^a-z^A-Z^0-9^#^@]/\./ig;
	for ($b=$count;$b<16;$b++){
		print "   ";
	}
	print $str."\n";
	
	#print "\n"."-"x33;
	#$data=~s/[^a-z^A-Z^0-9]/\./ig;
	#print "\n$data\n";
}

sub UDP_Proxy {
        local ($server_port, $forward_host, $forward_port) = @_;

        $sock = IO::Socket::INET->new(LocalPort=>$server_port,Proto=>'udp') or die "can't open $server_port/udp  msg: $!";
        print "Listeinig $server_port/udp and redirecting to $forward_host:$forward_port/udp\n";

        while ($sock->recv($dgram, $UDP_MAX_DGRAM_SIZE)) {
                #my ($client_port, $client_ip) = sockaddr_in($sock->peername);
                #$hishost = gethostbyaddr($ipaddr, AF_INET);

		&muestra($dgram, 1);
		push @sended, $dgram;
		$dgram = &changeData($dgram, 1);
		$packet_num++;

                #print "localhost:$server_port/udp -> $forward_host:$forward_port/udp\n";
                #print "$dgram\n";

                $resp = UDP_Send($forward_host, $forward_port, $dgram);

		&muestra($resp, 0);
		push @sended, $resp;
		$resp = &changeData($resp, 0);
		$packet_num++;


                $sock->send($resp);


                #print "localhost:$server_port/udp <- $forward_host:$forward_port/udp\n";
                #print "$resp\n";

        }
        die "UDP Service crashed: $!";
}

sub UDP_Send {
        local ($host,$port,$dgram) = @_;

        $udp = IO::Socket::INET->new(Proto=>'udp',PeerPort=>$port,PeerAddr=>$host) or die "Error sending datagram to $host\n$!\n";
        $udp->send($dgram) or die "send: $!";

	$resp = '';
        eval {
                local $SIG{ALRM} = sub { die "alarm time out" };
                alarm $UDP_RECV_TIMEOUT;
                $udp->recv($resp, $UDP_MAX_DGRAM_SIZE)      or die "recv: $!";
                alarm 0;
                1;  # return value from eval on normalcy
        } or print "recv from $host timed out after $UDP_RECV_TIMEOUT seconds.\n";

        #($port, $ipaddr) = sockaddr_in($sock->peername);
        #$hishost = gethostbyaddr($ipaddr, AF_INET);
        #print "Server $hishost responded ``$resp''\n";

        return $resp;
}


# MAIN

if ($proto eq "tcp") {

		TCP_Proxy();

} else {
	if ($proto eq "udp")  {

		UDP_Proxy($lport,$rhost,$rport);		

	} else {
		die "$proto protocol is not suported, only tcp or udp and their sub-protocols\n";
	}
}



