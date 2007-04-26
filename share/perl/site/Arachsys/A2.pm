package Arachsys::A2;
require 5.006;

use Net::DNS;
use Socket;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);
our $VERSION = 0.40;
our @EXPORT = qw();
our @EXPORT_OK = qw(nslist soalist txtlist checkdomain domainusers checkip
                    ipusers checkuser checkdomainuser checkipuser
                    checkprivilege);

my $resolver = new Net::DNS::Resolver;

my %nslistcache = ();

sub nslist($) {
  my $domain = shift;
  unless (exists $nslistcache{$domain}) {
    my @nslist = ();
    my $query = $resolver->query("$domain.", "NS");
    if ($query) {
      foreach my $rr ($query->answer) {
        next unless $rr->name eq $domain and $rr->type eq 'NS';
        push @nslist, $rr->nsdname;
      }
    }
    $nslistcache{$domain} = [@nslist];
  }
  return @{$nslistcache{$domain}};
}

my %soalistcache = ();

sub soalist($) {
  my $domain = shift;
  unless (exists $soalistcache{$domain}) {
    my @soalist = ();
    my $query = $resolver->query("$domain.", "SOA");
    if ($query) {
      foreach my $rr ($query->answer) {
        next unless $rr->name eq $domain and $rr->type eq 'SOA';
        push @soalist, $rr->mname;
      }
    }
    $soalistcache{$domain} = [@soalist];
  }
  return @{$soalistcache{$domain}};
}

my %txtlistcache = ();

sub txtlist($) {
  my $domain = shift;
  unless (exists $txtlistcache{$domain}) {
    my @txtlist = ();
    my $query = $resolver->query("$domain.", "TXT");
    if ($query) {
      foreach my $rr ($query->answer) {
        next unless $rr->name eq $domain and $rr->type eq 'TXT';
        push @txtlist, $rr->char_str_list;
      }
    }
    $txtlistcache{$domain} = [@txtlist];
  }
  return @{$txtlistcache{$domain}};
}

my $domainatom = qr/(?i:[a-z0-9](?:[a-z0-9-]*[a-z0-9]|))/;
my $domainpattern = qr/^($domainatom(?:\.$domainatom)*)\.?$/;

sub checkdomain($) {
  my $domain = lc shift;
  return (defined $domain and $domain =~ $domainpattern) ? $1 : undef;
}

my $nspattern = qr/(\w+)\.\w+\.ns\.arachsys\.(net|com)/i;
my $txtpattern = qr/\s*ARACHSYS\s+USER[:\s]+([^:\s].*)/i;

sub domainusers($) {
  my $domain = shift;
  return () unless defined $domain;
  my (@nsusers, @txtusers, %seen);
  $domain =~ s/^\.*(.*?)\.*$/$1/;
  do {
    foreach my $txt (txtlist $domain) {
      next unless $txt =~ $txtpattern;
      push @txtusers, split /[\s,;:]+/, lc $1;
    }
    foreach my $ns (soalist $domain, nslist $domain) {
      push @nsusers, lc $1 if $ns =~ $nspattern;
    }
  } while (not @nsusers and $domain =~ s/^[^.]+\.//);
  return grep { ! $seen{$_} ++ } (@nsusers, @txtusers);
}

sub checkip($) {
  my $ip = shift;
  return undef unless inet_aton $ip;
  $ip = inet_ntoa(inet_aton $ip);
  return $ip;
}

sub ipusers($) {
  my $ip = checkip(shift);
  return () unless defined $ip and $ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
  if ($1 == 127 and $2 == 1) {
    return scalar getpwuid 256*$3 + $4 || ();
  }
  return domainusers "$4.$3.$2.$1.in-addr.arpa";
}

sub checkuser($) {
  my $username = shift;
  my $uid = getpwnam $username;
  return defined $uid ? $uid == $< : 0;
}

my %checkeddomains = ();

sub checkdomainuser($) {
  my $domain = lc shift;
  return "" unless defined $domain;
  unless (exists $checkeddomains{$domain}) {
    $checkeddomains{$domain} = "";
    foreach my $username (domainusers $domain) {
      if (checkuser $username) {
        $checkeddomains{$domain} = $username;
        last;
      }
    }
  }
  return $checkeddomains{$domain};
}

sub checkipuser($) {
  my $ip = checkip(shift);
  return () unless defined $ip and $ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
  if ($1 == 127 and $2 == 1) {
    return $< == 256*$3 + $4 ? scalar getpwuid $< : "";
  }
  return checkdomainuser "$4.$3.$2.$1.in-addr.arpa";
}

sub checkprivilege() {
  return 1 if $< == 0;
  my $staff = getgrnam "staff";
  return 0 unless defined $staff;
  foreach my $group (split ' ', $() {
    return 1 if ($group == $staff);
  }
  return 0;
}

1;
