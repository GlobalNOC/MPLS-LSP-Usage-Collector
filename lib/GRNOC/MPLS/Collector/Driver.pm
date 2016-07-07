package GRNOC::MPLS::Collector::Driver;

use strict;
use warnings;

use Net::SNMP;

use GRNOC::Log;
use GRNOC::Config;
use GRNOC::WebService::Client;

use Data::Dumper;

sub new {
    my ($class, $self) = @_;
    if (!defined($self->{'community'}) ||
	!defined($self->{'version'}) ||
	!defined($self->{'ip'}) ||
	!defined($self->{'name'}) ||
	!defined($self->{'device'})) {
	return;
    }

    bless($self, $class);
    return $self;
}

sub collect_data { 
    my ($self) = @_;
    my $res; 
    if (lc($self->{'device'}) eq 'juniper') {
	$res = $self->_collect_juniper();
    }
    return $res;
}

sub _collect_juniper {
    my ($self) = @_;
    my $mplsLspInfoName = "1.3.6.1.4.1.2636.3.2.5.1.1";
    my $mplsLspInfoState = "1.3.6.1.4.1.2636.3.2.5.1.2";
    my $mplsLspInfoOctets = "1.3.6.1.4.1.2636.3.2.5.1.3";
    my $mplsLspInfoPackets = "1.3.6.1.4.1.2636.3.2.5.1.4";
    my $mplsLspInfoFrom = "1.3.6.1.4.1.2636.3.2.5.1.15";
    my $mplsLspInfoTo = "1.3.6.1.4.1.2636.3.2.5.1.16";
    my $mplsPathInfoName = "1.3.6.1.4.1.2636.3.2.5.1.17";

    my ($session, $error) = Net::SNMP->session(
    	-hostname => $self->{'ip'},
    	-community => $self->{'community'},
    	-version => 'snmpv2c',
    	-translate => [-octetstring => 0]
    	);
    
    if (!$session) {
    	log_error("Error talking SNMP to $self->{'name'}: " . $error);
    	return;
    }
    
    my $collection_timestamp = time(); 
    
    my $name = $session->get_table(
    	-baseoid => $mplsLspInfoName
    	);

    if (!$name) {
    	log_error("Error getting mplsLspInfoName for $self->{'name'}: " . $session->error());
    	$session->close();
    	return;
    }

    my $state = $session->get_table(
	-baseoid => $mplsLspInfoState
	);

    if (!$state) {
	log_error("Error getting mplsLspInfoState for $self->{'name'}: " . $session->error());
	$session->close();
	return;
    }

    my $octets = $session->get_table(
	-baseoid => $mplsLspInfoOctets
	);

    if (!$octets) { 
	log_error("Error getting mplsLspInfoOctets for $self->{'name'}: " . $session->error());
	$session->close();
	return;
    }

    my $packets = $session->get_table(
	-baseoid => $mplsLspInfoPackets
	);

    if (!$packets) { 
	log_error("Error getting mplsLspInfoPackets for $self->{'name'}: " . $session->error());
	$session->close();
	return;
    }

    my $from = $session->get_table(
	-baseoid => $mplsLspInfoFrom
	);

    if (!$from) {
	log_error("Error getting mplsLspInfoFrom for $self->{'name'}: " . $session->error());
	$session->close();
	return;
    }

    my $to = $session->get_table(
	-baseoid => $mplsLspInfoTo
	);

    if (!$to) {
	log_error("Error getting mplsLspInfoTo for $self->{'name'}: " . $session->error());
	$session->close();
	return;
    }

    my $path_name = $session->get_table(
	-baseoid => $mplsPathInfoName
	);

    if (!$path_name) {
	log_error("Error getting mplsPathInfoName for $self->{'name'}: " . $session->error());
	$session->close();
	return;
    }

    $session->close();

    my @result = ($name, $state, $octets, $packets, $from, $to, $path_name);
    return \@result;
}
1;
