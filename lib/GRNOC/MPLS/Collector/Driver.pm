package GRNOC::MPLS::Collector::Driver;

use strict;
use warnings;

use Net::SNMP;
use GRNOC::Log;

sub new {
    my $class = shift;
    return bless({}, $class);
}

sub collect_data { 
    my ($self, $params) = @_;
    my $stats;
    my $node = $params->{'node'};

    if (lc($node->{'device'}) eq 'juniper') {
	$stats = $self->_collect_juniper($node);
    } else {
	log_error("Unsupported device");
	return;
    }

    return $stats;
}

sub _collect_juniper {
    my ($self, $node) = @_;

    my $mplsLspInfoName = "1.3.6.1.4.1.2636.3.2.5.1.1";
    my $mplsLspInfoState = "1.3.6.1.4.1.2636.3.2.5.1.2";
    my $mplsLspInfoOctets = "1.3.6.1.4.1.2636.3.2.5.1.3";
    my $mplsLspInfoPackets = "1.3.6.1.4.1.2636.3.2.5.1.4";
    my $mplsLspInfoFrom = "1.3.6.1.4.1.2636.3.2.5.1.15";
    my $mplsLspInfoTo = "1.3.6.1.4.1.2636.3.2.5.1.16";
    my $mplsPathInfoName = "1.3.6.1.4.1.2636.3.2.5.1.17";

    my ($session, $error) = Net::SNMP->session(
    	-hostname => $node->{'ip'},
    	-community => $node->{'community'},
    	-version => 'snmpv2c',
	-maxmsgsize => 65535,
    	-translate => [-octetstring => 0]
    	);
    
    if (!$session) {
    	log_error("Error talking SNMP to $node->{'name'}: " . $error);
    	return;
    }
    
    my $mpls_data = {
	timestamp => time(),
	lsps => {},
    };
    
    my $name = $session->get_table(
    	-baseoid => $mplsLspInfoName
    	);

    if (!$name) {
    	log_error("Error getting mplsLspInfoName for $node->{'name'}: " . $session->error());
    	$session->close();
    	return;
    }

    my $state = $session->get_table(
	-baseoid => $mplsLspInfoState
	);

    if (!$state) {
	log_error("Error getting mplsLspInfoState for $node->{'name'}: " . $session->error());
	$session->close();
	return;
    }

    my $octets = $session->get_table(
	-baseoid => $mplsLspInfoOctets
	);

    if (!$octets) { 
	log_error("Error getting mplsLspInfoOctets for $node->{'name'}: " . $session->error());
	$session->close();
	return;
    }

    my $packets = $session->get_table(
	-baseoid => $mplsLspInfoPackets
	);

    if (!$packets) { 
	log_error("Error getting mplsLspInfoPackets for $node->{'name'}: " . $session->error());
	$session->close();
	return;
    }

    my $from = $session->get_table(
	-baseoid => $mplsLspInfoFrom
	);

    if (!$from) {
	log_error("Error getting mplsLspInfoFrom for $node->{'name'}: " . $session->error());
	$session->close();
	return;
    }

    my $to = $session->get_table(
	-baseoid => $mplsLspInfoTo
	);

    if (!$to) {
	log_error("Error getting mplsLspInfoTo for $node->{'name'}: " . $session->error());
	$session->close();
	return;
    }

    my $path_name = $session->get_table(
	-baseoid => $mplsPathInfoName
	);

    if (!$path_name) {
	log_error("Error getting mplsPathInfoName for $node->{'name'}: " . $session->error());
	$session->close();
	return;
    }

    $session->close();

    while (my ($oid, $value) = each %$name) {
	$value =~ s/[^[:print:]]//g;
	
	$oid =~ s/$mplsLspInfoName/$mplsLspInfoState/;
	$mpls_data->{'lsps'}->{$value}->{'state'} = $state->{$oid};

	$oid =~ s/$mplsLspInfoState/$mplsLspInfoOctets/;
	$mpls_data->{'lsps'}->{$value}->{'octets'} = $octets->{$oid};
	
	$oid =~ s/$mplsLspInfoOctets/$mplsLspInfoPackets/;
	$mpls_data->{'lsps'}->{$value}->{'packets'} = $packets->{$oid};

	$oid =~ s/$mplsLspInfoPackets/$mplsLspInfoFrom/;
	$mpls_data->{'lsps'}->{$value}->{'from'} = $from->{$oid};

	$oid =~ s/$mplsLspInfoFrom/$mplsLspInfoTo/;
	$mpls_data->{'lsps'}->{$value}->{'to'} = $to->{$oid};

	$oid =~ s/$mplsLspInfoTo/$mplsPathInfoName/;
	$mpls_data->{'lsps'}->{$value}->{'path_name'} = $path_name->{$oid};
    }

    return $mpls_data;
}
1;
