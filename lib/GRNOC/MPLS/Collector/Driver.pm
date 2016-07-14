package GRNOC::MPLS::Collector::Driver;

use strict;
use warnings;

use Net::SNMP;
use JSON;

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
    my ($self, $params) = @_;
    my ($timestamp, $stats);

    if (lc($self->{'device'}) eq 'juniper') {
	($timestamp, $stats) = $self->_collect_juniper();
    } else {
	log_error("Unsupported device");
	return;
    }
    print Dumper($stats);
    my $tsds_push = GRNOC::WebService::Client->new(
	url => "$params->{'tsds_push_service'}/push.cgi",
	uid => $params->{'tsds_user'},
	passwd => $params->{'tsds_pass'},
	realm => $params->{'tsds_realm'},
	usePost => 1
	);

    my $tsds_admin = GRNOC::WebService::Client->new(
	url => "$params->{'tsds_push_service'}/admin.cgi",
	uid => $params->{'tsds_user'},
	passwd => $params->{'tsds_pass'},
	realm => $params->{'tsds_realm'},
	usePost => 1
	);

    foreach my $lsp (keys(%{$stats})) {
    	my $msg = {};
    	$msg->{'type'} = 'lsp';
    	$msg->{'time'} = $params->{'timestamp'};
    	$msg->{'interval'} = $params->{'interval'};
	
    	my $meta = {};
    	$meta->{'node'} = $self->{'name'};
    	$meta->{'lsp'} = $lsp;
    	$msg->{'meta'} = $meta;

    	my $values = {};
    	$values->{'state'} = $stats->{$lsp}->{'state'};
    	$values->{'octets'} = $stats->{$lsp}->{'octets'};
    	$values->{'packets'} = $stats->{$lsp}->{'packets'};
    	$msg->{'values'} = $values;

	my $tmp = [];
	push(@$tmp, $msg);
	my $json_push = encode_json($tmp);
	my $res_push = $tsds_push->add_data(data => $json_push);
	if (!defined $res_push) {
	    log_error("Could not post data to TSDS: " . $res_push->{'error'});
	    return; 
	}

	$msg = {};
	$msg->{'type'} = 'lsp';
	$msg->{'node'} = $self->{'name'};
	$msg->{'lsp'} = $lsp;
	$msg->{'start'} = $params->{'timestamp'};
	$msg->{'end'} = undef;
    	$msg->{'destination'} = $stats->{$lsp}->{'from'};
    	$msg->{'source'} = $stats->{$lsp}->{'to'};
    	$msg->{'path'} = $stats->{$lsp}->{'path_name'};

	$tmp = [];
	push(@$tmp, $msg);
	my $json_admin = encode_json($tmp);
	my $res_admin = $tsds_admin->update_measurement_metadata(values => $json_admin);
	if (!defined $res_admin) {
	    log_error("Could not post metadata to TSDS: " . $res_admin->{'error'});
	    return;
	}
    }

    return 1;
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
	-maxmsgsize => 65535,
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

    my $mpls_data;

    while (my ($oid, $value) = each %$name) {
	$value =~ s/[^[:print:]]//g;
	
	$oid =~ s/$mplsLspInfoName/$mplsLspInfoState/;
	$mpls_data->{$value}->{'state'} = $state->{$oid};

	$oid =~ s/$mplsLspInfoState/$mplsLspInfoOctets/;
	$mpls_data->{$value}->{'octets'} = $octets->{$oid};
	
	$oid =~ s/$mplsLspInfoOctets/$mplsLspInfoPackets/;
	$mpls_data->{$value}->{'packets'} = $packets->{$oid};

	$oid =~ s/$mplsLspInfoPackets/$mplsLspInfoFrom/;
	$mpls_data->{$value}->{'from'} = $from->{$oid};

	$oid =~ s/$mplsLspInfoFrom/$mplsLspInfoTo/;
	$mpls_data->{$value}->{'to'} = $to->{$oid};

	$oid =~ s/$mplsLspInfoTo/$mplsPathInfoName/;
	$mpls_data->{$value}->{'path_name'} = $path_name->{$oid};
    }

    return($collection_timestamp, $mpls_data);
}
1;
