package GRNOC::MPLS::Collector::Driver;

use strict;
use warnings;

use Net::SNMP;

use GRNOC::Log;
use GRNOC::Config;
use GRNOC::WebService::Client;

use Data::Dumper;

sub new {
    my $caller = shift;
    my $class = ref($caller);
    $class = $caller if (!$class);
    my $self = {@_};
    bless($self, $class);
    return $self;
}

sub _collect_juniper {
    my ($self, $node) = @_;
    my $mplsLspInfoName = "1.3.6.1.4.1.2636.3.2.5.1.1";

    my ($session, $error) = Net::SNMP->session(
    	-hostname => $node->{'ip'},
    	-community => $node->{'community'},
    	-version => 'snmpv2c',
    	-translate => [-octetstring => 0]
    	);
    
    if (!$session) {
    	log_error("Error talking SNMP to $node->{'name'}: " . $error);
    	return;
    }
    
    my $collection_timestamp = time(); 
    
    my $mpls_lsp_info_name = $session->get_table(
    	-baseoid => $mplsLspInfoName
    	);

    if (!$mpls_lsp_info_name) {
    	log_error("Error getting mplsLspInfoName for $node->{'name'}: " . $session->error());
    	$session->close();
    	return;
    }

    print Dumper($mpls_lsp_info_name); 
}
1;
