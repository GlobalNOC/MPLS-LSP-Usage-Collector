#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;

use GRNOC::Log;
use GRNOC::Config;
use GRNOC::MPLS::Collector;

use constant DEFAULT_CONFIG_FILE => "/etc/grnoc/mpls-lsp-usage-collector/config.xml";

my $config_file = DEFAULT_CONFIG_FILE;
my $nofork = 0;
my $debug = 0;
my $help;

GetOptions( "config|c=s" => \$config_file,
            "nofork" => \$nofork,
	    "debug|d" => \$debug,
            "help|h|?" => \$help,
    );


usage() if ( $help );

my $config = GRNOC::Config->new(
    'config_file' => $config_file,
    'force_array' => 0
    );

my $grnoc_log = GRNOC::Log->new(
    'config' => $config->get('/config/logging/@config-file')
    );

my $collector = GRNOC::MPLS::Collector->new( config_file => $config_file,
					     daemonize => !$nofork,
    );

$collector->start();

sub usage {
    print "$0 [--config <config file>] [--debug] [--help]\n";
    print "\t--nofork - Do not daemonize\n";
    exit( 1 );
}
