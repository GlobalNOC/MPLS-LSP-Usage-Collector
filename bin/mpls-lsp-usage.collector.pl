#!/usr/bin/perl

use strict;
use warnings;

use GRNOC::MPLS::Collector;
use Getopt::Long;

### constants ###

use constant DEFAULT_CONFIG_FILE => "/etc/grnoc/mpls-lsp-usage-collector/config.xml";
use constant DEFAULT_LOGGING_FILE => "/etc/grnoc/mpls-lsp-usage-collector/logging.conf";
use constant DEFAULT_PID_FILE => "/var/run/mpls-lsp-usage-collector.pid";

# command line options
my $config_file = DEFAULT_CONFIG_FILE;
my $logging_file = DEFAULT_LOGGING_FILE;
my $pid_file = DEFAULT_PID_FILE;
my $nofork;
my $help;

GetOptions( "config|c=s" => \$config_file,
            "logging=s" => \$logging_file,
            "pid-file=s" => \$pid_file,
            "nofork" => \$nofork,
            "help|h|?" => \$help,
            "timerange=s" => \$time_range,
            "runonce" => \$runonce ) or usage();

# did they ask for help?
usage() if ( $help );

my $grnoc_log = new GRNOC::Log(
    config => $logging_file
    );

my $daemonize = !$nofork;

my $collector = GRNOC::MPLS::Collector->new( config_file => $config_file,
					     pid_file => $pid_file,
					     daemonize => $daemonize,
					     time_range_cli => $time_range,
					     run_once => $runonce,
    );

$collector->start();

sub usage {
    print "$0 [--config <config file>] [--logging <logging config file>] [--pid-file <pid file>] [--nofork] [--timerange <seconds>] [--runonce] [--help]\n";
    print "\t--nofork - Do not daemonize\n";
    exit( 1 );
}
