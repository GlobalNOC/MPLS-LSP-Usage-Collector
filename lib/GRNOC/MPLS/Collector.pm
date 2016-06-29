#!/usr/bin/perl

package GRNOC::MPLS::Collector;

use strict;
use warnings;

use Net::SNMP;
use Proc::Daemon;
use Parallel::ForkManager;
use Math::Round qw( nhimult );
use JSON;

use GRNOC::Log;
use GRNOC::Config;
use GRNOC::WebService::Client;

our $VERSION = '0.1.0';

use constant DEFAULT_PID_FILE => '/var/run/mpls-lsp-usage-collector.pid';

sub new {
    my $caller = shift;
    my $class = ref($caller);
    $class = $caller if (!$class);

    my $self = { 
	config_file => undef,
	pid_file => DEFAULT_PID_FILE,
	daemonize => 1,
	running => 0,
	hup => 0,
	@_
    };

    bless($self, $class);
    $self->_init();
    return $self;
}

sub start {
    my ($self) = @_;

    if ($self->{'daemonize'}) {
	log_info("Spawning daemon process");

	my ($name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell) = getpwnam("mpls-lsp-usage-collector");
	
	my $daemon = Proc::Daemon->new(
	    setgid => $gid,
	    setuid => $uid,
	    pid_file => $self->{'pid_file'}
	    );

	my $pid = $daemon->init();

	if (!$pid) {
	    $0 = "mpls-lsp-usage-collector";

	    $SIG{'TERM'} = sub {$self->stop();};
	    $SIG{'HUP'} = sub {$self->hup();};

	    $self->{'running'} = 1;
	    $self->_run();
	}

    } else {
	$self->{'running'} = 1;
	$self->_run();
    }
}

sub stop {
    my ($self) = @_;

    log_info("Stopping");
    $self->{'running'} = 0;
}

sub hup {
    my ($self) = @_;

    log_info("HUP received");
    $self->{'hup'}++;
}

sub _run {
    my ($self) = @_;

    log_info("Starting");

    while ($self->{'running'}) { 
	my $now = time();
	my $timestamp = nhimult($self->{'interval'}, $now);
	my $sleep_seconds = $timestamp - $now;
	my $human_readable_date = localtime($timestamp);

	log_info("Sleeping $sleep_seconds until local time $human_readable_date ($timestamp).");

	while ($sleep_seconds > 0) {
	    my $time_slept = sleep($sleep_seconds);
	    last if (!$self->{'running'});
	    $sleep_seconds -= $time_slept;
	}

	last if (!$self->{'running'});

	if ($self->{'hup'}) { 
	    log_info("Handle HUP");
	    $self->_init();
	    log_info("HUP finished");
	    $self->{'hup'} = 0;
	    next;
	}

	$self->_collect();
    }
}

sub _collect {
    return;
}

sub _init {
    my ($self) = @_;

    log_info("Creating new config object from $self->{'config_file'}");
    my $config = GRNOC::Config->new(
    	config_file => $self->{'config_file'},
    	force_array => 0
    	);
    $self->{'config'} = $config;

    $self->{'interval'} = $config->get('/config/@interval');
    $self->{'interval'} //= 10;

    $self->{'tsds_push_service'} = $config->get('/config/@tsds_push_service');
    $self->{'tsds_user'} = $config->get('/config/@tsds_user');
    $self->{'tsds_pass'} = $config->get('/config/@tsds_pass');

    $self->{'tsds_realm'} = $config->get('/config/@tsds_realm');
    $self->{'tsds_realm'} //= "Basic Auth";

    $config->{'force_array'} = 1;
    $self->{'nodes'} = $config->get('/config/node');

    log_info("Creating new webservice client object");
    my $tsds_svc = GRNOC::WebService::Client->new(
    	use_keep_alive => 1,
    	cookieJar => '/tmp/mpls-lsp-usage-collector-cookies.txt',
    	url => $self->{'tsds_push_service'},
    	uid => $self->{'tsds_user'},
    	passwd => $self->{'tsds_pass'},
    	realm => "Realm Here",
    	debug => $self->{'debug'}
    	);
}
