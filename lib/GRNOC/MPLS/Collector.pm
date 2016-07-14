package GRNOC::MPLS::Collector;

use strict;
use warnings;

use Proc::Daemon;
use Parallel::ForkManager;
use Math::Round qw( nhimult );

use GRNOC::Log;
use GRNOC::Config;
use GRNOC::MPLS::Collector::Driver;

use Data::Dumper;

our $VERSION = '0.1.0';

use constant DEFAULT_PID_FILE => '/var/run/mpls-lsp-usage-collector.pid';
use constant MAX_RATE_VALUE => 2199023255552;

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
    my ($self) = @_;
    log_info("Collecting...");

    my $forker = Parallel::ForkManager->new($self->{'max_procs'});

    foreach my $node (@{$self->{'nodes'}}) {
	$forker->start() and next;

	my $driver = GRNOC::MPLS::Collector::Driver->new($node);
	if (!defined($driver)) {
	    log_error("Could not create driver for $node->{'name'}");
	    $forker->finish() and next;
	}

	my $res = $driver->collect_data({
	    interval => $self->{'interval'},
	    tsds_push_service => $self->{'tsds_push_service'},
	    tsds_user => $self->{'tsds_user'},
	    tsds_pass => $self->{'tsds_pass'},
	    tsds_realm => $self->{'tsds_realm'}
				       });

	if (!defined $res) {
	    log_error("Could not submit data on $node->{'name'}");
	}

	$forker->finish();
    }

    $forker->wait_all_children();
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

    $self->{'max_procs'} = $config->get('/config/@max_procs');

    $self->{'tsds_push_service'} = $config->get('/config/@tsds_push_service');
    $self->{'tsds_user'} = $config->get('/config/@tsds_user');
    $self->{'tsds_pass'} = $config->get('/config/@tsds_pass');

    $self->{'tsds_realm'} = $config->get('/config/@tsds_realm');
    $self->{'tsds_realm'} //= "Basic Auth";

    $config->{'force_array'} = 1;
    $self->{'nodes'} = $config->get('/config/node');

}
1;
