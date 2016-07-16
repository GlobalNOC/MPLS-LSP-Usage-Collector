package GRNOC::MPLS::Collector;

use strict;
use warnings;

use Proc::Daemon;
use Parallel::ForkManager;
use Math::Round qw( nhimult );
use JSON;

use GRNOC::Log;
use GRNOC::Counter;
use GRNOC::WebService::Client;
use GRNOC::MPLS::Collector::Driver;

use Data::Dumper;

our $VERSION = '0.1.0';

use constant DEFAULT_PID_FILE => '/var/run/mpls-lsp-usage-collector.pid';
use constant MAX_RATE_VALUE => 9_007_199_254_740_992;

my $counter;
my $interval;
my $push_svc;
my $update_svc;
my %counter_keys = ();

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
	my $timestamp = nhimult($interval, $now);
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

sub _submit_data {
    my ($pid, $exit_code, $ident, $exit_signal, $core_dump, $data) = @_;
    my $node_name = $ident;

    if ($data) {
    	my $timestamp = $data->{'timestamp'};
	my $stats = $data->{'stats'};

    	foreach my $lsp (keys(%{$stats})) {
    	    my $key = "$node_name|$lsp|octets";
    	    if (!exists($counter_keys{$key})) {
    		$counter_keys{$key} = 1;
    		$counter->add_measurement($key, $interval, 0, MAX_RATE_VALUE);
    	    }

    	    my $octet_rate = $counter->update_measurement($key, $timestamp, $stats->{$lsp}->{'octets'});
    	    $octet_rate = ($octet_rate >= 0) ? $octet_rate : undef;

    	    $key = "$node_name|$lsp|packets";
    	    if (!exists($counter_keys{$key})) {
    		$counter_keys{$key} = 1;
    		$counter->add_measurement($key, $interval, 0, MAX_RATE_VALUE);
    	    }

    	    my $packet_rate = $counter->update_measurement($key, $timestamp, $stats->{$lsp}->{'packets'});
    	    $packet_rate = ($packet_rate >= 0) ? $packet_rate : undef;
	    
    	    my $msg = {};
    	    $msg->{'type'} = 'lsp';
    	    $msg->{'time'} = $timestamp;
    	    $msg->{'interval'} = $interval;
	
    	    my $meta = {};
    	    $meta->{'node'} = $node_name;
    	    $meta->{'lsp'} = $lsp;
    	    $msg->{'meta'} = $meta;
	    
    	    my $values = {};
    	    $values->{'state'} = $stats->{$lsp}->{'state'};
    	    $values->{'octets'} = $octet_rate;
    	    $values->{'packets'} = $packet_rate;
    	    $msg->{'values'} = $values;

    	    my $tmp = [];
    	    push(@$tmp, $msg);
    	    my $json_push = encode_json($tmp);
    	    my $res_push = $push_svc->add_data(data => $json_push);
    	    if (!defined $res_push) {
    		log_error("Could not post data to TSDS: " . $res_push->{'error'});
    		return; 
    	    }

    	    $msg = {};
    	    $msg->{'type'} = 'lsp';
    	    $msg->{'node'} = $node_name;
    	    $msg->{'lsp'} = $lsp;
    	    $msg->{'start'} = $timestamp;
    	    $msg->{'end'} = undef;
    	    $msg->{'destination'} = $stats->{$lsp}->{'from'};
    	    $msg->{'source'} = $stats->{$lsp}->{'to'};
    	    $msg->{'path'} = $stats->{$lsp}->{'path_name'};
	    
    	    $tmp = [];
    	    push(@$tmp, $msg);
    	    my $json_update = encode_json($tmp);
    	    my $res_update = $update_svc->update_measurement_metadata(values => $json_update);
    	    if (!defined $res_update) {
    		log_error("Could not post metadata to TSDS: " . $res_update->{'error'});
    		return;
    	    }
    	}
    }
}


sub _collect {
    my ($self) = @_;
    log_info("Collecting...");

    my $forker = Parallel::ForkManager->new($self->{'max_procs'});
    $forker->run_on_finish(\&_submit_data);
    
    foreach my $node (@{$self->{'nodes'}}) {
	$forker->start($node->{'name'}) and next;

	my $stats = $self->{'driver'}->collect_data({
	    node => $node,
						    });

	if (!defined $stats) {
	    log_error("Could not collect data on $node->{'name'}");
	    $forker-finish() and next;
	}

	$forker->finish(0, {stats => $stats->{'lsps'}, timestamp => $stats->{'timestamp'}});
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

    $interval = $config->get('/config/@interval');
    $interval //= 10;

    $self->{'max_procs'} = $config->get('/config/@max_procs');

    $push_svc = GRNOC::WebService::Client->new(
	url => $config->get('/config/@tsds_push_service') . "/push.cgi",
	uid =>  $config->get('/config/@tsds_user'),
	passwd => $config->get('/config/@tsds_pass'),
	realm => $config->get('/config/@tsds_realm'),
	usePost => 1
	);

    $update_svc = GRNOC::WebService::Client->new(
	url => $config->get('/config/@tsds_push_service') . "/admin.cgi",
	uid =>  $config->get('/config/@tsds_user'),
	passwd => $config->get('/config/@tsds_pass'),
	realm => $config->get('/config/@tsds_realm'),
	usePost => 1
	);

    $config->{'force_array'} = 1;
    $self->{'nodes'} = $config->get('/config/node');

    $self->{'driver'} = GRNOC::MPLS::Collector::Driver->new();

    $counter = GRNOC::Counter->new();
}
1;
