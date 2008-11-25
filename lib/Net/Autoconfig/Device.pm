package Net::Autoconfig::Device;

use 5.008008;
use strict;
use warnings;

use base "Net::Autoconfig";
use Log::Log4perl qw(:levels);
use Net::SNMP;
use Expect;
use Net::Ping;
use Data::Dumper;

our $VERSION = '1.01';

#################################################################################
## Constants and Global Variables
#################################################################################

use constant TRUE   =>  1;
use constant FALSE  =>  0;
use constant LONG_TIMEOUT   => 30;
use constant MEDIUM_TIMEOUT => 15;
use constant SHORT_TIMEOUT  =>  5;

use constant SSH_CMD    =>  "/usr/bin/ssh";
use constant TELNET_CMD =>  "/usr/bin/telnet";

# Default device parameters
use constant DEFAULT_INVALID_CMD_REGEX => '[iI]nvalid input';
use constant DEFAULT_SNMP_VERSION      => "2c";
use constant DEFAULT_ACCESS_METHOD     => "ssh";

####################
# device    =>  matching regex tables
####################
use constant SPECIFIC_DEVICE_MODEL_REGEX => {
    hp2626        =>    'Switch 2626\s',
    hp2650        =>    'Switch 2650\s',
    hp2626pwr     =>    'Switch 2626-PWR',
    hp2650pwr     =>    'Switch 2650-PWR',
    hp2512        =>    'Switch 2512',
    hp2524        =>    'Switch 2524',
    hp2824        =>    'Switch 2824',
    hp2848        =>    'Switch 2848',
    'hp2810-24g'  =>    'Switch 2810-24',
    'hp2810-48g'  =>    'Switch 2810-48',
    'hp2900-24g'  =>    'Switch 2900-24',
    'hp2900-48g'  =>    'Switch 2900-48',
    hp4104        =>    'Switch 4104',
    hp4108        =>    'Switch 4108',
    hp4208        =>    'Switch 4208',
    hp6108        =>    'Switch 6108',
    hub24         =>    'J2603A/B',
    hub48         =>    'J2603A ',
    c3550         =>    'C3550',
    c3560         =>    'C3560',
    c3750         =>    'C3750',
    c2960         =>    'C2960',
};

use constant GENERIC_DEVICE_MODEL_REGEX => {
    hp1600        =>    'Switch 16',
    hp2600        =>    'Switch 26',
    hp2500        =>    'Switch 25',
    hp2800        =>    'Switch 28(2|4)',
    hp2810        =>    'Switch 2810',
    hp2900        =>    'Switch 29',
    hp4100        =>    'Switch 41',
    hp4200        =>    'Switch 42',
    hp6100        =>    'Switch 61',
    hp4000        =>    'Switch 40',
    hp8000        =>    'Switch 80',
    hp224         =>    '1991-1994',
    hub           =>    'J2603A',
    c3xxx         =>    'C3(5|6|7)',
    c29xx         =>    'C29(5|6)',
};

use constant ALL_TYPES_MODEL_HASH => {
    hp1600        =>  'hp_switch',
    hp2600        =>  'hp_switch',
    hp2500        =>  'hp_switch',
    hp2800        =>  'hp_switch',
    hp2810        =>  'hp_switch',
    hp2900        =>  'hp_switch',
    hp4100        =>  'hp_switch',
    hp4200        =>  'hp_switch',
    hp6100        =>  'hp_switch',
    hp4000        =>  'hp_switch',
    hub           =>  'hp_hub',
    c3xxx         =>  'cisco_switch',
    c29xx         =>  'cisco_switch',
};

use constant VENDORS_REGEX => {
    HP            =>  '(?i:hp|Switch \d{3,4}|Hewlett)',
    Cisco         =>  '(?i:cisco|C\d{4})',
};

####################
# Expect Commands
####################

####################
# Expect Command Definitions
# These statements are strings, which need to be
# evaled within the methods to get their
# actual values.  This provides a way to pre-declare
# common expect commands without having to copy-paste
# them into each and every method that uses them.
# This incurs a performance hit, but I think its
# worth it.
#
# Yay!
####################

my $expect_show_version_cmd = '[
                            -re => "#",
                            sub
                            {
                                $session->clear_accum();
                                $session->send("show version\n");
                                sleep(1);
                            }
                        ]';
my $expect_ssh_key_cmd   = '[
                            -re => "continue connecting",
                            sub
                            {
                                $session->clear_accum();
                                $session->send("yes\n"); sleep(1);
                            }
                        ]';
my $expect_username_cmd  = '[
                            -re => "name:",
                            sub
                            {
                                $session->clear_accum();
                                $session->send($self->username . "\n");
                                sleep(1);
                            }
                        ]';
my $expect_password_cmd = '[
                            -re => "word[.:.]",
                            sub
                            {
                                $session->clear_accum();
                                $session->send($self->password . "\n");
                                sleep(1);
                            }
                        ]';
my $expect_hp_continue_cmd = '[
                            -re => "any key to continue",
                            sub
                            {
                                $session->clear_accum();
                                $session->send("\n");
                                sleep(1);
                            }
                        ]';
my $expect_exec_mode_cmd = '[
                            -re => ">",
                            sub
                            {
                                $session->clear_accum();
                                $session->send("\n");
                                sleep(1);
                                $connected_to_device = TRUE;
                            }
                        ]';
my $expect_priv_mode_cmd = '[
                            -re => "#",
                            sub
                            {
                                $session->clear_accum();
                                $session->send("\n");
                                sleep(1);
                                $self->admin_status(TRUE);
                                $connected_to_device = TRUE;
                            }
                        ]';
my $expect_enable_cmd = '[
                            -re => ">",
                            sub
                            {
                                $session->clear_accum();
                                $session->send("enable\n");
                                sleep(1);
                            }
                        ]';
my $expect_enable_passwd_cmd = '[
                            -re => "[Pp]assword:",
                            sub
                            {
                                $session->clear_accum();
                                $session->send($self->enable_password . "\n");
                                sleep(1);
                            }
                        ]';
my $expect_already_enabled_cmd = '[
                            -re => "#",
                            sub
                            {
                                $session->clear_accum();
                                $session->send("\n");
                                sleep(1);
                                $already_enabled = TRUE;
                            }
                        ]';
my $expect_initial_console_prompt_cmd = '[
                            -re => "how and erase",
                            sub
                            {
                                sleep(3);
                                $session->clear_accum();
                                $session->send("I\n");
                                sleep(1);
                                $expect->send("\r\n\r\n");
                                sleep(1);
                                $expect->send("\n");
                            }
                        ]';
# Compromise - set the length to 512
#     Cisco disable paging = set length to 0
#     HP    disable paging = set length to 1000
my $expect_disable_paging_cmd = '[
                            -re => "#",
                            sub
                            {
                                $session->clear_accum();
                                $session->send("terminal length 512\n");
                            }
                        ]';
my $expect_timeout_cmd = '[
                    timeout =>
                        sub
                        {
                            $command_failed = TRUE;
                        }
                    ]';

#################################################################################
# Methods
#################################################################################

############################################################
# Public Methods
############################################################

########################################
# new
# public method
#
# create a new Net::Autoconfig::Device object.
#
# If passed an array, it will assume those are key
# value pairs and assign them to the device.
#
# If no values are defined, then default ones are assigned.
#
# Returns:
#   A Net::Autoconfig::Device object
########################################
sub new {
    my $invocant = shift; # calling class
    my $class    = ref($invocant) || $invocant;
    my $self     = {
                    hostname            =>    "",
                    model               =>    "",
                    vendor              =>    "",
                    auto_discover       =>    TRUE,
                    admin_rights_status =>    FALSE,
                    console_username    =>    "",
                    console_password    =>    "",
                    username            =>    "",
                    password            =>    "",
                    enable_password     =>    "",
                    session             =>    undef,
                    snmp_community      =>    "",
                    snmp_version        =>    DEFAULT_SNMP_VERSION,
                    access_method       =>    DEFAULT_ACCESS_METHOD,
                    access_cmd          =>    SSH_CMD,
                    invalid_cmd_regex   =>    DEFAULT_INVALID_CMD_REGEX,
                    @_,
                    };
    my $log      = Log::Log4perl->get_logger('Net::Autoconfig');
    bless $self, $class;

    if ($log->is_trace())
    {
        $log->trace(Dumper($self));
    }

    $log->debug("Creating new device object");
    return $self->get('auto_discover') ? $self->auto_discover : $self;
}

########################################
# auto_discover
# public method
#
# Try to determine the make and model of the device.
# If it's possible, return a more specific device.
# Else, return itself (the old device)
########################################
sub auto_discover {
    my $self           = shift;
    my $vendor         = $self->vendor         || "";
    my $model          = $self->model          || "";
    my $snmp_community = $self->snmp_community || "";
    my $snmp_version   = $self->snmp_version   || "2c";
    my $session        = $self->session        || "";
    my $log            = Log::Log4perl->get_logger("Net::Autoconfig");
    my $device_type;   # The name of the module for that device.

    $log->debug("Auto-discovering device.");

    $device_type = $self->lookup_model();

    if (not $device_type)
    {
        $log->info("Using default device class for " . $self->hostname);
    }

    # Unset "auto_discover" so it doesn't try to recurse to infinity
    $self->set('auto_discover', FALSE);

    # Make a new object of the returned device type.
    # If we didn't get one, return the same object.
    if ($device_type)
    {
        eval "require $device_type;";
        if ($@)
        {
            $log->warn("Unable to load module: $device_type");
            return;
        }
        return $device_type->new( $self->get() );
    }
    else
    {
        return $self;
    }
}



########################################
# get
#
# return a value for a given attribute,
# or return all attributes as a hash or  hash ref
# if no value is passed.
########################################
sub get {
    my $self = shift;
    my @attribs = @_;
    my $ref = ref($self);
    my %data; 

    if (not @attribs)
    {
        %data = %{ $self };
    }
    elsif (scalar(@attribs) == 1)
    {
        return $self->{$attribs[0]};
    }
    else
    {
        foreach my $attrib (@attribs)
        {
            $data{$attrib} = $self->{$attrib};
        }
    }
    return wantarray ? %data : \%data;
}


########################################
#set()
#
# Set the value of an attribute.  If the attribute does not
# yet exist, create it.
# 
# Returns undef for success
# Returns TRUE for failure
############################################################
sub set {
    my $self = shift;
    my %attribs = @_;
    my $log = Log::Log4perl->get_logger(ref($self));

    foreach my $key ( keys %attribs )
    {
        $self->{$key} = $attribs{$key} || '';
    }

    return;
}


########################################
# Below are a set of accessor/mutator methods.
# They return or set values for the attribute specified
########################################
sub model {
    my $self = shift;
    my $model = shift;
    defined $model and $self->{'model'} = scalar $model;
    return defined $model ? undef : $self->{'model'};
}
sub vendor {
    my $self = shift;
    my $vendor = shift;
    defined $vendor and $self->{'vendor'} = scalar $vendor;
    return defined $vendor ? undef : $self->{'vendor'};
}
sub hostname {
    my $self = shift;
    my $hostname = shift;
    defined $hostname and $self->{'hostname'} = scalar $hostname;
    return defined $hostname ? undef : $self->{'hostname'};
}
sub username {
    my $self = shift;
    my $username = shift;
    defined $username and $self->{'username'} = scalar $username;
    return defined $username ? undef : $self->{'username'};
}
sub password {
    my $self = shift;
    my $password = shift;
    defined $password and $self->{'password'} = scalar $password;
    return defined $password ? undef : $self->{'password'};
}
sub provision {
    my $self = shift;
    my $provision = shift;
    defined $provision and $self->{'provision'} = scalar $provision;
    return defined $provision ? undef : $self->{'provision'};
}
sub admin_status {
    my $self = shift;
    my $admin_status = shift;
    defined $admin_status and $self->{'admin_status'} = scalar $admin_status;
    return defined $admin_status ? undef : $self->{'admin_status'};
}
sub console_username {
    my $self = shift;
    my $console_username = shift;
    defined $console_username and $self->{'console_username'} = scalar $console_username;
    return defined $console_username ? undef : $self->{'console_username'};
}
sub console_password {
    my $self = shift;
    my $console_password = shift;
    defined $console_password and $self->{'console_password'} = scalar $console_password;
    return defined $console_password ? undef : $self->{'console_password'};
}
sub enable_password {
    my $self = shift;
    my $enable_password = shift;
    defined $enable_password and $self->{'enable_password'} = scalar $enable_password;
    return defined $enable_password ? undef : $self->{'enable_password'};
}
sub snmp_community {
    my $self = shift;
    my $snmp_community = shift;
    defined $snmp_community and $self->{'snmp_community'} = scalar $snmp_community;
    return defined $snmp_community ? undef : $self->{'snmp_community'};
}
sub snmp_version {
    my $self = shift;
    my $snmp_version = shift;
    defined $snmp_version and $self->{'snmp_version'} = scalar $snmp_version;
    return defined $snmp_version ? undef : $self->{'snmp_version'};
}
sub session {
    my $self = shift;
    my $session = shift;
    defined $session and $self->{'session'} = scalar $session;
    return defined $session ? undef : $self->{'session'};
}

########################################
# access_method
# public method
#
# Set the access method to either ssh,
# telnet or something user defined.
# OR
# Get the access method if undef is passed
########################################
sub access_method {
    my $self = shift;
    my $access_method = shift;

    $access_method or $access_method = "";

    if ($access_method =~ /ssh/i)
    {
        $self->{'access_method'} = "ssh";
    }
    elsif ($access_method =~ /telnet/i)
    {
        $self->{'access_method'} = "telnet";
    }
    elsif ($access_method)
    {
        $self->{'access_method'} = "user_defined";
    }

    return $access_method ? undef : $self->{'access_method'};
}

########################################
# access_cmd
# public method
#
# Get the command to connect to the device.
# ssh and telnet are defined.  Anything else must
# have an absolute path or else it's ignored.
#
# Also set the access_method.  This can be
# overwritten.
#
# Specifying "ssh" or "telnet", without the
# absoluate path, will use the default
# ssh and telnet locations.
########################################
sub access_cmd {
    my $self = shift;
    my $access_cmd = shift;
    my $log = Log::Log4perl->get_logger("Net::Autoconfig");

    $access_cmd or $access_cmd = "";

    if ($access_cmd =~ /^ssh$/i)
    {
        $self->{'access_cmd'} = SSH_CMD;
    }
    elsif ($access_cmd =~ /^telnet$/i)
    {
        $self->{'access_cmd'} = TELNET_CMD;
    }
    elsif ($access_cmd =~ /^\/.+/)
    {
        $self->{'access_cmd'} = $access_cmd;
    }
    elsif ($access_cmd)
    {
        $log->warn($self->hostname . ": Access command, '$access_cmd', specified but not recognized.");
    }

    if ($access_cmd =~ /ssh/i)
    {
        $self->access_method('ssh');
    }
    elsif ($access_cmd =~ /telnet/i)
    {
        $self->access_method('telnet');
    }
    elsif ($access_cmd)
    {
        $self->access_method('user_Defined');
    }

    return $access_cmd ? undef : $self->{'access_cmd'};
}

########################################
# invalid_regex
# public
#
# Either get or set the regex that
# determines if a command was invalid
# or was not recognized by the device.
########################################
sub invalid_cmd_regex {
    my $self  = shift;
    my $regex = shift;
    defined $regex and $self->{'invalid_cmd_regex'} = $regex;
    return defined $regex ? undef : $self->{'invalid_cmd_regex'};
}

########################################
# connect
# public method
#
# Connect to a generic device using parameters
# specified in the device object, i.e.
# hostname, username and password.
#
# This expects to be overridden by a sub class
# E.g. Net::Autoconfig::Device::Cisco.
########################################
sub connect {
    my $self = shift;
    my $session;              # a ref to the expect session
    my $access_command;       # the string to use to the telnet/ssh app.
    my $result;               # the value returned after executing an expect cmd
    my @expect_commands;      # the commands to run on the device
    my $spawn_cmd;            # command expect uses to connect to the device
    my $log = Log::Log4perl->get_logger("Net::Autoconfig");

    $log->debug("Using default connect method.");

    # Expect success/failure flags
    my $connected_to_device;      # indicates a successful connection to the device
    my $command_failed;           # indicates a failed     connection to the device

    # Do some sanity checking
    if (not $self->hostname)
    {
        $log->warn("No hostname defined for this device.");
        return "No hostname defined for this devince.";
    }

    if (not $self->access_method)
    {
        $log->warn("Access method for " . $self->hostname . " not defined.");
        return "Access method not defined.";
    } 
    
    if (not $self->access_cmd)
    {
        $log->warn("Access command for " . $self->hostname . " not defined.");
        return "Access command not defined";
    }

    if (not $self->username)
    {
        $log->warn("No username defined.");
        return "No username defined.";
    }

    # Setup the access command
    if ($self->access_method =~ /^ssh$/)
    {
        $spawn_cmd = join(" ", $self->access_cmd, "-l", $self->username, $self->hostname);
    }
    else
    {
        $spawn_cmd = join(" ", $self->access_cmd, $self->hostname);
    }

    # Okay, let's get on with connecting to the device
    $session = $self->session;
    if (&_invalid_session($session))
    {
        $log->info("Connecting to " . $self->hostname);
        $log->debug("Using command '" . $self->access_cmd . "'");
        $log->debug("Spawning new expect session with: '$spawn_cmd'");

        if (&_host_not_reachable($self->hostname))
        {
            return "Failed " . $self->hostname . " not reachable via ping.";
        }

        eval
        {
            $session = new Expect;
            $session->raw_pty(TRUE);
            $session->spawn($spawn_cmd);
        };
        if ($@)
        {
            $log->warn("Connecting to " . $self->hostname . " failed: $@");
            return $@;
        }
    }
    else
    {
        $log->info("Session for ". $self->hostname . " already exists.");
    }

    # Enable dumping data to the screen.
    if ($log->is_trace() || $log->is_debug() )
    {
        $session->log_stdout(TRUE);
    }
    else
    {
        $session->log_stdout(FALSE);
    }

    ####################
    # Setup Expect command array
    #
    # The commands are defined for the class, but they need
    # to be eval'ed before we can use them.
    ####################
    # Setup the expect commands to do the initial login.
    # Up to four commands may need to be run:
    # accept the ssh key
    # send the username
    # send the password
    # verify connection (exec or priv exec mode)
    ####################
    push(@expect_commands, [
                            eval $expect_ssh_key_cmd,
                            eval $expect_username_cmd,
                            eval $expect_password_cmd,

                            # Check to see if we already have access
                            eval $expect_exec_mode_cmd,
                            eval $expect_priv_mode_cmd,
                    ]);
    # Handle some HP weirdness
    push(@expect_commands, [
                            # Get past the initial login banner
                            eval $expect_hp_continue_cmd,

                            eval $expect_username_cmd,
                            eval $expect_password_cmd,
                            eval $expect_exec_mode_cmd,
                            eval $expect_priv_mode_cmd,
                    ]);
    push(@expect_commands, [
                            eval $expect_username_cmd,
                            eval $expect_password_cmd,
                            eval $expect_exec_mode_cmd,
                            eval $expect_priv_mode_cmd,
                    ]);
    push(@expect_commands, [
                            eval $expect_password_cmd,
                            eval $expect_exec_mode_cmd,
                            eval $expect_priv_mode_cmd,
                    ]);
    push(@expect_commands, [
                            eval $expect_exec_mode_cmd,
                            eval $expect_priv_mode_cmd,
                    ]);

    foreach my $command (@expect_commands)
    {
        $session->expect(MEDIUM_TIMEOUT, @$command, eval $expect_timeout_cmd);
        if ($log->level == $TRACE)
        {
            $log->trace("Expect matching before: " . $session->before);
            $log->trace("Expect matching match : " . $session->match);
            $log->trace("Expect matching after : " . $session->after);
        }

        if ($connected_to_device)
        {
            $log->debug("Connected to device " . $self->hostname);
            $self->session($session);
            last;
        }
        elsif ($command_failed)
        {
            $self->error_end_session("Failed to connect to device " . $self->hostname);
            $log->debug("Failed on command: " , Dumper($command));
            last;
        }
    }

    return $connected_to_device ? undef : 'Failed to connect to device.';
}

########################################
# console_connect
# public method
#
# Connect to a console server for a given
# hostname. Assumes various characterisitics about
# the hostname and username + password
#
# After connecting to the console server,
# this then calls the normal connect method.
#
# At this point in time, this returns undef.
########################################
sub console_connect {
    my $self = shift;
    my $hostname;   # hostname of the console server
    my $tty;        # console port name
    my $username;   # console username
    my $session;              # a ref to the expect session
    my $access_command;       # the string to use to the telnet/ssh app.
    my $result;               # the value returned after executing an expect cmd
    my @expect_commands;      # the commands to run on the device
    my $spawn_cmd;            # command expect uses to connect to the device
    my $log = Log::Log4perl->get_logger("Net::Autoconfig");

    $log->debug("Using default console connect method.");

    # Expect success/failure flags
    my $connected_to_device;      # indicates a successful connection to the device
    my $command_failed;           # indicates a failed     connection to the device

    # Do some sanity checking
    if (not $self->hostname)
    {
        $log->warn("No hostname defined for this device.");
        return "No hostname defined for this devince.";
    }

    if (not $self->provision)
    {
        $log->warn("Device not configured for provisioning (console server) proceeding anyway.");
    }

    if (not $self->access_method)
    {
        $log->warn("Access method for " . $self->hostname . " not defined.");
        return "Access method not defined.";
    } 
    
    if (not $self->access_cmd)
    {
        $log->warn("Access command for " . $self->hostname . " not defined.");
        return "Access command not defined";
    }

    if (not $self->console_username)
    {
        $log->warn("No console user defined.");
        return "No console user defined.";
    }

    if (not $self->username)
    {
        $log->warn("No normal username defined.");
    }

    $username = $self->console_username;
    $self->hostname =~ /(\S*?)\@(\S*)/;
    $1 and $tty      = $1;
    $2 and $hostname = $2;

    # this could read (not $tty or not $hostname)
    if (not $tty or not $hostname)
    {
        $log->warn('Failed - Invalid tty@console hostname.');
        return 'Failed - Invalid tty@console hostname.';
    }

    $username = join(":", $self->console_username, $tty);

    # Setup the access command
    if ($self->access_method =~ /^ssh$/)
    {
        $spawn_cmd = join(" ", $self->access_cmd, "-l", $username, $hostname);
    }
    else
    {
        $spawn_cmd = join(" ", $self->access_cmd, $hostname);
    }

    # Okay, let's get on with connecting to the device
    $session = $self->session;
    if (&_invalid_session($session))
    {
        $log->info("Connecting to console " . $hostname);
        $log->debug("Using command '" . $self->access_cmd . "'");
        $log->debug("Spawning new expect session with: '$spawn_cmd'");

        if (&_host_not_reachable)
        {
            return "Failed $hostname not reachable via ping.";
        }

        eval
        {
            $session = new Expect;
            $session->raw_pty(TRUE);
            $session->spawn($spawn_cmd);
        };
        if ($@)
        {
            $log->warn("Connecting to " . $self->hostname . " failed: $@");
            return $@;
        }
    }
    else
    {
        $log->info("Session for ". $self->hostname . " already exists.");
    }

    # Enable dumping data to the screen.
    if ($log->is_trace() || $log->is_debug() )
    {
        $session->log_stdout(TRUE);
    }
    else
    {
        $session->log_stdout(FALSE);
    }

    ####################
    # Setup Expect command array
    #
    # The commands are defined for the class, but they need
    # to be eval'ed before we can use them.
    ####################
    # Setup the expect commands to do the initial login.
    # Up to four commands may need to be run:
    # accept the ssh key
    # send the username
    # send the password
    # verify connection (exec or priv exec mode)
    ####################
    push(@expect_commands, [
                            eval $expect_ssh_key_cmd,
                            eval $expect_password_cmd,
                       ]);
    # Handle some HP weirdness
    push(@expect_commands, [
                            eval $expect_password_cmd,
                            eval $expect_initial_console_prompt_cmd,
                       ]);
    push(@expect_commands, [
                            eval $expect_initial_console_prompt_cmd,
                            eval $expect_username_cmd,
                            eval $expect_password_cmd,
                            eval $expect_exec_mode_cmd,
                            eval $expect_priv_mode_cmd,
                       ]);
    push(@expect_commands, [
                            eval $expect_password_cmd,
                            eval $expect_exec_mode_cmd,
                            eval $expect_priv_mode_cmd,
                       ]);
    push(@expect_commands, [
                            eval $expect_exec_mode_cmd,
                            eval $expect_priv_mode_cmd,
                       ]);

    foreach my $command (@expect_commands)
    {
        $session->expect(MEDIUM_TIMEOUT, @$command, eval $expect_timeout_cmd);
        if ($log->level == $TRACE)
        {
            $log->trace("Expect matching before: " . $session->before);
            $log->trace("Expect matching match : " . $session->match);
            $log->trace("Expect matching after : " . $session->after);
        }
        if ($connected_to_device)
        {
            $log->debug("Connected to device " . $self->hostname);
            $self->session($session);
            last;
        }
        elsif ($command_failed)
        {
            $self->error_end_session("Failed to connect to device " . $self->hostname);
            $log->debug("Failed on command: " , Dumper($command));
            last;
        }
    }

    return $connected_to_device ? undef : 'Failed to connect to device.';
}

########################################
# configure
# public method
#
# This can be overwritten in submodules
# if necessary.
# E.g. Net::Autoconfig::Device::Cisco.
#
# Configure a device using the
# specified template.
#
# Template data should be in the form of
# a hash:
# $template_data = {
#   {cmds}    = [ {cmd 1}, {cmd 2}, {cmd 3} ]
#   {default} = { default data }
#
# Returns
#    success = undef
#    failure = Failure message.
########################################
sub configure {
    my $self          = shift;
    my $template_data = shift;
    my $session;      # the object's expect session
    my $error_cmd;    # expect cmd to see if a cmd was invalid
    my $error_flag;   # indicates if the command was invalid
    my $log           = Log::Log4perl->get_logger("Net::Autoconfig");
    my $last_cmd;     # record keeping for error reporting


    # Let's do some sanity checking
    if (not $template_data)
    {
        $log->warn("Failed - No template data");
        return "Failed - No template data";
    }

    if (&_invalid_session($self->session))
    {
        my $hostname = $self->hostname || "no hostname";
        $log->warn("Failed - No session for " . $hostname);
        return "Failed - No session for " . $hostname;
    }

    if (not $self->admin_status)
    {
        my $hostname = $self->hostname || "no hostname";
        $log->warn("Failed - do not have admin access to device.");
        return "Failed - do not have admin access to device.";
    }
    
    if (not exists $template_data->{default})
    {
        $template_data->{default} = {};
    }
    $session = $self->session;

    # Each cmd is a hash ref
    # Join it with the default data.  The cmd data
    # will overwrite the default data.  Yay!
    COMMAND:
    foreach my $cmd (@{ $template_data->{cmds} })
    {
        my $expect_cmd;        # the command to run on the CLI
        my $error_cmd;         # the cmd that detects an error/invalid command
        my $command_failed;    # a flag to indicate if the command failed
        my $timeout_cmd;       # what to do if there's a timeout

        # This is a perfance hit for each command.  Does it matter?
        if ($cmd->{required} )
        {
            $timeout_cmd = eval $expect_timeout_cmd;
        }
        else
        {
            undef $timeout_cmd;
        }

        $log->trace("Command: Regex   :" . $cmd->{regex});
        $log->trace("Command: Cmd     :" . $cmd->{cmd});
        $log->trace("Command: Timeout :" . $cmd->{timeout});
        $log->trace("Command: Required:" . $cmd->{required});

        VARIABLE_INTERPOLATION:
        {
            my $old_cmd = $cmd->{cmd};
            my $new_cmd = $old_cmd;
            # matches $variable_name; not \$variable_name
            # "-" counts as a word boundry, which is good for things like "range $a-$b"
            FIND_VARIABLE:
            while ($old_cmd =~ /[^\\]\$(\w+)/g)
            {
                my $replacement = $self->get($1);
                if (defined $replacement)
                {
                    $log->trace("Replacing '$1' with '$replacement' for cmd "
                                . "'$old_cmd' for device " . $self->hostname);
                    $new_cmd =~ s/\$$1/$replacement/;
                }
                else
                {
                    if ($cmd->{required})
                    {
                        my $message = "'$1' not defined for required command "
                                      . "'$old_cmd' for " . $self->hostname;
                        $self->error_end_session($message);
                        return "Command failed.";
                    }
                    else
                    {
                        $log->info("Skipping... ". "'$1' not defined for optinal command "
                                    . "'$old_cmd' for " . $self->hostname);
                        next COMMAND;
                    }
                }
            }
            # Since we escape the $s, remove the
            # escape characters.
            $new_cmd =~ s/\\\$/\$/g;
            if (not $new_cmd eq $old_cmd)
            {
                $cmd->{cmd} = $new_cmd;
            }
        }


        $error_cmd = [
                    -re =>  $self->invalid_cmd_regex,
                    sub
                    {
                        $log->warn("Invalid command entered! '$last_cmd'");
                        $command_failed = TRUE;
                    }
                    ];

        $expect_cmd = [
                    -re =>  $cmd->{regex},
                    sub
                    {
                        $session->clear_accum();
                        $session->send($cmd->{cmd} . "\n");
                    }
                    ];


        # Okay, send the command
        if ($cmd->{cmd} =~ /wait/i)
        {
            $session->expect($cmd->{timeout}, [ -re => "BOGUS REGEX" ] );
        }
        else
        {
            $session->expect($cmd->{timeout}, $error_cmd, $expect_cmd, $timeout_cmd);
        }

        $last_cmd = $cmd->{cmd};

        if ($command_failed)
        {
            # close session and alarm
            $self->error_end_session("Required command failed for " . $self->hostname);
            $log->debug(Dumper(%$cmd));
            return "Command failed.";
        }
    }

    # One last check to see if the last comand was invalid.
    # This is different than the one in the COMMAND loop
    # The Expect->expect method can't exit or return from _this_
    # method.  So, detect the error and do our own exiting.
    $error_cmd = [
                -re =>  $self->invalid_cmd_regex,
                sub
                {
                    $error_flag = TRUE;
                    $log->warn("Invalid command entered! '"
                    . $template_data->{cmds}->[-1]->{cmd}
                    . "'" 
                    );
                }
                ];
    
    if ($log->is_trace)
    {
        $log->trace( "Error command: " . Dumper($error_cmd) );
    }

    $session->expect(SHORT_TIMEOUT, $error_cmd );

    if ($error_flag)
    {
        $self->error_end_session("Last command entered was invalid for " . $self->hostname);
        return "Last command was invalid.";
    }

    $log->info("All commands executed successfullly for " . $self->hostname . ".");
    return;
}

########################################
# lookup_model
# public method
#
# Try to match the vendor and model device parameters against
# a lookup tableto see if the model and vendor can be discerned.
#
# See the defined constants at the beginning of the module for
# the definitions.
#
# Return the object name for the device.
########################################
sub lookup_model {
    my $self    = shift;
    my $class   = ref($self);
    my $log     = Log::Log4perl->get_logger($class);

    my $model   = $self->model   || '';
    my $vendor  = $self->vendor  || '';;
    my $models  = GENERIC_DEVICE_MODEL_REGEX;
    my $snmp_community = $self->snmp_community   || '';
    my $snmp_device_type;  # holds the output from the snmp query
    my $device_model;
    my $device_vendor;

    if ( $self->hostname)
    {
        $log->debug("Looking up device info (model/vendor).");
    }
    #else
    #{
    #    $log->info("Unable to deterine device type for "
    #                . "believed/assumed to be a default device");
    #    return $class;
    #}

    $self->identify_vendor;
    $self->identify_model;

    if ( $self->vendor )
    {
        $class = join('::', $class, $self->vendor );
        $log->debug("Found device model: $class");
    }
    else
    {
        $log->debug("Unable to determine device model.  Using $class.");
    }

    return $class;
}

########################################
# identify_vendor
# public method
#
# Lookup the device vendor.  Use (in order)
# one of the following methods.  Sets the
# vendor attribute of the device
#
# configured in device file
# snmp (sysDescr.0)
# console (show ver...doesn't always work)
#
# Returns:
#   success => undef
#   failure => error message
########################################
sub identify_vendor {
    my $self    = shift;
    my $log     = Log::Log4perl->get_logger( ref($self) );
    my $info;   # String to look at to determine the vendor
    my $vendor; # the name of the device vendor

    if ($self->vendor)
    {
        $log->debug("Vendor already defined for " . $self->hostname);
        $vendor = _get_vendor_from_string( $self->vendor );
        if ( not ($self->vendor eq $vendor) )
        {
            $self->vendor($vendor);
            $log->trace("Defined vendor incorrect.  Correcting...");
        }
        return;
    }
    elsif ($self->snmp_community)
    {
        $info = $self->snmp_get_description;
        $log->debug("Using snmp to determine vendor for " . $self->hostname);
    }
    elsif ($self->session)
    {
        $info = $self->console_get_description;
        $log->debug("Using terminal to determine vendor for "
                    . $self->hostname);
    }
    else
    {
        $log->info("Unable to determine the vendor for " . $self->hostname);
        return "Unable to determine the vendor.";
    }

    $info and $log->trace("Found snmp or console info: $info");

    $vendor = _get_vendor_from_string($info);

    if ($vendor)
    {
        $self->vendor($vendor);
    }

    return $info ? undef : "Unable to determine vendor.";
}

########################################
# identify_model
# public method
#
# Lookup the device model.  Use (in order)
# one of the following methods.  Sets the
# model attribute of the device
#
# configured in device file
# snmp (sysDescr.0)
# console (show ver...doesn't always work)
#
# Returns:
#   success => undef
#   failure => error message
########################################
sub identify_model {
    my $self    = shift;
    my $log     = Log::Log4perl->get_logger( ref($self) );
    my $info;   # String to look at to determine the model
    my $model;  # the device model

    if ($self->model)
    {
        $log->debug("Model already defined for " . $self->hostname);
        return;
    }
    elsif ($self->snmp_community)
    {
        $info = $self->snmp_get_description;
        $log->debug("Using snmp to determine model for " . $self->hostname);
    }
    elsif ($self->session)
    {
        $info = $self->console_get_description;
        $log->debug("Using terminal to determine model for "
                    . $self->hostname);
    }
    else
    {
        $log->info("Unable to determine the model for " . $self->hostname);
    }

    $model = _get_model_from_string($info);

    if ($model)
    {
        $self->model( $model );
    }

    return $model ? undef : "Unable to determine device model";
}

########################################
# snmp_get_description
# public method
#
# Get the sysDescr.0 from the device
#
# Returns:
#   success =>  the sysDescr.0 string
#   failure =>  undef
########################################
sub snmp_get_description {
    my $self         = shift;
    my $log          = Log::Log4perl->get_logger( ref($self) );
    my $snmp;        # snmp session
    my $snmp_error;  # the error from a snmp session
    my $snmp_vendor; # output from the snmp get request
    my $snmp_oid;    # oid of the attribute to get
    my $snmp_result; # the result of the snmp query

    $log->debug("Using snmp to determine the vendor.");
    ($snmp, $snmp_error) = Net::SNMP->session(
                        -hostname   =>  $self->hostname,
                        -version    =>  $self->snmp_version,
                        -community  =>  $self->snmp_community,
                    );
    if (not $snmp)
    {
        $log->warn("Error getting vendor using snmp connecting to "
                    . $self->hostname . " Error: $snmp_error");
    }

    # sysDescr.0
    $snmp_oid = '.1.3.6.1.2.1.1.1.0';

    $snmp_result = $snmp->get_request(
                        -varbindlist    =>  [ $snmp_oid ],
                        );

    if ($snmp_result)
    {
        $log->debug("snmp sysDescr.0 for " . $self->hostname . " was "
                    . $snmp_result->{$snmp_oid});
    }
    else
    {
        $log->warn("Unable to get the sysDescr via SNMP from "
                    . $self->hostname . " using community " . $self->community
                    . " with version " . $self->snmp_version);
    }

    return $snmp_result ? $snmp_result->{$snmp_oid} : undef;
}

########################################
# console_get_description
# public method
#
# Get the output from "show version"
# 
# Returns:
#   success =>  the result from "show version"
#   failure =>  undef
########################################
sub console_get_description {
    my $self = shift;
    my $log  = Log::Log4perl->get_logger( ref($self) );
    my $session = $self->session;
    my $command_failed;     # a flag to indicate success or failure of the command.
    my $result;             # the output from the show version command
    my $processed_result;   # massage the data to return meaningful data

    $log->debug("Using the CLI to determine the device model.");

    if ($session)
    {
        if (not $self->admin_status)
        {
            $self->get_admin_rights;
        }


        if ($self->admin_rights)
        {
            $session->expect(MEDIUM_TIMEOUT, [eval $expect_show_version_cmd ]
                                           ,  eval $expect_timeout_cmd);
            $session->expect(MEDIUM_TIMEOUT, []);
            $result = $session->after();
            
        }
    }

    if ($result =~ /[iI]mage\s*stamp/)
    {
        $processed_result = "HP";
    }
    elsif ($result =~ /cisco/i)
    {
        $processed_result = "Cisco";
    }
    else
    {
        $processed_result = "";
    }

    return $processed_result;
}


########################################
# get_admin_rights
# public method
#
# Tries to gain administrative privileges
# on the device.  Should work with both
# cisco and hp.
#
# Returns:
#   success = undef
#   failure = reason for failure (aka a true value)
########################################
sub get_admin_rights {
    my $self     = shift;
    my $session  = $self->session;
    my $password = $self->enable_password;
    my $log      = Log::Log4perl->get_logger("Net::Autoconfig");
    my $command_failed;       # indicates of the command failed.
    my $already_enabled;      # indicates if already in admin mode
    my @expect_commands;      # the commands to run on the device

    $log->debug("Using default get_admin_rights method.");

    # Do some sanity checking
    if (not $self->session)
    {
        $log->warn("No session defined for get admin rights.");
        return "No session defined for get admin rights.";
    }

    if ($self->admin_status)
    {
        $log->debug("Already have admin rights.");
        return;
    }

    ####################
    # Setup Expect command array
    #
    # The commands are defined for the class, but they need
    # to be eval'ed before we can use them.
    ####################
    # Setup the expect commands to get admin rights
    # send "enable"
    # send the enable password
    # verify priv mode
    ####################
    push(@expect_commands, [
                            eval $expect_enable_cmd,
                            eval $expect_already_enabled_cmd,
                    ]);
    push(@expect_commands, [
                            eval $expect_enable_passwd_cmd,
                    ]);
    push(@expect_commands, [
                            eval $expect_priv_mode_cmd,
                    ]);

    foreach my $command (@expect_commands)
    {
        $self->session->expect(MEDIUM_TIMEOUT, @$command, eval $expect_timeout_cmd);
        if ($command_failed) {
            $log->warn("Command failed.");
            $log->debug("Failed command(s): " . @$command);
            $self->admin_status(FALSE);
            return "Enable command failed.";
        }
        elsif ($already_enabled)
        {
            $log->info("Already have admin privileges");
            last;
        }
    }

    $self->admin_status(TRUE);
    return;
}

########################################
# disable_paging
# public method
#
# Disable terminal paging (press -Enter-
# to continue) messages.  They cause problems
# when using expect.
#
# Returns:
#   success = undef
#   failure = reason for failure

########################################
sub disable_paging {
    my $self = shift;
    my $session;         # the object's expect session
    my $log           = Log::Log4perl->get_logger("Net::Autoconfig");
    my $command_failed;  # a flag to indicate if the command failed
    my @commands;        # an array of commands to execute

    $session = $self->session;
    if (&_invalid_session($session))
    {
        return "Failed - session not defined";
    }

    $log->debug("Disabling paging");

    $session->expect(MEDIUM_TIMEOUT, eval $expect_disable_paging_cmd, eval $expect_timeout_cmd);
    if ($command_failed)
    {
        $log->warn("Failed to disable paging.  The rest of the configuration could fail.");
        return "Failed - paging command timed out";
    }

    $session->send("\n");

    $log->debug("Paging disabled.");

    return;
}

########################################
# end_session
# public method
#
# If the device has a valid session,
# end it.
#
# Returns undef
########################################
sub end_session {
    my $self = shift;
    my $log  = Log::Log4perl->get_logger("Net::Autoconfig");

    if ($self->session)
    {
        $log->info("Terminating session for '" . $self->hostname . "'");
        $self->session->soft_close();
        $self->session(FALSE);
    }
    else
    {
        $log->info("No session to terminate for '" . $self->hostname . "'");
    }
    return;
}

########################################
# error_end_session
# public method
#
# Terminate a session due to an error.
# Mainly it has different logging options
# than the normal end_session method
#
# Takes:
#   A string to output to the log.
#
# Returns undef
########################################
sub error_end_session {
    my $self = shift;
    my $message = shift;
    my $log  = Log::Log4perl->get_logger("Net::Autoconfig");

    if (defined $message)
    {
        $log->warn($self->hostname, " - $message");
    }

    if ($self->session)
    {
        $log->warn("Terminating session for '" . $self->hostname . "'");
        $self->session->soft_close();
        $self->session(FALSE);
    }
    else
    {
        $log->info("No session to terminate for '" . $self->hostname . "'");
    }
    return;
}

########################################


############################################################
# Private Methods
############################################################

########################################
# _host_not_reachable
# private method
#
# Ping the specified hostname / ip address.
# 
# Returns
#   success = FALSE
#   failure = TRUE
########################################
sub _host_not_reachable {
    my $hostname = shift;
    my $log      = Log::Log4perl->get_logger("Net::Autoconfig");
    my $ping;    # Ping object

    if (not $hostname)
    {
        $log->warn("No hostname defined.");
        return TRUE;
    }

    $ping = eval { Net::Ping->new( $> ? "tcp" : "icmp" ) };
    if ($@)
    {
        $log->error("Net::Ping Failed - $@");
        $log->error("Connection to '$hostname' failed.");
        return TRUE;
    }
        
    if ($ping->ping($hostname))
    {
        $log->debug("'$hostname' is reachable via ping.");
        return FALSE;
    }
    else
    {
        $log->warn("Ping failed - '$hostname' not reachable via ping.");
        return TRUE;
    }
}



########################################
# _get_vendor_from_string
# private method
#
# Given a string, search through it
# to determine the manufacturer of the
# device.  The output of "show version"
#
# Example:
#   
#   $show_ver = "Cisco Systems, C3560E 12.2(46)SE...."
#   $vendor = _get_model_from_string($show_ver)
#
# Returns:
#   success - The name of the vendor
#   failure - undef
########################################
sub _get_vendor_from_string {
    my $string         = shift;
    my $vendors        = VENDORS_REGEX;      # a string that holds the vendor
    my $device_model;  # a string that links to the module for that device type
    my $log            = Log::Log4perl->get_logger("Net::Autoconfig");

    foreach my $vendor_key (keys %$vendors)
    {
        my $regex = $vendors->{$vendor_key};
        if ($string =~ /$regex/)
        {
            $log->trace("Vendor matched: $regex => $vendor_key");
            $device_model = $vendor_key;
            last;
        }
    }

    if ($device_model)
    {
        $log->debug("Got vendor: $device_model");
    }
    else
    {
        $log->debug("Failed to get vendor.");
    }

    return $device_model ? $device_model : undef;
}

########################################
# _get_model_from_string_
# private method
#
# Given a string, search through it
# to determine the model of the
# device.  Can be the output from show
# version (cisco devices), or snmp (sysDescr.0)
#
# Example:
#   
#   $show_ver = "Cisco Systems, C3560E 12.2(46)SE...."
#   $vendor = _get_model_from_string($show_ver)
#
# The returned array or array ref contains
# all of the different model types that
# this devices matches.  This makes it so
# you can specify all switches, or hp2600
# or hp2626 in the template file and it will
# use the right template.
#
# Returns:
#   success
#       Scalar context = array ref
#       Array context  = array
#   failure - undef
########################################
sub _get_model_from_string {
    my $string          = shift;
    my $specific_models = SPECIFIC_DEVICE_MODEL_REGEX;
    my $generic_models  = GENERIC_DEVICE_MODEL_REGEX;
    my $all_types       = ALL_TYPES_MODEL_HASH;
    my $models          = []; # The array ref of models this device matches
    my $log             = Log::Log4perl->get_logger("Net::Autoconfig");

    if (not $string)
    {
        $log->debug("No or false string passed.");
        return undef;
    }

    SPECIFIC_MODEL:
    foreach my $model (keys %$specific_models)
    {
        my $regex = $specific_models->{$model};
        if ( $string =~ qr($regex) )
        {
            $log->debug("Found specifc model: $model");
            push(@$models, $model);
            last SPECIFIC_MODEL;
        }
    }

    GENERIC_MODEL:
    foreach my $model (keys %$generic_models)
    {
        my $regex = $generic_models->{$model};
        if ( $string =~ qr($regex) )
        {
            $log->debug("Found generic model: $model");
            push(@$models, $model);
            last GENERIC_MODEL;
        }
    }

    # Sanity checking
    if (not @$models)
    {
        $log->debug("Unable to determine model for '$string'");
        return undef;
    }

    # Look for the most generic model type
    # It should be the last one on the list
    if ( $all_types->{ $models->[-1] } )
    {
        my $type = $all_types->{ $models->[-1] };
        $log->debug("Found generic model: $type");
        push( @$models, $type );
    }
    return wantarray ? @$models : $models;
}

########################################
# _invalid_session
# private method
#
# Determine if this is a valid session.
# We're using expect, so it has to be an
# expect object reference, and it has to
# be defined.
#
# Returns:
#   true if invalid
#   undef if valid
########################################
sub _invalid_session {
    my $session = shift;

    if (not defined $session)
    {
        return TRUE;
    }
    
    if (not ref($session))
    {
        return TRUE;
    }
    
    if (not ref($session) eq 'Expect')
    {
        return TRUE;
    }
    else
    {
        return;
    }
}




########################################
# _is_ip_addr
# private method
#
# Test to see if a string is an ip address.
# Returns:
#   True if it is (or looks like it is)
#   False if it is not.
########################################
sub _is_ip_addr {
    my $ip_addr = shift;

    $ip_addr or return FALSE;

    if ($ip_addr =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/)
    {
        # It slooks like it's valid, let's check and see
        foreach my $octet ($1, $2, $3, $4)
        {
            ($octet > 255) and return FALSE;
            ($octet < 0) and return FALSE;
        }
    }
    else
    {
        return FALSE;
    }

    return TRUE;
}

########################################
# _prefix_to_netmask
#
# Given a prefix, return the corresponding
# netmask. 
#
# Returns:
#   netmask upon success
#   undef   upon failure
########################################
sub _prefix_to_netmask {
    my $prefix = shift;
    my $prefix_octets;
    my $prefix_remainder;
    my @netmask;

    ($prefix) or return;
    ($prefix =~ /\/\d{1,2}$/) or return;

    $prefix =~ s/\///;

    $prefix_octets = int($prefix / 8);
    $prefix_remainder = ($prefix % 8);

    my $prefix_values = {
                0   =>  "0",
                1   =>  "128",
                2   =>  "192",
                3   =>  "224",
                4   =>  "240",
                5   =>  "248",
                6   =>  "252",
                7   =>  "254",
                8   =>  "255",
                };

    foreach my $octet (1..4)
    {
        if ($prefix_octets > 0)
        {
            $prefix_octets--;
            push(@netmask, $prefix_values->{8});
        }
        elsif ($prefix_remainder)
        {
            push(@netmask, $prefix_values->{$prefix_remainder});
            $prefix_remainder = 0;
        }
        else
        {
            push(@netmask, $prefix_values->{0});
        }
    }
    return
        wantarray ? @netmask : join(".", @netmask);
}


########################################
# _netmask_to_prefix
#
# Given a netmask, return the corresponding
# prefix "/\d{1,2}"
#
# Returns:
#   prefix  upon success
#   undef   upon failure
########################################
sub _netmask_to_prefix {
    my $netmask = shift;
    my @netmask;         # the octets of the netmask
    my $prefix = 0;      # the prefix form of the netmask
    my $log = Log::Log4perl->get_logger('Net::Autoconfig');

    my %netmask_values = {
            255 =>  "8",
            254 =>  "7",
            252 =>  "6",
            248 =>  "5",
            240 =>  "4",
            224 =>  "3",
            192 =>  "2",
            128 =>  "1",
            0   =>  "0",
            };
    
    if (! $netmask)
    {
        $log->info("No netmask was specified.");
        return;
    }

    @netmask = split(/\./, $netmask);

    if ( @netmask != 4)
    {
        $log->info("Invalid netmask. '" . $netmask . "'");
        return;
    }

    foreach my $octet (@netmask)
    {
        ($octet > 255) and $log->info("Netmask octect > 255");
        ($octet < 0)   and $log->info("Netmask octect < 0");
            
        $prefix += $netmask_values{$octet};
    }
    return $prefix;
}


# Modules must return true.
TRUE;


__END__

############################################################
# Documentation
############################################################

=head1 NAME

Net::Autoconfig - Perl extension for provisioning or reconfiguring network devices.

=head1 SYNOPSIS

  use Net::Autoconfig::Device;

  %data = (
            hostname => dev1,
            username => user1,
            password => pass1,
            enable_password => enable1,
            snmp_community  => public1,
            snmp_version    => 2c,
          );
  $device = Net::Autoconfig::Device->new(%data);
  $device = Net::Autoconfig::Device->new();

  $device->hostname("device1");
  $device->set('fu' => 'bar');
  $device->set(%data);

  $hostname = $device->hostname
  $hostname = $device->get("hostname");

  %all_device_data = $device->get;

  There are a lot of built-in access/mutator methods.  Beyond
  those values, you can add whatever you want to the
  device object.

=head1 DESCRIPTION

Net::Autoconfig uses the concept of devices.  Each device
contains all relevent information internally.  By default,
the device type/model/vendor is discovered automatically.
If there is a specific module for that paticular vendor/model,
then that module will be used.  If not, then it will use the
default methods contained in this module.

=head1 Methods

=head2 Public Methods

=over

=item new()

Creates a new Net::Autoconfig::Device object.
Additional info can be configured after the object has been created.
Pass an array with ( key1 => value1, key2 => value2, ...) to initialize
the object with those key values.

 Default values:
 auto_discover      = TRUE
 snmp_version       = 2c
 access_method      = ssh
 access_cmd         = /usr/bin/ssh
 invalid_cmd_regex  = '[iI]nvalid command'

=item autodiscover()

Enabled by default.  Can be disabled by setting
C<'auto_discover' = FALSE> (0, "", etc)

Try to discover the vendor and model number of the device.
It uses the following (in order) to determine the device type:
 1. if vendor and model are specified in the device config file
 2. if a snmp community is specified, it will use that (preferred method)
 3. if a session is open to the device, use the CLI (intermittent)

=item get()

Get the value of the specified attribute, or get a hash ref of all of
the attribute => value pairings.  This provides a mechanism for getting
attributes that are either part of the module, or that you have defined.
Returns undef if an attribute does not exist.

=item set()

Set the value of an attribute.  If the attribute does not
yet exist, create it.

This method is used by passing an array to the method.  The
method then adds/overwrites existing key => value pairs
to the object.  You can create or modify any variable inside
the object using this method.

Returns undef for success
Returns TRUE for failure

=item I<accessor/mututaor methods>

If any of these methods are passed C<undef>, then the value
for that variable is returned.  If passed anything that is not
undef, then set the device variable to that.  Some of these
methods do some sanity checking, other allow you to set the
values to whatever you want.

=over

=item model()

=item vendor()

=item hostname()

=item username()

=item password()

=item provision()

=item admin_status()

=item console_username()

=item enable_password()

=item snmp_community()

=item snmp_version()

=item session()

=item access_method()

=item access_cmd()

=back

=item disable_paging()

Attempts to disable the pagination of command output.  I.e.
having to hit the spacebar to see the next chunk of the output.
Script don't interact will with paginated data.  This method
tries a compromise, it will not work as well as an overloaded
method in a sub-class.

=item end_session()

Terminates the session.

=item error_end_session($error_message);

Terminates the session and gives an error message that
you specify.

=item lookup_model()

This trys to determine the vendor and  model of the device.  This
is usually called from C<auto_discover()>.  B<If auto_discover is not false,
then this will cause a loop.>

Returns the vendor specific module, or "Net::Autoconfig::Device"
if nothing more specific is found.

=item identify_vendor()

This method actually calls does the heavy lifting of determining the
device type.  It sets the vendor variable of the device.

Returns:
 Success = undef
 Failure = error message

=item identify_model()

This method actually calls does the heavy lifting of determining the
device model(s).  It sets the device model to an array ref containing
all device models that this device matches.  The list goes from
most specific to least specific.

Example:
 [ 'hp2626' 'hp2600' 'hp_switch' ]

Returns:
 Success = undef
 Failure = error message

=item snmp_get_description()

Uses SNMP to get the sysDescr from the device.

Returns:
 success = the output/string from the system description
 failure = undef

=item console_get_description()

Uses the cli (if a session exists) to get some information
about the device.  It parses the data and returns something
useful that the C<identify_vendor> and C<identify_model> methods
can use.

Returns:
 success = a string that can identify the device
 failure = undef

=item connect()

Will try to connect to a device using default methods. This method
should be overloaded by a sub class.  It tries to take into account
the idiosyncrasies of both HP and Cisco switches, but it could fail.

=item console_connect()

Will try to connect to a console server.  Assumes the  hostname is
in the following format:

 terminal_line@console_server_hostname

This procedure works for Avocent Cyclades console servers.
This will connect to the console server using (ssh or telnet):

 ssh -l username:termineal_line console_server_hostname

You should call C<connect()> after using this method.

=item get_admin_rights()

This method tries to gain administrative rights on the device.
(aka enable mode).  It works for both Cisco and HP devices,
but the overridden methods in the sub-classes have a higher
percentage chance of working.

=item configure()

Given a configruration in a template file, execute the
commands on the CLI using Expect.  Using the given command
template, configure the device.

 $template = Net::Autoconfig::Template->new("filename");
 $device->configure( $template->{$device->model} );
 $device->configure( $template->{$device->hostname} );

It will notify you (via the logs) if a specific command
failed to execute correctly.  If a command does not
execute correctly, it disconnects from that device.
If an optional command fails, it notifys you, but continues
execute commands on the device.

Returns:
 success = undef
 failure = TRUE

=item access_method()

If ssh or telnet are passed, then it sets the method to
C<ssh> or C<telnet>.  If anything else is passed, it
sets the method to C<user_defined>.

=item access_cmd()

Checks to see if the passed value is ssh, telnet or
something else that has an absolute path.  If ssh
or telnet are passed, the default locations for these
are used, C</usr/bin/ssh> or C</usr/bin/telnet>.
If the absolute file path is specified, use that instead.

This will also set the access method to ssh, telnet or
user defined.  If a non-standard ssh or telent location
is specified, it will still set the method to ssh or
telnet.  If it is something else, then it will set the
method to user defined.

=back

=head1 Device File Format (Colon Format)

The file format used for describing objects was created by
me, with commentary and input of Stephen Fromm, to be easy
to type and readable.  All "commands" are sandwitched between
colons, ":", hense the name, "colon format".

Devices or default devices begin with "default" or the
name of the device.  The device ends with a C<:end:> statement.
There must be an C<:end:> statement per device/default definition.
Any subsequent device or default statement overrides the previous
one.  I.e. you can start with one default statement, define
some devices, define a new default, and then define some more
devices.  You can manually set the hostname C<hostname = blah>
or it will take the part between the colons and use that as
the hostname.  You decide.

Whitespace is irrelavent if it comes at the beginning or end
of a line.  I.e. if you want to use tabs to make the definitions
look pretty, go ahead.  If you want to line-up the "=" signs,
go ahead.

Example:
 :default:
   netmask            = 255.255.255.0
   username           = some_user
   password           = some_password
   enable_password    = secret_password
   snmp_community     = public
   access_vlan        = 10
   voice_vlan         = 20
   mgmt_vlan          = 30
 :end:

 :cisco_switch_1:
 :end:

 :cisco_switch_1:
 model = c2960
 :end:

 :hp_switch_1:
 some_crazy_variable = some_crazy_value
 :end:

=head1 SEE ALSO

    Net::Autoconfig

=head1 AUTHOR

Kevin Ehlers E<lt>kevin@uoregon.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008 by Kevin Ehlers, University of Oregon.
All rights reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=head1 DISCLAIMER OF WARRENTY

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE
LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR
OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS
TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM
PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR
OR CORRECTION.

=cut

