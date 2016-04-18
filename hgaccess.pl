#!/usr/bin/env perl
use strict;
use warnings;

use Cwd;
use File::Basename;
use File::Copy;
use File::Spec;
use File::Temp qw( tempfile );
use POSIX qw( strftime );

my $SKIP_BACKUP = 0;

my $AUTHKEYSFILE = File::Spec->catfile($ENV{HOME}, '.ssh', 'authorized_keys');
my $ADMINLIST = 'hgadmin.list';
my $NOADMINFILE = 0;

my $ADMINUSER = '';

my $SCRIPTNAME = basename $0;

my $DEBUGLOG = File::Spec->catfile($ENV{HOME}, '.hgaccess.debug.log');
my $ACTIONLOG = File::Spec->catfile($ENV{HOME}, '.hgactions.log');

# Subroutines

sub abort {
    my $msg = shift || 'Unknown error';
    print STDERR '=' x 72, "\n";
    print STDERR $msg, "\n";
    print STDERR '=' x 72, "\n";
    exit 255;
}

sub debug {
    return unless -f $DEBUGLOG;
    if (open(my $fh, '>>', $DEBUGLOG)) {
        my $timestamp = strftime("%Y-%m-%d-%H%M%S", localtime);
        print $fh "[DEBUG] $timestamp ", @_, "\n";
        close $fh;
    }
}

sub log_action {
    return unless -f $ACTIONLOG;
    if (open (my $fh, '>>', $ACTIONLOG)) {
        my ($action, $gate, $details) = @_;
        $gate ||= ''; $details ||= '';
        my $timestamp = strftime("%Y-%m-%d-%H%M%S", localtime);
        print $fh "$timestamp\t$action\t$gate\t$ADMINUSER\t$details\n";
        close $fh;
    }
}

sub load_admins {
    my $file = File::Spec->catfile($ENV{HOME}, $ADMINLIST);
    my %admins;
    if (open(my $fh, $file)) {
        while (<$fh>) {
            next if /^\s*$/;
            next if /^\s*#/;
            s/^\s*//;
            s/\s*$//;
            $admins{$_} = 1;
        }
        close $fh;
    } else {
        $NOADMINFILE = 1;
    }
    return \%admins;
}

# No dependencies on CPAN modules
sub load_conf {
    my $file = File::Spec->catfile($ENV{HOME}, 'hgaccess.conf');
    my %c;

    if (open(my $fh, $file)) {
        my $repo;
        while (<$fh>) {
            next if /^\s*$/;
            next if /^\s*#/;

            if (/^\s*\[(.*?)\]/) {
                $repo = $1;
                next;
            }

            if (/^\s*(.*?)=(.*)/) {
                my $key = $1;
                my $vals = $2;

                $key =~ s/\s*$//;
                $vals =~ s/^\s*//;
                $vals =~ s/\s*$//;

                my %vals;
                if (not $vals) {
                    $vals{'-'} = 1;
                } elsif ($vals =~ /^__ALL_/) {
                    $vals{'+'} = 1;
                }
                my $pref = ($vals =~ /^__ALL_EXCEPT__/ ? '-' : '');
                $vals =~ s/__.*?__\s*//;

                my %avals = map { ($pref . $_) => 1 } split(/\s*,\s*/, $vals);
                %vals = (%vals, %avals);

                $c{$repo}->{$key} = \%vals;
            }
        }
        close $fh;
    }
    return \%c;
}

sub is_repo {
    my $repo = shift;
    return -d File::Spec->catfile($ENV{HOME}, $repo, '.hg');
}

sub is_valid_user {
    my $user = shift;
    my %users = users_and_roles();
    return exists $users{$user};
}

my $__roles;
sub is_valid_role {
    my $role = shift;
    $__roles = load_conf() unless $__roles;
    return exists $__roles->{$role};
}

my $__admins;
my $__warnonce;
sub is_admin_user {
    if ($NOADMINFILE) {
        print STDERR "WARNING!!! $ADMINLIST not found. Treating all users as admins.\n"
            unless $__warnonce;
        $__warnonce = 1;
        return 1;
    }
    my $user = shift;
    $__admins = load_admins unless $__admins;
    return exists $__admins->{$user};
}

sub actions_for {
    my %p = @_;
    my $conf = $p{conf};
    my $role = $p{role};
    my $repo = $p{repo};

    my (%actions, $msg);
    $actions{$_} = 0 foreach (qw( read write ));

    if (not exists $conf->{$role}) {
        $msg = "Unknown role: $role";
    } elsif (not is_repo $repo) {
        $msg = "Unknown repo: $repo";
    } else {
        foreach my $action (qw( read write )) {
            if ($conf->{$role}->{$action}->{$repo}) {
                $actions{$action} = 1;
            } elsif ($conf->{$role}->{$action}->{'+'}) {
                $actions{$action} = 1 unless $conf->{$role}->{$action}->{"-$repo"};
            }
        }
    }

    return (\%actions, $msg);
}

sub cmd_for {
    my %p = @_;
    my $user = $p{user};
    my $roles = $p{role};
    my $repo = $p{repo};
    my $conf = $p{conf};

    my @cmd = ( 'hg', '-R', $repo, 'serve', '--stdio' );

    my (%actions, @msgs, $msg);
    $actions{$_} = 0 foreach (qw( read write ));

    my @roles = split(/\s*,\s*/, $roles);
    foreach my $role (@roles) {
        debug "User: $user, role=$role, repo=$repo";
        my ($acts, $msg) = actions_for(
            role => $role,
            repo => $repo,
            conf => $conf,
        );
        push(@msgs, $msg) if $msg;

        $actions{$_} |= $acts->{$_} foreach keys %$acts;
    }
    $msg = join("\n", @msgs);

    debug "Read access: $actions{read}, write access: $actions{write}";
    return ([], ($msg || 'Access denied')) unless $actions{read};

    if (is_locked($repo)) {
        my %users = gate_access($repo);
        $actions{write} = 0 unless exists $users{$user};
    }

    push(@cmd, (
            '--config', "hooks.prechangegroup.hgaccess='$0'",
            '--config', "hooks.prepushkey.hgaccess='$0'",
    )) unless $actions{write};

    #use Data::Dumper; debug(Dumper($actions));
    return (\@cmd, $msg);
}

sub lock_dir {
    my $repo = shift;
    abort "Repo not specified" unless $repo;
    my $repodir = File::Spec->catfile($ENV{HOME}, $repo);
    abort "Unknown repo: $repo" unless -d $repodir;

    my $lock_dir = $repodir . '.lock';
    return $lock_dir;
}

sub is_locked {
    my $repo = shift;
    my $is_locked = -d lock_dir($repo);
    debug "Repo locked: $is_locked" if $is_locked;
    return $is_locked;
}

sub gate_access {
    my $repo = shift;
    my $lock_dir = lock_dir $repo;
    return () unless is_locked $repo;

    opendir(my $dh, $lock_dir) or abort "Failed to open directory: $lock_dir";
    my @users = grep { /^[^\.]/ and -f "$lock_dir/$_" } readdir $dh;
    closedir $dh;
    return map { $_ => 1 } @users;
}

sub repo_list {
    opendir(my $dh, $ENV{HOME}) or abort "Failed to open home directory";
    my @dirs = grep { /^[^\.]/ and -d "$ENV{HOME}/$_" and is_repo($_) } readdir $dh;
    closedir $dh;
    return sort @dirs;
}

sub gate_status {
    my $repo = shift;
    abort "Usage: status <gate>" unless $repo;
    unless (is_locked $repo) {
        print "$repo: unlocked\n";
    } else {
        print "$repo: locked\n";
        my %users = gate_access $repo;
        print "`- push open for: ", join(', ', sort keys %users), "\n" if %users;
    }
}

sub lock_gate {
    my $repo = shift;
    abort "Usage: lock <gate>" unless $repo;
    abort "Gate already locked: $repo" if is_locked $repo;

    my $lockdir = lock_dir $repo;
    mkdir $lockdir or abort "Failed to create directory: $lockdir: $!";
    log_action('LOCK', $repo);
}

sub unlock_gate {
    my $repo = shift;
    abort "Usage: unlock <gate>" unless $repo;
    abort "Gate not locked: $repo" unless is_locked $repo;

    my %users = gate_access $repo;
    if (%users) {
        debug "Closing gate for users: ", join(', ', sort keys %users);
        close_gate($repo, keys %users);
    }

    my $lockdir = lock_dir $repo;
    debug "Unlocking gate: $repo";
    rmdir $lockdir or abort "Failed to remove directory: $lockdir";
    log_action('UNLOCK', $repo);
}

sub open_gate {
    my $repo = shift;
    abort "Usage: open <gate> <user> [<user>...]" unless $repo and @_;
    abort "Gate not locked: $repo" unless is_locked $repo;

    my $lockdir = lock_dir $repo;
    foreach my $user (get_usernames(@_)) {
        my $openfile = File::Spec->catfile($lockdir, $user);
        unless (-e $openfile) {
            print "Opening gate \"$repo\" for $user\n";
            open(my $fh, '>', $openfile) or die "Failed to create file: $openfile";
            close $fh;
            log_action('OPEN', $repo, $user);
        }
    }
}

sub close_gate {
    my $repo = shift;
    abort "Usage: close <gate> <user> [<user>...]" unless $repo and @_;
    abort "Gate not locked: $repo" unless is_locked $repo;

    my $lockdir = lock_dir $repo;
    foreach my $user (get_usernames(@_)) {
        my $openfile = File::Spec->catfile($lockdir, $user);
        next unless -e $openfile;
        print "Closing gate \"$repo\" for $user\n";
        unless (-f $openfile and -z $openfile) {
            abort "Unable to close gate for user: $user\nNot an empty file: $openfile"
        }
        unlink $openfile;
        log_action('CLOSE', $repo, $user);
    }
}

my %_users;
sub users_and_roles {
    if (not %_users) {
        open(my $fh, $AUTHKEYSFILE) or die "Failed to open file: $AUTHKEYSFILE";
        while (<$fh>) {
            next unless /^\s*command="(.*?)"/;
            my $command = $1;
            unless ($command =~ /\Q$SCRIPTNAME\E/) {
                debug "Ignoring line: $_";
                next;
            }
            my $user_role = (split(' ', $command))[1];
            debug "Got user:role = $user_role";
            my ($user, $role) = split(':', $user_role);
            $_users{$user} = [] unless exists $_users{$user};
            push(@{$_users{$user}}, $role);
        }
        close $fh;
    };
    return %_users;
}

sub known_users {
    my %users = users_and_roles;
    return sort keys %users;
}

sub match_usernames {
    my @patterns = @_;
    my %known_users = users_and_roles;
    my @sorted_names = sort keys %known_users;
    my @users;
    my @unknown;
    my %ambiguous;
    foreach my $pat (@patterns) {
        if (exists $known_users{$pat}) {
            push(@users, $pat);
        } else {
            my @matches = grep /\Q$pat\E/, @sorted_names;
            if (not @matches) {
                push(@unknown, $pat);
            } elsif (@matches > 1) {
                $ambiguous{$pat} = \@matches;
            } else {
                push(@users, $matches[0]);
            }
        }
    }
    return (\@users, \@unknown, \%ambiguous);
}

sub get_usernames {
    my ($users, $unknown, $ambiguous) = match_usernames(@_);
    if (@$unknown) {
        abort "Unknown user(s): " . join(', ', @$unknown);
    } elsif (%$ambiguous) {
        my $err;
        foreach my $pat (keys %$ambiguous) {
            $err .= "\n\t$pat: matches " . join(', ', @{ $ambiguous->{$pat} });
        }
        abort "Ambiguous username(s): $err";
    }
    return @$users;
}

sub list_users {
    my $pat = shift;
    my %users = users_and_roles;
    if ($pat) {
        foreach (keys %users) {
            delete $users{$_} unless /\Q$pat\E/;
        }
    }
    die "No users found matching pattern '$pat'\n" if not %users;

    my $fmt = "%-30s  %5s  %s\n";
    print "\n";
    printf($fmt, 'USER', 'ADMIN', 'ROLES');
    print '-' x 30, '  ', '-' x 5, '  ', '-' x 40, "\n";
    foreach my $user (sort keys %users) {
        my %roles;
        foreach my $rlist (@{ $users{$user} }) {
            foreach my $role (split(/\s*,\s*/, $rlist)) {
                $roles{$role}++;
            }
        }
        my $admin = (is_admin_user($user) ? '  X  ' : '');
        printf($fmt, $user, $admin, join(', ', sort keys %roles));
    }
    print "\n";
}

sub add_user {
    my $user = shift;
    my $roles = shift;
    my $key = join(' ', @_);
    if (not $user or not $roles or not $key) {
        abort "usage: adduser <user> <role>[,<role>...] <key>";
    }
    $roles =~ s/\s//g;

    abort "User exists: $user" if is_valid_user $user;
    foreach my $role (split(/\s*,\s*/, $roles)) {
        abort "Unknown role: $role" unless is_valid_role $role;
    }

    my ($fh, $filename) = tempfile;
    print $fh $key, "\n";
    close $fh;

    open(my $kgen, "ssh-keygen -l -f $filename 2>/dev/null |") or abort "Unable to validate key\n";
    my $fingerprint = <$kgen>; chomp $fingerprint;
    close $kgen;
    my $rc = $?;
    unlink $filename;
    abort "Invalid public key: $key" unless $rc == 0;

    # DOES NOT LOCK FILE!
    unless ($SKIP_BACKUP) {
        my $timestamp = strftime("%Y-%m-%d-%H%M%S", localtime);
        my $nfile = $AUTHKEYSFILE . '.' . $timestamp;
        copy($AUTHKEYSFILE, $nfile);
    }

    open(my $authfh, '>>', $AUTHKEYSFILE) or abort "Unable to open file: $AUTHKEYSFILE";
    print $authfh "command=\"$0 $user:$roles\",no-port-forwarding,no-x11-forwarding,no-agent-forwarding $key\n";
    close $authfh;

    log_action('ADD', '', "$user:$roles");

    print <<ADDUSER;

ADDED USER:
  username       : $user
  roles          : $roles
  key fingerprint: $fingerprint

ADDUSER
}

sub validate_users {
    my %users = users_and_roles;
    my $conf = load_conf;
    my %roles = map { $_ => 1 } keys %$conf;

    my $errors = 0;
    my $warnings = 0;
    foreach my $user (sort keys %users) {
        my $roles = $users{$user};
        if (@$roles > 1) {
            print "WARNING: Multiple entries for user: $user (roles: ", join(', ', @$roles), ")\n";
            $warnings++;
        }
        foreach my $rolelist (@$roles) {
            foreach my $role (split(/\s*,\s*/, $rolelist)) {
                unless (exists $roles{$role}) {
                    print "ERROR: Unknown role: $role (user: $user)\n";
                    $errors++;
                }
            }
        }
    }

    if (not $errors and not $warnings) {
        print "Config OK\n";
    } else {
        my @msg;
        push(@msg, "$errors error(s)") if $errors;
        push(@msg, "$warnings warning(s)") if $warnings;
        print "\n", join(', ', @msg), "\n";
    }
}

sub admin_help {
    print <<HELP;
ADMIN COMMANDS:
==============

- gates
  List available gates (repos).

- users [part-of-username]
  List known users.

- adduser <user> <role>[,<role>...] <public-key>
  Add a user to the access list (authorized_keys).

- validate
  Validate config (authorized_keys).

- status <gate>
  Report status of specified gate.

- lock <gate>
  Lock specified gate.

- unlock <gate>
  Unlock specified gate.

- open <gate> <user> [<user>...]
  Allow listed user(s) push access to locked gate.

- close <gate> <user> [<user>...]
  Revoke push access to locked gate for listed user(s).

- help
  Display this message.

NOTE: If no command is specified, the admin user is dropped into a shell.

HELP
}

sub admin_command {
    my $cmdline = shift;

    my @cmd = split(' ', $cmdline);
    my $cmd = shift @cmd;
    my $repo = shift @cmd;

    if ($cmd eq 'help') {
        admin_help;
        exit 0;
    } elsif ($cmd eq 'gates') {
        print join("\n", repo_list), "\n";
        exit 0;
    } elsif ($cmd eq 'users') {
        my $pat = $repo;
        list_users($pat);
        exit 0;
    } elsif ($cmd eq 'adduser') {
        my $user = $repo;
        add_user($user, @cmd);
        exit 0;
    } elsif ($cmd eq 'validate') {
        validate_users;
        exit 0;
    } elsif ($cmd eq 'status') {
        gate_status $repo;
        exit 0;
    } elsif ($cmd eq 'lock') {
        lock_gate $repo;
        gate_status $repo;
        exit 0;
    } elsif ($cmd eq 'unlock') {
        unlock_gate $repo;
        gate_status $repo;
        exit 0;
    } elsif ($cmd eq 'open') {
        open_gate $repo, @cmd;
        gate_status $repo;
        exit 0;
    } elsif ($cmd eq 'close') {
        close_gate $repo, @cmd;
        gate_status $repo;
        exit 0;
    } else {
        print "ERROR: Unknown command: $cmdline\n\n";
        admin_help;
        exit 1;
    }

    exit 0;
}

# Main

if (@ARGV < 1) {
    my $msg = "Access denied, read-only repository: ";

    my $repo = basename getcwd;
    my $lockdir = lock_dir($repo);
    $msg = "Access denied, gate locked: " if -e $lockdir;

    abort $msg . $repo;
}

my $conf = load_conf;
my $admins = load_admins;

#use Data::Dumper; debug Dumper $conf;

my ($user, $role) = split(':', shift);
if ($ENV{SSH_ORIGINAL_COMMAND}) {
    my @cmd = split(' ', $ENV{SSH_ORIGINAL_COMMAND});
    if ($cmd[0] eq 'hg') {
        my $repo = $cmd[2];
        if (not is_repo $repo) {
            # Convert fully-qualified repo path to one relative to $HOME
            debug "Attempting to extract repo name from path: $repo";
            if ($repo =~ qr|^\Q${ENV{HOME}}/\E(.*)|) {
                $repo = $1;
            } else {
                abort "Unknown repo: $repo";
            }
        }
        my ($run, $msg) = cmd_for(
            user => $user,
            repo => $repo,
            role => $role,
            conf => $conf,
        );
        $msg ||= '';
        debug "Command: \"", join(' ', @$run), "\" ($msg)";

        unless (@$run) {
            abort $msg if $msg;
            exit 255;
        }
        print STDERR $msg, "\n" if $msg;
        exec @$run;
    } else {
        my $is_admin = is_admin_user($user);
        debug('admin: ', ($is_admin ? 'yes' : 'no'));
        abort "Access denied, non-admin user: $user" unless $is_admin;
        $ADMINUSER = $user;
        admin_command($ENV{SSH_ORIGINAL_COMMAND});
    }
}

my $is_admin = is_admin_user($user);
debug('admin: ', ($is_admin ? 'yes' : 'no'));

if ($is_admin) {
    $ADMINUSER = $user;
    log_action('SHELL');
    print "(Launching shell for admin user $user)\n";
    $ENV{HGADMIN} = $user;
    exec "/bin/bash";
} else {
    print STDERR "Logins not allowed for user $user\n";
    exit 255;
}
