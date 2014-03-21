# ABSTRACT: Client for Graylog2 analysis server


package Net::Graylog::Client;

use strict;
use warnings;
use POSIX qw(strftime);
use Data::Printer;
use Furl;
use JSON::Tiny;
use Sys::Hostname;
use Data::UUID;
use POSIX qw(strftime);
use Mo qw( default is required );    # not using (build builder coerce)
use namespace::clean;

use vars qw( @EXPORT @ISA);

# -----------------------------------------------------------------------------

@ISA = qw(Exporter);

# this is the list of things that will get imported into the loading packages
# namespace
@EXPORT = qw(
    valid_levels
    valid_facilities
);

# -----------------------------------------------------------------------------



has url       => ( is => 'ro', required => 1 );
has _uuid     => ( is => 'ro', init_arg => undef, default => sub { Data::UUID->new() }, );
has _hostname => ( is => 'ro', init_arg => undef, default => sub { hostname(); } );

# -----------------------------------------------------------------------------

# these are the syslog severity levels
my @msg_levels  = qw( emerg alert crit error warning notice info debug);
my $_mc         = 0;
my %msg_lvalues = map { $_ => $_mc++; } @msg_levels;

# some levels have alternate names
my %msg_tx = ( panic => 'emerg', err => 'error', warn => 'warning' );

my @msg_facilities = qw(
    kern user mail daemon auth syslog lpr news
    uucp clock authpriv ftp ntp audit alert cron
    local0 local1 local2 local3 local4 local5 local6 local7
);
my $_mf = 0;
my %msg_fvalues = map { $_ => $_mf++; } @msg_facilities;

# -----------------------------------------------------------------------------


sub send {
    my $self = shift;
    my (%data) = @_;

    # we add these fields so, we will report issues if they are passed
    # for some reason graylog accepts a message with a count field
    # but then silently discards it!
    map { die "Field '$_' not allowed" if ( $data{$_} ) } qw( uuid datetime timestr count);

    die "message field is required" if ( !$data{message} );

    $data{short_message} = $data{message};
    $data{uuid}          = $self->_uuid->create_str();
    $data{datetime}      = time();
    $data{timestr}       = strftime( "%Y-%m-%d %H:%M:%S", gmtime( time() ) );
    $data{host}          = $data{server} || $data{host} || hostname();

    # convert the level to match a syslog level and stop graylog fretting
    if ( defined $data{level} && $data{level} !~ /^\d+$/ ) {

        # convert the level into a number
        my $l = $data{level};

        # get the alternate name if needed
        $l = $msg_tx{ $data{level} } if ( $msg_tx{ $data{level} } );
        if ( defined $msg_lvalues{$l} ) {
            $data{level} = $msg_lvalues{$l};

            # also save as a string for user to reference
            $data{levelstr} = $l;
        }
    }

    # remove some entries we dont want
    map { delete $data{$_} if ( exists $data{$_} ); } qw( server message);

    # convert any floats into strings

    # foreach my $k ( keys %data) {
    #     # floating point numbers need to be made into strings
    #     if( $data{$k} =~ /^[0-9]{1,}(\.[0-9]{1,})$/) {
    #         $data{$k} = "" . $data{$k} ;
    #     }
    # }

    my $json = JSON::Tiny->new();
    my $furl = Furl->new(
        agent   => __PACKAGE__,
        timeout => 1,
    );

    my $status = $furl->post( $self->url, [ 'Content-Type' => ['application/json'] ], $json->encode( \%data ) );

    return ( $status->is_success, $status->code );
}

# -----------------------------------------------------------------------------


sub AUTOLOAD {

    # we use AUTOLOAD to handle some aliases for send

    # find out if this is a name we alias
    my $level = our $AUTOLOAD;
    $level =~ s/.*:://;    # strip the package name
    if ( !defined $msg_lvalues{$level} ) {
        die qq(Can't locate object method $level via package "@{[__PACKAGE__]}");
    }

    my $self   = shift;
    my %params = @_;

    # set the level field
    $params{level} = $level;

    # and perform the actual send
    return $self->send(%params);
}

# -----------------------------------------------------------------------------


sub valid_levels {
    return @msg_levels;
}

# -----------------------------------------------------------------------------


sub valid_facilities {
    return @msg_facilities;
}


# -----------------------------------------------------------------------------
1;

__END__

=pod

=encoding UTF-8

=head1 NAME

Net::Graylog::Client - Client for Graylog2 analysis server

=head1 VERSION

version 0.2

=head1 SYNOPSIS

  use Net::Graylog::Client ;
 
  my $log = Net::Graylog::Client->new( 'http://graylog.server:12002/gelf' ) ;

  $log->send( message => 'testing', level =< 'debug') ;

=head1 DESCRIPTION

Send a message to a graylog2 analysis server

You may send any data to a gray log server, but there are some restrictions plus this module
adds some defaults.

* There must be a message field
* a level field will be interpreted as a syslog level and converted to a number
    * you can access the original value with the levelstr field
* a datetime and timestr field are added, the former is a unix int timestamp, the latter a time string
* each message gets a uuid
* a server field will be reinterpreseted as a host field, a default of hostname() will be added if needed

=head1 NAME

Net::Graylog::Client

=head1 AUTHOR

 kevin mulholland

=head1 VERSIONS

v0.1  2014/03/19, initial work

=head1 Notes

Obviously if you just want oto do this on the command line you can use 

curl -XPOST http://graylog2_server:12202/gelf -p0 -d '{"short_message":"Hello there", "host":"example.org", "facility":"test", "_foo":"bar"}'

=head1 See Also

 Log::Log4perl::Layout::GELF , Net::Sentry::Client

=head1 Public Functions

=over 4

=item new

Create a new instance of the logger

    my $log = Net::Graylog::Client->new( 'http://graylog2_server:12202/gelf') ;

B<Parameters>
  url the url of the graylog server, of the form http://graylog2_server:12202/gelf

=item send

send a hash of data to the graylog server

    my $log = Net::Graylog::Client->new( 'http://graylog2_server:12202/gelf') ;
    $log->send( message => 'test message', level => 'info', elapsed = 12.1 )

Any data that is in the hash is passed to the server, though some may be re-interpreted
as mentioned in the DESCRIPTION

B<Parameters>
  hash of data to send

B><Returns>
    status - true = Sent, false = Failed
    code - HTTP response code from the graylog server

=item emerg alert crit error warning notice info debug

short cut to send, setting the syslog level to the name of the method

    my $log = Net::Graylog::Client->new( 'http://graylog2_server:12202/gelf') ;
    # level = alert
    $log->alert( message => 'test message', elapsed = 12.1 )
    # level = debug
    $log->debug( message => 'test message', elapsed = 12.1 )

Any data that is in the hash is passed to the server, though some may be re-interpreted
as mentioned in the DESCRIPTION

The level field is overwritten with the name of the method called

B<Parameters>
  hash of data to send

B><Returns>
    status - true = Sent, false = Failed
    code - HTTP response code from the graylog server

=item valid_levels

returns a list of the valid syslog levels

=item valid_facilities

returns a list of the valid syslog facilies

=back

=head1 AUTHOR

Kevin Mulholland <moodfarm@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2014 by Kevin Mulholland.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
