#!/usr/bin/perl -w

=head1 NAME

config.t

=head1 DESCRIPTION

test Net::Graylog::Client

=head1 AUTHOR

kevin mulholland, moodfarm@cpan.org

=cut

use v5.10;
use strict;
use warnings;

use Test::More tests => 4;

BEGIN { use_ok('Net::Graylog::Client'); }

# as most people will not have a graylog server to hand, there is not
# much we can test, except that the module compiles and has some of
# the expected methods, esp those that autoload

my $graylog = Net::Graylog::Client->new( url => 'http://localhost:1/gelf' );
isa_ok( $graylog, 'Net::Graylog::Client' );

# all of the levels should autoload
my @levels = Net::Graylog::Client::valid_levels();
my $lvls = 0 ;
foreach my $method ( @levels) {
  eval {
    $graylog->$method( message => 'message') ;
    $lvls++ ;   # if this was OK
  } ;
}
ok( $lvls == scalar( @levels), 'All autoload methods ok ' . $lvls . " vs " . scalar( @levels)) ;

# we should get a 500 code if we connect to an invalid url
my ( $status, $code ) = $graylog->send( message => 'message' );
ok( $code == 500, 'Failed to connect to server (as expected)')

# -----------------------------------------------------------------------------
# completed all the tests
