#!/usr/bin/env perl
use strict;
use warnings;

use Test::More tests => 7;
use Try::Tiny;

use_ok('OWASP::ESAPI::Reference::DefaultEncoder');

{
    package MockCodec;
    use Moose;

    extends 'OWASP::ESAPI::Codec';

    has from => ( is => 'ro' );
    has to   => ( is => 'ro' );

    sub encode_character {
        my ($self, $immune, $c) = @_;
        if ($c eq $self->from) {
            return $self->to;
        }
        else {
            return $c;
        }
    }
}

# TODO Use OWASP::ESAPI to fetch this...
my $encoder = OWASP::ESAPI::Reference::DefaultEncoder->new(
    codecs => [
        MockCodec->new( from => 'c', to => 'd' ),
        MockCodec->new( from => 'a', to => 'b' ),
        MockCodec->new( from => 'b', to => 'c' ),
    ],

    # TODO Test logging
    # logger => ... mock logger ...,
);

try {
    my $encoded = $encoder->canonicalize('abcd', { strict => 1 });
    fail('canonicalize should have thrown an exception');
}
catch {
    isa_ok($_, 'OWASP::ESAPI::Exception');
    is($_->ident, 'input validation failure');
    is_deeply($_->tags, [ 'intrusion' ], 'tags is intrusion');
    is($_->message, 'Multiple (3) and mixed encoding (3) detected in abcd.', 
        'exception message is as expected');
    is_deeply($_->payload, 
        { found_count => 3, mixed_count => 3, input => 'abcd' }, 
        'exception payload is as expected');
};

try {
    my $encoded = $encoder->canonicalize('abcd', { strict => 0 });
    is($encoded, 'dddd', 'encoded to dddd');

    # TODO Test logging...
}
catch {
    fail("Should not have gotten exception: $_");
};