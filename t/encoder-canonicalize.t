#!/usr/bin/env perl
use strict;
use warnings;

use Test::More tests => 7;
use Try::Tiny;
use Test::MockObject;

my $esapi = Test::MockObject->new;
$esapi->set_isa('OWASP::ESAPI');

use_ok('OWASP::ESAPI::Reference::DefaultEncoder');

{
    package MockCodec;
    use Moose;

    extends 'OWASP::ESAPI::Codec';

    use MooseX::Params::Validate;

    has from => ( is => 'ro' );
    has to   => ( is => 'ro' );

    sub decode_character {
        my ($self, $input) = validated_list(\@_,
            input => { isa => 'ScalarRef[Str]' },
        );

        my $c = substr $$input, 0, 1, '';
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
    esapi  => $esapi,
    codecs => [
        MockCodec->new( from => 'c', to => 'd' ),
        MockCodec->new( from => 'a', to => 'b' ),
        MockCodec->new( from => 'b', to => 'c' ),
    ],

    # TODO Test logging
    # logger => ... mock logger ...,
);

try {
    my $encoded = $encoder->canonicalize({ input => 'abcd', strict => 1 });
    fail('canonicalize should have thrown an exception');
}
catch {
    isa_ok($_, 'OWASP::ESAPI::Exception');
    is($_->ident, 'input validation failure');
    is($_->tags, 'intrusion', 'tags is intrusion');
    is($_->message, 'mixed encoding (3) and multiple (4) detected in abcd', 
        'exception message is as expected');
    is_deeply($_->payload, 
        { found_count => 4, mixed_count => 3, input => 'abcd' }, 
        'exception payload is as expected');
};

try {
    my $encoded = $encoder->canonicalize({ input => 'abcd', strict => 0 });
    is($encoded, 'dddd', 'encoded to dddd');

    # TODO Test logging...
}
catch {
    fail("Should not have gotten exception: $_");
};
