#!/usr/bin/env perl
use strict;
use warnings;

use Test::More tests => 22;
use Test::MockObject;
use Moose::Util::TypeConstraints;
use Try::Tiny;

use_ok('OWASP::ESAPI::Reference::Validation::StringValidationRule');

my $esapi = Test::MockObject->new;
$esapi->set_isa('OWASP::ESAPI');

{
    my $rule = OWASP::ESAPI::Reference::Validation::StringValidationRule->new(
        esapi => $esapi,
        type  => 'Str',
    );

    my $value = $rule->get_valid(
        context => '',
        input   => 'no frills !@#$%^&*()',
    );

    is($value, 'no frills !@#$%^&*()', 'Str validation is pointless');
}

{
    subtype 'Letters'
        => as 'Str'
        => where { /^[a-zA-Z]*$/ };

    my $rule = OWASP::ESAPI::Reference::Validation::StringValidationRule->new(
        esapi => $esapi,
        type  => 'Letters',
    );

    try {
        $rule->get_valid(context => '', input => 'Magnum44');
        fail('expected exception to be thrown');
    }
    catch {
        is($_->ident, 'validation exception', 'got a validation exception');
        like($_->message, qr{: }, 'message contains a ": "');
    };

    is($rule->get_valid(context => '', input => 'MagnumPI'), 'MagnumPI', 'MagnumPI is valid');
}

{
    try {
        my $rule = OWASP::ESAPI::Reference::Validation::StringValidationRule->new(
            esapi => $esapi,
            type  => 'Undef',
        );
        fail('expected exception to be thrown');
    }
    catch {
        is($_->ident, 'type is not a type of must_subtype', 'got an exception setting type to Undef');
    };
}

{
    subtype 'NoAngleBrackets'
        => as 'Str'
        => where { not /[<>]/ };

    my $rule = OWASP::ESAPI::Reference::Validation::StringValidationRule->new(
        esapi => $esapi,
        type  => 'NoAngleBrackets',
    );

    try {
        $rule->get_valid(context => '', input => 'beg <script> end');
        fail('expected exception to be thrown');
    }
    catch {
        is($_->ident, 'validation exception', 'got a validation exception');
        like($_->message, qr{: }, 'message contains a ": "');
    };

    is($rule->get_valid(context => '', input => 'beg script end'), 'beg script end', 'beg script end is valid');
}

{
    subtype 'NotShorterThan2_NotLongerThan12'
        => as 'Str'
        => where { length $_ >= 2 and length $_ <= 12 };

    my $rule = OWASP::ESAPI::Reference::Validation::StringValidationRule->new(
        esapi => $esapi,
        type  => 'NotShorterThan2_NotLongerThan12',
    );

    ok($rule->is_valid(context => '', input => '12'), '12 is valid');
    ok($rule->is_valid(context => '', input => '123456'), '123456 is valid');
    ok($rule->is_valid(context => '', input => 'ABCDEFGHIJKL'), 'ABCDEFGHIJKL is valid');

    ok(!$rule->is_valid(context => '', input => '1'), '1 is not valid');
    ok(!$rule->is_valid(context => '', input => 'ABCDEFGHIJKLM'), 'ABCDEFGHIJKLM is not valid');

    my @error_list;
    is($rule->get_valid(context => '', input => '1234567890', error_list => \@error_list), '1234567890', '1234567890 is valid');
    is(scalar @error_list, 0, 'error list is still empty');
    is($rule->get_valid(context => '', input => '123456789012345', error_list => \@error_list), undef, '123456789012345 is not valid');
    is(scalar @error_list, 1, 'error list is not empty');
}

{
    my $rule = OWASP::ESAPI::Reference::Validation::StringValidationRule->new(
        esapi => $esapi,
        type  => 'Str',
    );

    ok(!$rule->optional, 'optional is false by default');
    ok(!$rule->is_valid(context => '', input => undef), 'undef is not valid');

    $rule->optional(1);
    ok($rule->optional, 'optional has now been turned on');
    ok($rule->is_valid(context => '', input => undef), 'undef is valid when optional is true');
}
