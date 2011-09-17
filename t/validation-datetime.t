#!/usr/bin/env perl
use strict;
use warnings;

use Test::More;
use Test::MockObject;
use Moose::Util::TypeConstraints;
use Try::Tiny;

eval 'use DateTime';
plan skip_all => 'DateTime is not available.' if $@;
eval 'use DateTime::Format::Natural';
plan skip_all => 'DateTime::Format::Natural is not available.' if $@;

plan tests => 3;

use_ok('OWASP::ESAPI::ValidationRule');

my $esapi = Test::MockObject->new;
$esapi->set_isa('OWASP::ESAPI');

# Do not run this test real close to midnight, you sillies...
{
    class_type 'DateTime';
    subtype 'TestDateTime' => as 'DateTime';
    my $dt = DateTime::Format::Natural->new;
    coerce 'TestDateTime'
        => from 'Str'
        => via { 
            my $v = $dt->parse_datetime($_); 
            die $dt->error unless $dt->success; 
            $v 
        };

    my $rule = OWASP::ESAPI::ValidationRule->new(
        esapi => $esapi,
        type  => 'TestDateTime',
    );

    my $value = $rule->get_valid(
        context => '',
        input   => 'today',
    );
    
    my $today = DateTime->today;
    is(''.$value, ''.$today, "today parsed to $today");

    try {
        my $value2 = $rule->get_valid(
            context => '', 
            input   => 'xyz',
        );
        fail("expected exception but got $value2");
    }
    catch {
        isa_ok($_, 'OWASP::ESAPI::Exception');
    };
}
