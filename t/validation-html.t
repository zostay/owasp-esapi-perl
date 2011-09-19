#!/usr/bin/env perl
use strict;
use warnings;

use Test::More tests => 2;
use Test::MockObject;

use_ok('OWASP::ESAPI::ValidationRule::HTML');

my $esapi = Test::MockObject->new;
$esapi->set_isa('OWASP::ESAPI');

{
    my $rule = OWASP::ESAPI::ValidationRule::HTML->new(
        esapi                => $esapi,
        type                 => 'Str',
        html_scrubber_policy => {
            allow => [ qw( b i u strong em ) ],
        },
    );

    my $value = $rule->get_valid(
        context => '',
        input   => q[<b>bold OK</b><script>Script, not so much</script>],
    );

   is($value, '<b>bold OK</b>', 'HTML is scrubbed'); 
}
