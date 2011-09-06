#!/usr/bin/env perl
use strict;
use warnings;

use Test::More tests => 23;

use_ok('OWASP::ESAPI::Codec::HTMLEntityCodec');
use_ok('OWASP::ESAPI::Codec::PercentCodec');
use_ok('OWASP::ESAPI::Codec::JavaScriptCodec');
use_ok('OWASP::ESAPI::Codec::VBScriptCodec');
use_ok('OWASP::ESAPI::Codec::CSSCodec');
# use_ok('OWASP::ESAPI::Codec::MySQLCodec');
# use_ok('OWASP::ESAPI::Codec::OracleCodec');
# use_ok('OWASP::ESAPI::Codec::UnixCodec');
# use_ok('OWASP::ESAPI::Codec::WindowsCodec');

my $html_codec       = OWASP::ESAPI::Codec::HTMLEntityCodec->new;
my $percent_codec    = OWASP::ESAPI::Codec::PercentCodec->new;
my $javascript_codec = OWASP::ESAPI::Codec::JavaScriptCodec->new;
my $vbscript_codec   = OWASP::ESAPI::Codec::VBScriptCodec->new;
my $css_codec        = OWASP::ESAPI::Codec::CSSCodec->new;

is($html_codec->encode([], 'test'), 'test', 'test HTML encode');
is($percent_codec->encode([], '<'), '%3c', 'test percent encode');
is($javascript_codec->encode([], '<'), '\\x3c', 'test JavaScript encode');
is($vbscript_codec->encode([], '<'), 'chrw(60)', 'test VBScript encode');
is($css_codec->encode([], '<'), '\\3c ', 'test CSS encode');

is($css_codec->decode('\\abcdefg'), "\x{FFFD}g", 'test css invalid codepoint decode');
# TODO test MySQL ANSI encode
# TODO test MySQL Standard Encode
# TODO test Oracle encode
# TODO test Unix encode
# TODO test Windows encode

is($html_codec->encode([], '<'), '&lt;', 'test HTML encode char');
is($html_codec->encode([], "\x{100}"), '&#x100;', 'test HTML encode 0x100');

is($percent_codec->encode([], '<'), '%3c', 'test percent encode <');
is($percent_codec->encode([], "\x{100}"), '%c4%80', 'test percent encode 0x100');

is($javascript_codec->encode([], '<'), '\\x3c', 'test javascript encode <');
is($javascript_codec->encode([], "\x{100}"), '\\u0100', 'test javascript encode 0x100');

is($vbscript_codec->encode([], '<'), 'chrw(60)', 'test vbscript encode <');
is($vbscript_codec->encode([], "\x{100}"), 'chrw(256)', 'test vbscript encode 0x100');

is($css_codec->encode([], '<'), '\\3c ', 'test CSS encode <');
is($css_codec->encode([], "\x{100}"), '\\100 ', 'test CSS encode 0x100');

# TODO various MySQL encoding tests...
# TODO various Oracle encoding tests...
# TODO various Unix encoding tests...

is($html_codec->decode('&#116;&#101;&#115;&#116;!'), 'test!', 'test HTML decode decimal entities');
is($html_codec->decode('&#x74;&#x65;&#x73;&#x74;!'), 'test!', 'test HTML decode hex entities');
