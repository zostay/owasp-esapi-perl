#!/usr/bin/env perl
use strict;
use warnings;

use Test::More tests => 68;

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
is($html_codec->decode('&jeff;'), '&jeff;', 'test HTML decode invalid attribute');

is($html_codec->decode('&amp;'),       '&',         'test decode amp');
is($html_codec->decode('&amp;X'),      '&X',        'test decode amp X');
is($html_codec->decode('&amp'),        '&',         'test decode amp no semi');
is($html_codec->decode('&ampX'),       '&X',        'test decode amp no semi X');
is($html_codec->decode('&lt;'),        '<',         'test decode lt');
is($html_codec->decode('&lt;X'),       '<X',        'test decode lt X');
is($html_codec->decode('&lt'),         '<',         'test decode lt no semi');
is($html_codec->decode('&ltX'),        '<X',        'test decode lt no semi X');
is($html_codec->decode("&sup1;"),      "\x{00B9}",  'test decode sup1');
is($html_codec->decode("&sup1;X"),     "\x{00B9}X", 'test decode sup1 X');
is($html_codec->decode("&sup1"),       "\x{00B9}",  'test decode sup1 no semi');
is($html_codec->decode("&sup1X"),      "\x{00B9}X", 'test decode sup1 no semi X');
is($html_codec->decode("&sup2;"),      "\x{00B2}",  'test decode sup2');
is($html_codec->decode("&sup2;X"),     "\x{00B2}X", 'test decode sup2 X');
is($html_codec->decode("&sup2"),       "\x{00B2}",  'test decode sup2 no semi');
is($html_codec->decode("&sup2X"),      "\x{00B2}X", 'test decode sup2 no semi X');
is($html_codec->decode("&sup3;"),      "\x{00B3}",  'test decode sup3');
is($html_codec->decode("&sup3;X"),     "\x{00B3}X", 'test decode sup3 X');
is($html_codec->decode("&sup3"),       "\x{00B3}",  'test decode sup3 no semi');
is($html_codec->decode("&sup3X"),      "\x{00B3}X", 'test decode sup3 no semi X');
is($html_codec->decode("&sup;"),       "\x{2283}",  'test decode sup');
is($html_codec->decode("&sup;X"),      "\x{2283}X", 'test decode sup X');
is($html_codec->decode("&sup"),        "\x{2283}",  'test decode sup no semi');
is($html_codec->decode("&supX"),       "\x{2283}X", 'test decode sup no semi X');
is($html_codec->decode("&supe;"),      "\x{2287}",  'test decode supe'); 
is($html_codec->decode("&supe;X"),     "\x{2287}X", 'test decode supe X');
is($html_codec->decode("&supe"),       "\x{2287}",  'test decode supe no semi'); 
is($html_codec->decode("&supeX"),      "\x{2287}X", 'test decode supe no semi X');
is($html_codec->decode("&pi;"),        "\x{03C0}",  'test decode pi');
is($html_codec->decode("&pi;X"),       "\x{03C0}X", 'test decode pi X');
is($html_codec->decode("&pi"),         "\x{03C0}",  'test decode pi no semi');
is($html_codec->decode("&piX"),        "\x{03C0}X", 'test decode pi no semi X');
is($html_codec->decode("&piv;"),       "\x{03D6}",  'test decode piv');
is($html_codec->decode("&piv;X"),      "\x{03D6}X", 'test decode piv X');
is($html_codec->decode("&piv"),        "\x{03D6}",  'test decode piv no semi');
is($html_codec->decode("&pivX"),       "\x{03D6}X", 'test decode piv no semi X');
is($html_codec->decode("&theta;"),     "\x{03B8}",  'test decode theta');
is($html_codec->decode("&theta;X"),    "\x{03B8}X", 'test decode theta X');
is($html_codec->decode("&theta"),      "\x{03B8}",  'test decode theta no semi');
is($html_codec->decode("&thetaX"),     "\x{03B8}X", 'test decode theta no semi X');
is($html_codec->decode("&thetasym;"),  "\x{03D1}",  'test decode thetasym'); 
is($html_codec->decode("&thetasym;X"), "\x{03D1}X", 'test decode thetasym X');
is($html_codec->decode("&thetasym"),   "\x{03D1}",  'test decode thetasym no semi'); 
is($html_codec->decode("&thetasymX"),  "\x{03D1}X", 'test decode thetasym no semi X');
