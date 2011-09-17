package OWASP::ESAPI::Codec::JavaScriptCodec;
use Moose;

extends 'OWASP::ESAPI::Codec';

use List::MoreUtils qw( any );
use MooseX::Params::Validate;

sub encode_character {
    my ($self, $immune, $c) = validated_list(\@_,
        immune => { isa => 'ArrayRef[Str]' },
        input  => { isa => 'Str' },
    );

    # immune: as-is
    return $c if any { $c eq $_ } @$immune;

    # alphanumeric: as-is
    return $c if $c =~ /[a-zA-Z0-9]/;
    
    my $o = ord($c);

    # ord(c) < 256: \xFF or whatever
    return sprintf '\\x%02x', $o if $o < 256;

    # ord(c) >= 256: \uFFFF or whatever
    return sprintf '\\u%04x', $o;
}

sub decode_character {
    my ($self, $input) = validated_list(\@_,
        input  => { isa => 'ScalarRef[Str]' },
    );

    return "\b"   if $$input =~ s{^\\b}{};
    return "\t"   if $$input =~ s{^\\t}{};
    return "\n"   if $$input =~ s{^\\n}{};
    return "\x0b" if $$input =~ s{^\\v}{};
    return "\f"   if $$input =~ s{^\\f}{};
    return "\r"   if $$input =~ s{^\\r}{};
    return '"'    if $$input =~ s{^\\"}{};
    return "'"    if $$input =~ s{^\\'}{};
    return "\\"   if $$input =~ s{^\\\\}{};

    return chr(hex($1)) if $$input =~ s{^\\x([a-fA-F0-9]{2})}{};
    return chr(hex($1)) if $$input =~ s{^\\u([a-fA-F0-9]{4})}{};
    return chr(oct($1)) if $$input =~ s{^\\([0-7]{3})}{};

    return substr $$input, 0, 1, '';
}

__PACKAGE__->meta->make_immutable;
