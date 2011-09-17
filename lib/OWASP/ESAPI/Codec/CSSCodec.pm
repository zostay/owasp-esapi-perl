package OWASP::ESAPI::Codec::CSSCodec;
use Moose;

extends 'OWASP::ESAPI::Codec';

use MooseX::Params::Validate;
use List::MoreUtils qw( any );

sub encode_character {
    my ($self, $immune, $c) = validated_list(\@_,
        immune => { isa => 'ArrayRef[Str]' },
        input  => { isa => 'Str' },
    );

    return $c if any { $c eq $_ } @$immune;
    return $c if $c =~ /[a-zA-Z0-9]/;
    return sprintf '\\%x ', ord($c);
}

sub decode_character {
    my ($self, $input) = validated_list(\@_,
        input => { isa => 'ScalarRef[Str]' },
    );

    # Strip Whitespace from lines ending in \
    $$input =~ s{^\\(?:[\n\f\0]|\r\n?)}{};
    return '' unless length $$input > 0;

    # \XXXXXX: turn hex escape into char, absorb trailing whitespace
    if ($$input =~ s{\\([a-fA-F0-9]{1,6})\s?}{}) {
        my $c = chr(hex($1));
        return "\x{fffd}" unless $c =~ /\p{Assigned}/;
        return $c;
    }

    # Return the next char after a \.
    return $1 if $$input =~ s{^\\(.)}{}ms;

    return substr $$input, 0, 1, '';
}

__PACKAGE__->meta->make_immutable;
