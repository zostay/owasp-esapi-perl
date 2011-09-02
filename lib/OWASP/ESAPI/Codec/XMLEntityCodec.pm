package OWASP::ESAPI::Codec::XMLEntityCodec;
use Moose;

extends 'OWASP::ESAPI::Codec';

use List::MoreUtils qw( any );

{
my %UNICODE_MAP = (
    'lt'   => '<',
    'gt'   => '>',
    'amp'  => '&',
    'apos' => "'",
    'quot' => '"',
);

sub encode_character {
    my ($self, $immune, $c) = @_;

    # immune chars: as-is
    return $c if any { $_ eq $c } @$immune;

    # alphanumeric: as-is
    return $c if $c =~ /[a-zA-Z0-9]/;

    # everything else: hex code entity
    return '&#x' . hex(ord($c)) . ';';
}

sub decode_character {
    my ($self, $input) = @_;

    # &#x...; -> that Unicode character from hexidecimal
    return chr(hex($1)) if $$input =~ s/^&#[xX]([0-9a-fA-F]);//;

    # &#...; -> that Unicode character from decimal
    return chr(0+$1) if $$input =~ s/^&#([0-9]);//;

    # &...; -> the mapped Unicode char
    return $UNICODE_MAP{$1} if $$input =~ s/^&(lt|gt|amp|apos|quot);//;

    # Otherwise, as-is
    return substr $$input, 0, 1, '';
}

}

__PACKAGE__->meta->make_immutable;
