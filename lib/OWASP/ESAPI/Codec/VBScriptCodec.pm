package OWASP::ESAPI::Codec::VBScriptCodec;
use Moose;

extends 'OWASP::ESAPI::Codec';

use List::MoreUtils qw( any );

sub encode {
    my ($self, $immune, $input) = @_;

    my $output   = '';
    my $inquotes = '';
    for my $c (split //, $input) {
        if (any { $c eq $_ } @$immune or $c =~ /[a-zA-Z0-9]/) {
            $output .= '&"' unless $inquotes and length $output;
            $output .= $c;

            $inquotes = 1;
        }

        else {
            $output .= '"' if $inquotes;
            $output .= '&' if length $output;
            $output .= $self->encode_character($immune, $c);

            $inquotes = '';
        }
    }

    return $output;
}

sub encode_character {
    my ($self, $immune, $c) = @_;

    return $c if any { $c eq $_ } @$immune or $c =~ /[a-zA-Z0-9]/;
    return 'chrw(' . ord($c) . ')';
}

sub decode_character {
    my ($self, $input) = @_;

    return '"' if $$input =~ s{^""}{};
    return substr $$input, 0, 1, '';
}

__PACKAGE__->meta->make_immutable;
