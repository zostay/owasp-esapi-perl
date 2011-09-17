package OWASP::ESAPI::Codec::VBScriptCodec;
use Moose;

extends 'OWASP::ESAPI::Codec';

use List::MoreUtils qw( any );
use MooseX::Params::Validate;

sub encode {
    my ($self, $immune, $input) = validated_list(\@_,
        immune => { isa => 'ArrayRef[Str]' },
        input  => { isa => 'Str' },
    );

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
            $output .= $self->encode_character(immune => $immune, input => $c);

            $inquotes = '';
        }
    }

    $output .= '"' if $inquotes;
    return $output;
}

sub encode_character {
    my ($self, $immune, $c) = validated_list(\@_,
        immune => { isa => 'ArrayRef[Str]' },
        input  => { isa => 'Str' },
    );

    return $c if any { $c eq $_ } @$immune or $c =~ /[a-zA-Z0-9]/;
    return 'chrw(' . ord($c) . ')';
}

sub decode_character {
    my ($self, $input) = validated_list(\@_,
        input  => { isa => 'ScalarRef[Str]' },
    );

    return $1 if $$input =~ s{^"(.)}{}sm;
    return substr $$input, 0, 1, '';
}

__PACKAGE__->meta->make_immutable;
