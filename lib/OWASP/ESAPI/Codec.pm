package OWASP::ESAPI::Codec;
use Moose;

use MooseX::Params::Validate;

# ABSTRACT: Base class for encoding/decoding codecs

sub encode {
    my ($self, $immune, $input) = validated_list(\@_,
        immune => { isa => 'ArrayRef[Str]' },
        input  => { isa => 'Str' },
    );

    return join '', 
            map { $self->encode_character(immune => $immune, input => $_) } 
          split //, $input;
}

sub encode_character {
    my ($self, $immune, $c) = validated_list(\@_,
        immune => { isa => 'ArrayRef[Str]' },
        input  => { isa => 'Str' },
    );

    return $c;
}

sub decode {
    my ($self, $input) = validated_list(\@_,
        input => { isa => 'Str' },
    );

    my $output = '';
    while (length $input > 0) {
        my $c = $self->decode_character(input => \$input);
        $output .= $c;
    }

    return $output;
}

sub decode_character {
    my ($self, $input) = validated_list(\@_,
        input => { isa => 'ScalarRef[Str]' },
    );

    return substr $$input, 0, 1, '';
}

__PACKAGE__->meta->make_immutable;
