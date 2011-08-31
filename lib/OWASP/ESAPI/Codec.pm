package OWASP::ESAPI::Codec;
use Moose;

# ABSTRACT: Base class for encoding/decoding codecs

sub encode {
    my ($self, $immune, $input) = @_;

    return join '', 
            map { $self->encode_character($immune, $_) } 
          split //, $input;
}

sub encode_character {
    my ($self, $immune, $c) = @_;
    return $c;
}

sub decode {
    my ($self, $input) = @_;

    my $output = '';
    while (length $input > 0) {
        my $c = $self->decode_character(\$input);
        $output .= $c;
    }

    return $output;
}

sub decode_character {
    my ($self, $input) = @_;
    return substr $$input, 0, 1, '';
}

__PACKAGE__->meta->make_immutable;
