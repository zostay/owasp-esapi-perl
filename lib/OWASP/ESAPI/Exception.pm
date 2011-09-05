package OWASP::ESAPI::Exception;
use Moose;
use Sub::Exporter::Util qw( curry_method );
use Sub::Exporter -setup => {
    exports => {
        throw         => curry_method,
        new_exception => curry_method('new'),
    },
    groups => {
        default => [ qw( throw ) ],
    },
};

with qw(
    Throwable::X
    StackTrace::Auto
);

__PACKAGE__->meta->make_immutable( inline_constructor => 0 );
