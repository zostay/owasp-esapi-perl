package OWASP::ESAPI::Role::ESAPI;
use Moose::Role;

has esapi => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI',
    required    => 1,
);

1;
