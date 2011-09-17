package OWASP::ESAPI::Types;
use MooseX::Types -declare => [ qw(
    TypeConstraint
) ];

use MooseX::Types::Moose qw( Str );
use Moose::Util::TypeConstraints ();

class_type 'Moose::Meta::TypeConstraint';
subtype TypeConstraint,
    as 'Moose::Meta::TypeConstraint';

coerce TypeConstraint,
    from Str,
    via { Moose::Util::TypeConstraints::find_or_parse_type_constraint($_) };

1;
