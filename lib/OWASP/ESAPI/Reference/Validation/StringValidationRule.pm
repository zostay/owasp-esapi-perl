package OWASP::ESAPI::Reference::Validation::StringValidationRule;
use Moose;

with 'OWASP::ESAPI::ValidationRule';

use Moose::Util::TypeConstraints qw( find_type_constraint );

# ABSTRACT: Provide a validation rule for generic strings

=head1 SYNOPSIS

  use OWASP::ESAPI::Reference::Validation::StringValidationRule;

  my $rule = OWASP::ESAPI::Reference::Validation::StringValidationRule->new(
      esapi => $esapi,
      type  => 'MyApp::Types::FullName',
  );

  try {
      my $string = $rule->get_valid(
          context => 'Full Name',
          input   => $c->request->parameters->{full_name},
      );
  }
  catch {
      say "Your string is invalid: $_";
  };

=head1 DESCRIPTION

Provides a generic string validator for input fields.

=head1 METHODS

=head2 must_subtype

Returns the type object for C<Str>.

=cut

sub must_subtype {
    return find_type_constraint('Str');
}

__PACKAGE__->meta->make_immutable;
