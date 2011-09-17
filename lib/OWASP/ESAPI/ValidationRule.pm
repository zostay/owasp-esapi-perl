package OWASP::ESAPI::ValidationRule;
use Moose::Role;

with qw( OWASP::ESAPI::Role::ESAPI );

use OWASP::ESAPI::Exception qw( new_exception throw );
use OWASP::ESAPI::Types qw( TypeConstraint );
use Try::Tiny;

# ABSTRACT: Interface for type-oriented input validation tools

=head1 DESCRIPTION

This deviates from the Java reference implementation in a few important ways, but these deviations take advantage of Modern Perl features that greatly simplify implementation and allow for validation of almost any kind of data.

Mainly, this implementation depends heavily on the L<Moose> type system, which already provides the tools necessary to validate input and coerce form input into Perl data structures. This class focuses on providing these tools, applying encoding codecs in the approprieate places, and sanitization, which the Moose type system does not provide.

Some other details:

=over

=item *

The C<allowNull> property has been replaced with L</optional>. Be default this boolean property is false and C<undef> will be rejected. However, if you set optional, C<undef> will be permitted as input. This is better in keeping with usual Modern Perl naming.

=item *

The C<type_name> has been replaced with C<type>, which is a L<Moose::Meta::TypeConstraint>. It may be set using a string, which will be coerced into the named L<Moose> type object.

=item *

The whitelist method has been omitted since the same features are accomplished with the C<tr///> built-in.

=back

=head1 ATTRIBUTES

=head2 optional

This is a boolean value that defaults to false. If true, then passing C<undef> as input to one of the validation methods will result in that value being considered valid and returned as is. Otherwise, the value will be rejected as invalid.

=cut

has optional => (
    is          => 'rw',
    isa         => 'Bool',
    required    => 1,
    default     => 0,
);

=head2 type

This is a Moose type, i.e., a L<Moose::Meta::TypeConstraint>, that the L</get_valid> method will be returning. You may set it using a string, which will be coerced into a Moose type by that name automatically.

This type must be equal to or a subtype of the type returned by L</must_type> for the validation rule.

This type must also be equal to or a subtype of C<Str> or provide a type coercion from C<Str>.

=cut

has type => (
    is          => 'rw',
    isa         => TypeConstraint,
    required    => 1,
    coerce      => 1,
    trigger     => \&_check_type,
    handles     => {
        type_name => 'name',
    },
);

sub _check_type {
    my ($self, $value) = @_;

    # The given type must be the required subtype
    throw {
        ident   => 'type is not a type of must_subtype',
        tags    => [ 'argument' ],
        message => 'the type given to validation rule %{rule}s is %{type}s, but that is not a type of %{must_subtype}s',
        payload => {
            rule         => $self->meta->name,
            type         => $value->name,
            must_subtype => $self->must_subtype->name,
        },
    } unless $value->is_a_type_of($self->must_subtype);

    # The given type must be a type of 'Str' or provide a coercion from 'Str'
    throw {
        ident   => 'type is not a type of Str or coerce from Str',
        tags    => [ 'argument' ],
        message => 'the type given to validation rule %{rule}s is %{type}s but it is not equal to Str or provide a coercion from Str',
        payload => {
            rule => $self->meta->name,
            type => $value->name,
        },
    } unless $value->is_a_type_of('Str') 
          or ($value->has_coercion and $value->coercion->has_coercion_for_type('Str'));
}

=head2 encoder

This is the L<OWASP::ESAPI::Encoder> that will be used to decode the original string input.

=cut

has encoder => (
    is          => 'rw',
    isa         => 'OWASP::ESAPI::Encoder',
    required    => 1,
    lazy_build  => 1,
);

sub _build_encoder {
    my $self = shift;
    $self->esapi->encoder;
}

=head1 METHODS

=head2 type_name

  my $name = $rule->type_name;

This is the name of the L</type> that will be returned by L</get_valid> (barring an exception or other error).

=head2 assert_valid

  $rule->assert_valid(
      context => 'field name',
      input   => 'input',
  );

Throws an exception if the given input is not valid according to this validation rule. This is pretty much the same thing as L<get_valid>, but it does not return anything.

=cut

sub assert_valid {
    my ($self, %params) = @_;
    $self->get_valid(%params);
    return;
}

=head2 get_valid

  my $value = $rule->get_valid(
      context    => 'field name',
      input      => 'input',
      error_list => \@error_list, # optional
  );

Checks to make sure the input string is valid for the type given or can be coerced into that type. If it is valid or coerceable, the validated value is returned.

If it is not valid, this method will take one of two actions:

=over

=item 1

If C<@error_list> is passed the validation exception will be pushed onto the end of C<@error_list>.

=item 1

If C<@error_list> is not passed, the validation exception will be thrown.

=back

=cut

sub get_valid {
    my ($self, %params) = @_;

    my $context    = $params{context};
    my $input      = $params{input};
    my $error_list = $params{error_list};

    return $input if $self->optional and not defined $input;

    throw "context is required" unless defined $context;
    throw "input is required"   unless defined $input;

    my $valid;
    try {

        # If it's valid, we're done
        if ($self->type->check($input)) {
            $valid = $input;
        }

        # Otherwise, try to coerce it
        else {
            $valid = $self->type->assert_coerce($input);
        }

    }
    catch {

        # The coercion error is not helpful, use the validation error
        if (/Cannot coerce without a type coercion/) {
            $_ = $self->type->validate($input);
        }

        my $exception = new_exception {
            ident   => 'validation exception',
            tags    => [ 'validation' ],
            message => '%{context}s: %{message}s',
            payload => {
                context => $context // '',
                message => $_ // '',
            },
        };

        # If there's an error list, push it
        if (defined $error_list) {
            push @$error_list, $exception;
        }

        # Otherwise, rethrow
        else {
            die $exception;
        }
    };

    return $valid;
}

=head2 get_safe

  my $value = $rule->get_safe(
      context => 'field name',
      input   => 'input',
  );

This will call L</get_valid> to get a valid value from the input, if possible. If that fails, it will call L</sanitize> to get a valid input. The intent of this method is to make sure to return a value of the correct type regardless of the input.

=cut

sub get_safe {
    my ($self, %params) = @_;

    my $valid;
    try {
        $valid = $self->get_valid(%params);
    }
    catch {
        $valid = $self->sanitize(%params);
    };

    return $valid;
}

=head2 is_valid

  my $is_valid = $rule->is_valid(
      context => 'field name',
      input   => 'input',
  );

Calls L</get_valid> and returns a true value if the given input is valid. Returns a false value if it is not valid.

=cut

sub is_valid {
    my ($self, %params) = @_;

    my $valid = '';
    try {
        $self->get_valid(%params);
        $valid = 1;
    }
    catch {
        $valid = '';
    };

    return $valid;
}

=head1 REQUIRED METHODS

Implementors must provide the following methods.

=head2 must_subtype

  my $type = $self->must_subtype;

This must return an instance of L<Moose::Meta::TypeConstraint> that will be use to validate the L</type>.

=head2 sanitize

  my $value = $self->sanitize(
      context => 'field name',
      input   => 'input',
  );

This must always return a valid value for the type in L</type> so that L</get_safe> will always return a valid value, even if that value has nothing to do with the given input.

=cut

requires qw(
    must_subtype
    sanitize
);

1;
