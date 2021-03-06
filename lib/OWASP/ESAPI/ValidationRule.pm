package OWASP::ESAPI::ValidationRule;
use Moose;

with qw( OWASP::ESAPI::Role::ESAPI );

use OWASP::ESAPI::Exception qw( new_exception throw );
use OWASP::ESAPI::Types qw( TypeConstraint );
use MooseX::Params::Validate;
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

=head2 safe_default

This may be set to a safe default value for your validation. It must match the given type. If not given, all calls to L</get_safe> will fail with an immediate exception (i.e., it can't be safe if you don't give this value).

You may set this to C<undef> if L</optional> is true or if it is allowed by L</type>.

=cut

has default => (
    is          => 'rw',
    predicate   => 'has_default',
    trigger     => \&_check_default,
);

sub _check_default {
    my ($self, $value) = @_;

    throw {
        ident   => 'default does not match type',
        tags    => [ 'argument' ],
        message => 'the default %{value}s does not match type %{type}s for rule %{rule}s: %{message}s',
        payload => {
            rule    => $self->meta->name,
            value   => $value,
            type    => $self->type->name,
            message => $self->type->validate($value),
        },
    } unless $self->type->check($value)
          or $self->optional and not defined $value;
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
    my ($self, %params) = validated_has(\@_,
        context => { isa => 'Str' },
        input   => { isa => 'Maybe[Str]' },
    );
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

A subclass of L<OWASP::ESAPI::ValidationRule> may choose to augment this method by implementing either of the C<precheck_validation> or C<postcheck_validation> methods. Each of these will be passed a reference to the passed arguments and may modify these or throw exceptions. The return value of these methods is ignored.

The C<precheck_validation> method will be called before any validation of the value is performed.

The C<postcheck_validation> method will be called after the value has been validated and coerced. It will not be called if C<precheck_validation ,type validation or type coercion have thrown an exception. The hash reference passed to this method also contains an additional key, C<value>, which points to the validated (and possibly coerced) version of the orignal input.

=cut

sub precheck_validation { }

sub postcheck_validation { }

sub get_valid {
    my ($self, %params) = validated_hash(\@_,
        context    => { isa => 'Str' },
        input      => { isa => 'Maybe[Str]' },
        error_list => { isa => 'ArrayRef', optional => 1 },
    );

    return $params{input} if $self->optional and not defined $params{input};

    my $valid;
    try {

        # Before validation, a subclass may augment the type checking here
        $self->precheck_validation(\%params);

        # If it's valid, we're done
        if ($self->type->check($params{input})) {
            $valid = $params{input};
        }

        # Otherwise, try to coerce it
        else {
            $valid = $self->type->assert_coerce($params{input});
        }

        # After validation, a subclass may augment the type checking as well
        # to deal with the final and possibly coerced value.
        $params{value} = $valid;
        $self->postcheck_validation(\%params);

    }
    catch {

        # The coercion error is not helpful, use the validation error
        if (/Cannot coerce without a type coercion/) {
            $_ = $self->type->validate($params{input});
        }

        my $exception = new_exception {
            ident   => 'validation exception',
            tags    => [ 'validation' ],
            message => '%{context}s: %{message}s',
            payload => {
                context => $params{context} // '',
                message => $_ // '',
            },
        };

        # If there's an error list, push it
        my $error_list = $params{error_list};
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

This will call L</get_valid> to get a valid value from the input, if possible. If that fails, it will use L</default> to get a valid value. The intent of this method is to make sure to return a value of the correct type regardless of the input.

If L</default> is not set, this method will immediately fail. You must set a default for safety to be guaranteed.

=cut

sub get_safe {
    my ($self, %params) = validated_hash(\@_,
        context    => { isa => 'Str' },
        input      => { isa => 'Maybe[Str]' },
    );

    throw {
        ident   => 'cannot call get_safe without a default',
        tags    => [ 'state' ],
    } unless $self->has_default;

    my $valid;
    try {
        $valid = $self->get_valid(%params);
    }
    catch {
        $valid = $self->default;
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
    my ($self, %params) = validated_hash(\@_,
        context    => { isa => 'Str' },
        input      => { isa => 'Maybe[Str]' },
    );

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

1;
