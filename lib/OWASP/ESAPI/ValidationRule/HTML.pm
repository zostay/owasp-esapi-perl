package OWASP::ESAPI::ValidationRule::HTML;
use Moose;

extends 'OWASP::ESAPI::ValidationRule';

use HTML::Scrubber;

has html_scrubber_policy => (
    is          => 'ro',
    isa         => 'HashRef',
    required    => 1,
    lazy_build  => 1,
);

sub _build_scrubber_rules {
    my $self = shift;
    return $self->esapi->security_configuration->load_resource('html-scrubber-policy');
}

has html_scrubber => (
    is          => 'ro',
    isa         => 'HTML::Scrubber',
    required    => 1,
    lazy_build  => 1,
);

sub _build_html_scrubber {
    my $self = shift;
    my $policy = $self->html_scrubber_policy;
    return HTML::Scrubber->new(%$policy);
}

override precheck_validation => sub {
    my ($self, $params) = @_;
    $params->{input} = $self->html_scrubber->scrub($params->{input});
};

__PACKAGE__->meta->make_immutable;
