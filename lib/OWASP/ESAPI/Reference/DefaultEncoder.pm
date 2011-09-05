package OWASP::ESAPI::Reference::DefaultEncoder;
use Moose;

with qw( 
    OWASP::ESAPI::Role::Logger
    OWASP::ESAPI::Role::ESAPI
);

use OWASP::ESAPI::Codec::HTMLEntityCodec;
use OWASP::ESAPI::Codec::XMLEntityCodec;
use OWASP::ESAPI::Codec::PercentCodec;
use OWASP::ESAPI::Codec::JavaScriptCodec;
use OWASP::ESAPI::Codec::VBScriptCodec;
use OWASP::ESAPI::Codec::CSSCodec;
use OWASP::ESAPI::Exception;

use List::Util qw( sum );
use MIME::Base64 ();
use URI::Escape ();

use namespace::autoclean;

# ABSTRACT: Reference implementation of Encoder

# Some internal class constants recognizing whitelisted immune charcterc
my @__standard3 = (',', qw( . _ ));
my @__standard4 = (',', qw( . _ - ));
my @__standard5 = (@__standard4, ' ');
my %IMMUNE = (
    html       => \@__standard5,
    htmlattr   => \@__standard4,
    css        => [],
    javascript => \@__standard3,
    vbscript   => \@__standard3,
    xml        => \@__standard5,
    sql        => [ ' ' ],
    os         => [ '-' ],
    xmlattr    => \@__standard4,
    xpath      => \@__standard5,
);

has codecs => (
	is          => 'ro',
	isa         => 'ArrayRef[OWASP::ESAPI::Codec]',
	required    => 1,
	lazy_build  => 1,
    traits      => [ 'Array' ],
    handles     => {
        _apply_codecs => 'map',
        _codecs_count => 'count',
    },
);

sub _build_codecs {
	my $self = shift;
	return [
		$self->html_codec,
		$self->percent_codec,
		$self->javascript_codec,
	]
}

has html_entity_codec => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI::Codec::HTMLEntityCodec',
    required    => 1,
    lazy_build  => 1,
    handles     => {
        encode_for_html           => [ encode => $IMMUNE{html} ],
        decode_for_html           => 'decode',
        encode_for_html_attribute => [ encode => $IMMUNE{htmlattr}, ],
        encode_for_xpath          => [ encode => $IMMUNE{xpath} ],
    },
);

sub _build_html_entity_codec { OWASP::ESAPI::Codec::HTMLEntityCodec->new }

has xml_entity_codec => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI::Codec::XMLEntityCodec',
    required    => 1,
    lazy_build  => 1,
    handles     => {
        encode_for_xml           => [ encode => $IMMUNE{xml} ],
        encode_for_xml_attribute => [ encode => $IMMUNE{xmlattr} ],
    },
);

sub _build_xml_entity_codec { OWASP::ESAPI::Codec::XMLEntityCodec->new }

has percent_codec => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI::Codec::PercentCodec',
    required    => 1,
    lazy_build  => 1,
);

sub _build_percent_codec { OWASP::ESAPI::Codec::PercentCodec->new }

has javascript_codec => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI::Codec::JavaScriptCodec',
    required    => 1,
    lazy_build  => 1,
    handles     => {
        encode_for_javascript => [ encode => $IMMUNE{javascript} ],
    },
);

sub _build_javascript_codec { OWASP::ESAPI::Codec::JavaScriptCodec->new }

has vbscript_codec => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI::Codec::VBScriptCodec',
    required    => 1,
    lazy_build  => 1,
    handles     => {
        encode_for_vbscript => [ encode => $IMMUNE{vbscript} ],
    },
);

sub _build_vbscript_codec { OWASP::ESAPI::Codec::VBScriptCodec->new }

has css_codec => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI::Codec::CSSCodec',
    required    => 1,
    lazy_build  => 1,
    handles     => {
        encode_for_css => [ encode => $IMMUNE{css} ],
    },
);

sub _build_css_codec { OWASP::ESAPI::Codec::CSSCodec->new }

has ldap_codec => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI::Codec::LDAPCodec',
    required    => 1,
    lazy_build  => 1,
    handles     => {
        encode_for_ldap => [ encode => $IMMUNE{ldap} ],
    },
);

sub _build_ldap_codec { OWASP::ESAPI::Codec::LDAPCodec->new }

has dn_codec => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI::Codec::DNCodec',
    required    => 1,
    lazy_build  => 1,
    handles     => {
        encode_for_dn => [ encode => $IMMUNE{dn} ],
    },
);

sub _build_dn_codec { OWASP::ESAPI::Codec::DNCodec->new }

with 'OWASP::ESAPI::Encoder';

sub canonicalize {
    my ($self, $input, $options) = @_;

    return unless defined $input;

    $options = {} unless defined $options;
    my $restrict_multiple = $options->{restrict_multiple} || $options->{strict};
    my $restrict_mixed    = $options->{restrict_mixed}    || $options->{strict};

    $restrict_multiple = !$self->esapi->security_configuration->allow_multiple_encoding
        unless defined $restrict_multiple;
    $restrict_mixed    = !$self->esapi->security_configuration->allow_mixed_encoding
        unless defined $restrict_mixed;

    my @codecs_found = (0) x $self->_codecs_count;
    my $clean;
    my $working = $input;
    until ($clean) {
        $clean = 1;
        my $codec_index = 0;

        $self->_apply_codecs(sub {
            my $old = $working;
            $working = $_->decode($working);
            if ($working ne $old) {
                $codecs_found[ $codec_index ]++;
                $clean = '';
            }

            $codec_index++;
        });
    }

    my $found_count = sum @codecs_found;
    my $mixed_count = sum map { $_ ? 1 : 0 } @codecs_found;

    my @messages;
    my %payload;
    if ($found_count >= 2) { 
        push @messages, 'multiple (%{found_count}d)';
        $payload{found_count} = $found_count;
    }

    if ($mixed_count > 1) {
        push @messages, 'mixed encoding (%{mixed_count}d)';
        $payload{mixed_count} = $mixed_count;
    }

    if (@messages) {
        my $message = Moose::Util::english_list(@messages) . ' detected in %{input}s';
        $payload{input} = $input;

        if (($restrict_multiple and $found_count >= 2) or ($restrict_mixed and $mixed_count > 1)) {
            throw {
                ident   => 'input validation failure',
                tags    => [ 'intrusion' ],
                message => $message,
                payload => \%payload,
            };
        }
        else {
            $self->log_warning(
                type    => 'security failure',
                message => $message,
                payload => \%payload,
            );
        }
    }

    return $working;
}

sub encode_for_sql {
    my ($self, $codec, $input) = @_;
    return $codec->encode($IMMUNE{sql}, $input);
}

sub encode_for_os {
    my ($self, $codec, $input) = @_;
    return $codec->encode($IMMUNE{os}, $input);
}

sub encode_for_url {
    my ($self, $input) = @_;
    return URI::Escape::uri_escape($input);
}

sub decode_from_url {
    my ($self, $input) = @_;

    return unless defined $input;

    my $canonical = $self->canonical($input);
    return URI::Escape::uri_unescape($canonical);
}

sub encode_for_base64 {
    my ($self, $input, $options) = @_;
    $options = {} unless defined $options;
    $options->{wrap} = 1 unless defined $options->{wrap};

    my $eol = $options->{wrap} ? "\n" : "";

    return MIME::Base64::encode_base64($input, $eol);
}

sub decode_for_base64 {
    my ($self, $input) = @_;
    return MIME::Base64::decode_base64($input);
}

__PACKAGE__->meta->make_immutable;
