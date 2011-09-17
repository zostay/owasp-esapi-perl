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
use MooseX::Params::Validate;
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
        encode_for_html           => [ encode => immune => $IMMUNE{html} ],
        decode_for_html           => 'decode',
        encode_for_html_attribute => [ encode => immune => $IMMUNE{htmlattr}, ],
        encode_for_xpath          => [ encode => immune => $IMMUNE{xpath} ],
    },
);

sub _build_html_entity_codec { OWASP::ESAPI::Codec::HTMLEntityCodec->new }

has xml_entity_codec => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI::Codec::XMLEntityCodec',
    required    => 1,
    lazy_build  => 1,
    handles     => {
        encode_for_xml           => [ encode => immune => $IMMUNE{xml} ],
        encode_for_xml_attribute => [ encode => immune => $IMMUNE{xmlattr} ],
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
        encode_for_javascript => [ encode => immune => $IMMUNE{javascript} ],
    },
);

sub _build_javascript_codec { OWASP::ESAPI::Codec::JavaScriptCodec->new }

has vbscript_codec => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI::Codec::VBScriptCodec',
    required    => 1,
    lazy_build  => 1,
    handles     => {
        encode_for_vbscript => [ encode => immune => $IMMUNE{vbscript} ],
    },
);

sub _build_vbscript_codec { OWASP::ESAPI::Codec::VBScriptCodec->new }

has css_codec => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI::Codec::CSSCodec',
    required    => 1,
    lazy_build  => 1,
    handles     => {
        encode_for_css => [ encode => immune => $IMMUNE{css} ],
    },
);

sub _build_css_codec { OWASP::ESAPI::Codec::CSSCodec->new }

has ldap_codec => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI::Codec::LDAPCodec',
    required    => 1,
    lazy_build  => 1,
    handles     => {
        encode_for_ldap => [ encode => immune => $IMMUNE{ldap} ],
    },
);

sub _build_ldap_codec { OWASP::ESAPI::Codec::LDAPCodec->new }

has dn_codec => (
    is          => 'ro',
    isa         => 'OWASP::ESAPI::Codec::DNCodec',
    required    => 1,
    lazy_build  => 1,
    handles     => {
        encode_for_dn => [ encode => immune => $IMMUNE{dn} ],
    },
);

sub _build_dn_codec { OWASP::ESAPI::Codec::DNCodec->new }

with 'OWASP::ESAPI::Encoder';

sub canonicalize {
    my ($self, %params) = validated_hash(\@_,
        input             => { isa => 'Maybe[Str]' },
        restrict_multiple => { isa => 'Bool', optional => 1 },
        restrict_mixed    => { isa => 'Bool', optional => 1 },
        strict            => { isa => 'Bool', optional => 1 },
    );

    my $input = $params{input};
    return unless defined $input;

    my $restrict_multiple = $params{restrict_multiple} || $params{strict};
    my $restrict_mixed    = $params{restrict_mixed}    || $params{strict};

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
            $working = $_->decode(input => $working);
            if ($working ne $old) {
                $codecs_found[ $codec_index ]++;
                $clean = '';
            }

            $codec_index++;
        });
    }

    my $found_count = sum(@codecs_found) || 0;
    my $mixed_count = sum(map { $_ ? 1 : 0 } @codecs_found) || 0;

    my @messages;
    my %payload;

    if ($found_count >= 2) { 
        push @messages, 'multiple (%{found_count}i)';
        $payload{found_count} = $found_count;
    }

    if ($mixed_count > 1) {
        push @messages, 'mixed encoding (%{mixed_count}i)';
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
    my ($self, $codec, $input) = validated_list(\@_,
        codec => { isa => 'OWASP::ESAPI::Codec' },
        input => { isa => 'Str' },
    );
    return $codec->encode(immune => $IMMUNE{sql}, input => $input);
}

sub encode_for_os {
    my ($self, $codec, $input) = valiedated_list(\@_,
        codec => { isa => 'OWASP::ESAPI::Codec' },
        input => { isa => 'Str' },
    );
    return $codec->encode(immune => $IMMUNE{os}, input => $input);
}

sub encode_for_url {
    my ($self, $input) = validated_list(\@_,
        input => { isa => 'Str' },
    );
    return URI::Escape::uri_escape($input);
}

sub decode_from_url {
    my ($self, $input) = validated_list(\@_,
        input => { isa => 'Str' },
    );

    return unless defined $input;

    my $canonical = $self->canonicalize({ input => $input });
    return URI::Escape::uri_unescape($canonical);
}

sub encode_for_base64 {
    my ($self, $input, $wrap) = validated_list(\@_,
        input => { isa => 'Str' },
        wrap  => { isa => 'Bool', default => 1 },
    );

    my $eol = $wrap ? "\n" : "";

    return MIME::Base64::encode_base64($input, $eol);
}

sub decode_from_base64 {
    my ($self, $input) = @_;
    return MIME::Base64::decode_base64($input);
}

__PACKAGE__->meta->make_immutable;
