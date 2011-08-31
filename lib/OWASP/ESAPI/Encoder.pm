package OWASP::ESAPI::Encoder;
use Moose::Role;

# ABSTRACT: Interface describing tools for encoding/decoding various web formats

requires qw(
	canonicalize
	encode_for_css
	encode_for_html
	decode_for_html
	encode_for_html_attribute
	encode_for_javascript
	encode_for_vbscript
	encode_for_sql
	encode_for_os
	encode_for_ldap
	encode_for_dn
	encode_for_xpath
	encode_for_xml
	encode_for_xml_attribute
	encode_for_url
	decode_from_url
	encode_for_base64
	decode_from_base64
);

1;
