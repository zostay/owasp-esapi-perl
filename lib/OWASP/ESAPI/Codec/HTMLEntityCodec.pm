package OWASP::ESAPI::Codec::HTMLEntityCodec;
use Moose;

extends 'OWASP::ESAPI::Codec';

use List::MoreUtils qw( any );

{
my %ENTITY_MAP = (
    '"'        => 'quot',     # quotation mark
    '&'        => 'amp',      # ampersand
    '<'        => 'lt',       # less-than sign
    '>'        => 'gt',       # greater-than sign
    '\x{a0}'   => 'nbsp',     # no-break space
    '\x{a1}'   => 'iexcl',    # inverted exclamation mark
    '\x{a2}'   => 'cent',     # cent sign
    '\x{a3}'   => 'pound',    # pound sign
    '\x{a4}'   => 'curren',   # currency sign
    '\x{a5}'   => 'yen',      # yen sign
    '\x{a6}'   => 'brvbar',   # broken bar
    '\x{a7}'   => 'sect',     # section sign
    '\x{a8}'   => 'uml',      # diaeresis
    '\x{a9}'   => 'copy',     # copyright sign
    '\x{aa}'   => 'ordf',     # feminine ordinal indicator
    '\x{ab}'   => 'laquo',    # left-pointing double angle quotation mark
    '\x{ac}'   => 'not',      # not sign
    '\x{ad}'   => 'shy',      # soft hyphen
    '\x{ae}'   => 'reg',      # registered sign
    '\x{af}'   => 'macr',     # macron
    '\x{b0}'   => 'deg',      # degree sign
    '\x{b1}'   => 'plusmn',   # plus-minus sign
    '\x{b2}'   => 'sup2',     # superscript two
    '\x{b3}'   => 'sup3',     # superscript three
    '\x{b4}'   => 'acute',    # acute accent
    '\x{b5}'   => 'micro',    # micro sign
    '\x{b6}'   => 'para',     # pilcrow sign
    '\x{b7}'   => 'middot',   # middle dot
    '\x{b8}'   => 'cedil',    # cedilla
    '\x{b9}'   => 'sup1',     # superscript one
    '\x{ba}'   => 'ordm',     # masculine ordinal indicator
    '\x{bb}'   => 'raquo',    # right-pointing double angle quotation mark
    '\x{bc}'   => 'frac14',   # vulgar fraction one quarter
    '\x{bd}'   => 'frac12',   # vulgar fraction one half
    '\x{be}'   => 'frac34',   # vulgar fraction three quarters
    '\x{bf}'   => 'iquest',   # inverted question mark
    '\x{c0}'   => 'Agrave',   # Latin capital letter a with grave
    '\x{c1}'   => 'Aacute',   # Latin capital letter a with acute
    '\x{c2}'   => 'Acirc',    # Latin capital letter a with circumflex
    '\x{c3}'   => 'Atilde',   # Latin capital letter a with tilde
    '\x{c4}'   => 'Auml',     # Latin capital letter a with diaeresis
    '\x{c5}'   => 'Aring',    # Latin capital letter a with ring above
    '\x{c6}'   => 'AElig',    # Latin capital letter ae
    '\x{c7}'   => 'Ccedil',   # Latin capital letter c with cedilla
    '\x{c8}'   => 'Egrave',   # Latin capital letter e with grave
    '\x{c9}'   => 'Eacute',   # Latin capital letter e with acute
    '\x{ca}'   => 'Ecirc',    # Latin capital letter e with circumflex
    '\x{cb}'   => 'Euml',     # Latin capital letter e with diaeresis
    '\x{cc}'   => 'Igrave',   # Latin capital letter i with grave
    '\x{cd}'   => 'Iacute',   # Latin capital letter i with acute
    '\x{ce}'   => 'Icirc',    # Latin capital letter i with circumflex
    '\x{cf}'   => 'Iuml',     # Latin capital letter i with diaeresis
    '\x{d0}'   => 'ETH',      # Latin capital letter eth
    '\x{d1}'   => 'Ntilde',   # Latin capital letter n with tilde
    '\x{d2}'   => 'Ograve',   # Latin capital letter o with grave
    '\x{d3}'   => 'Oacute',   # Latin capital letter o with acute
    '\x{d4}'   => 'Ocirc',    # Latin capital letter o with circumflex
    '\x{d5}'   => 'Otilde',   # Latin capital letter o with tilde
    '\x{d6}'   => 'Ouml',     # Latin capital letter o with diaeresis
    '\x{d7}'   => 'times',    # multiplication sign
    '\x{d8}'   => 'Oslash',   # Latin capital letter o with stroke
    '\x{d9}'   => 'Ugrave',   # Latin capital letter u with grave
    '\x{da}'   => 'Uacute',   # Latin capital letter u with acute
    '\x{db}'   => 'Ucirc',    # Latin capital letter u with circumflex
    '\x{dc}'   => 'Uuml',     # Latin capital letter u with diaeresis
    '\x{dd}'   => 'Yacute',   # Latin capital letter y with acute
    '\x{de}'   => 'THORN',    # Latin capital letter thorn
    '\x{df}'   => 'szlig',    # Latin small letter sharp sXCOMMAX German Eszett
    '\x{e0}'   => 'agrave',   # Latin small letter a with grave
    '\x{e1}'   => 'aacute',   # Latin small letter a with acute
    '\x{e2}'   => 'acirc',    # Latin small letter a with circumflex
    '\x{e3}'   => 'atilde',   # Latin small letter a with tilde
    '\x{e4}'   => 'auml',     # Latin small letter a with diaeresis
    '\x{e5}'   => 'aring',    # Latin small letter a with ring above
    '\x{e6}'   => 'aelig',    # Latin lowercase ligature ae
    '\x{e7}'   => 'ccedil',   # Latin small letter c with cedilla
    '\x{e8}'   => 'egrave',   # Latin small letter e with grave
    '\x{e9}'   => 'eacute',   # Latin small letter e with acute
    '\x{ea}'   => 'ecirc',    # Latin small letter e with circumflex
    '\x{eb}'   => 'euml',     # Latin small letter e with diaeresis
    '\x{ec}'   => 'igrave',   # Latin small letter i with grave
    '\x{ed}'   => 'iacute',   # Latin small letter i with acute
    '\x{ee}'   => 'icirc',    # Latin small letter i with circumflex
    '\x{ef}'   => 'iuml',     # Latin small letter i with diaeresis
    '\x{f0}'   => 'eth',      # Latin small letter eth
    '\x{f1}'   => 'ntilde',   # Latin small letter n with tilde
    '\x{f2}'   => 'ograve',   # Latin small letter o with grave
    '\x{f3}'   => 'oacute',   # Latin small letter o with acute
    '\x{f4}'   => 'ocirc',    # Latin small letter o with circumflex
    '\x{f5}'   => 'otilde',   # Latin small letter o with tilde
    '\x{f6}'   => 'ouml',     # Latin small letter o with diaeresis
    '\x{f7}'   => 'divide',   # division sign
    '\x{f8}'   => 'oslash',   # Latin small letter o with stroke
    '\x{f9}'   => 'ugrave',   # Latin small letter u with grave
    '\x{fa}'   => 'uacute',   # Latin small letter u with acute
    '\x{fb}'   => 'ucirc',    # Latin small letter u with circumflex
    '\x{fc}'   => 'uuml',     # Latin small letter u with diaeresis
    '\x{fd}'   => 'yacute',   # Latin small letter y with acute
    '\x{fe}'   => 'thorn',    # Latin small letter thorn
    '\x{ff}'   => 'yuml',     # Latin small letter y with diaeresis
    '\x{152}'  => 'OElig',    # Latin capital ligature oe
    '\x{153}'  => 'oelig',    # Latin small ligature oe
    '\x{160}'  => 'Scaron',   # Latin capital letter s with caron
    '\x{161}'  => 'scaron',   # Latin small letter s with caron
    '\x{178}'  => 'Yuml',     # Latin capital letter y with diaeresis
    '\x{192}'  => 'fnof',     # Latin small letter f with hook
    '\x{2c6}'  => 'circ',     # modifier letter circumflex accent
    '\x{2dc}'  => 'tilde',    # small tilde
    '\x{391}'  => 'Alpha',    # Greek capital letter alpha
    '\x{392}'  => 'Beta',     # Greek capital letter beta
    '\x{393}'  => 'Gamma',    # Greek capital letter gamma
    '\x{394}'  => 'Delta',    # Greek capital letter delta
    '\x{395}'  => 'Epsilon',  # Greek capital letter epsilon
    '\x{396}'  => 'Zeta',     # Greek capital letter zeta
    '\x{397}'  => 'Eta',      # Greek capital letter eta
    '\x{398}'  => 'Theta',    # Greek capital letter theta
    '\x{399}'  => 'Iota',     # Greek capital letter iota
    '\x{39a}'  => 'Kappa',    # Greek capital letter kappa
    '\x{39b}'  => 'Lambda',   # Greek capital letter lambda
    '\x{39c}'  => 'Mu',       # Greek capital letter mu
    '\x{39d}'  => 'Nu',       # Greek capital letter nu
    '\x{39e}'  => 'Xi',       # Greek capital letter xi
    '\x{39f}'  => 'Omicron',  # Greek capital letter omicron
    '\x{3a0}'  => 'Pi',       # Greek capital letter pi
    '\x{3a1}'  => 'Rho',      # Greek capital letter rho
    '\x{3a3}'  => 'Sigma',    # Greek capital letter sigma
    '\x{3a4}'  => 'Tau',      # Greek capital letter tau
    '\x{3a5}'  => 'Upsilon',  # Greek capital letter upsilon
    '\x{3a6}'  => 'Phi',      # Greek capital letter phi
    '\x{3a7}'  => 'Chi',      # Greek capital letter chi
    '\x{3a8}'  => 'Psi',      # Greek capital letter psi
    '\x{3a9}'  => 'Omega',    # Greek capital letter omega
    '\x{3b1}'  => 'alpha',    # Greek small letter alpha
    '\x{3b2}'  => 'beta',     # Greek small letter beta
    '\x{3b3}'  => 'gamma',    # Greek small letter gamma
    '\x{3b4}'  => 'delta',    # Greek small letter delta
    '\x{3b5}'  => 'epsilon',  # Greek small letter epsilon
    '\x{3b6}'  => 'zeta',     # Greek small letter zeta
    '\x{3b7}'  => 'eta',      # Greek small letter eta
    '\x{3b8}'  => 'theta',    # Greek small letter theta
    '\x{3b9}'  => 'iota',     # Greek small letter iota
    '\x{3ba}'  => 'kappa',    # Greek small letter kappa
    '\x{3bb}'  => 'lambda',   # Greek small letter lambda
    '\x{3bc}'  => 'mu',       # Greek small letter mu
    '\x{3bd}'  => 'nu',       # Greek small letter nu
    '\x{3be}'  => 'xi',       # Greek small letter xi
    '\x{3bf}'  => 'omicron',  # Greek small letter omicron
    '\x{3c0}'  => 'pi',       # Greek small letter pi
    '\x{3c1}'  => 'rho',      # Greek small letter rho
    '\x{3c2}'  => 'sigmaf',   # Greek small letter final sigma
    '\x{3c3}'  => 'sigma',    # Greek small letter sigma
    '\x{3c4}'  => 'tau',      # Greek small letter tau
    '\x{3c5}'  => 'upsilon',  # Greek small letter upsilon
    '\x{3c6}'  => 'phi',      # Greek small letter phi
    '\x{3c7}'  => 'chi',      # Greek small letter chi
    '\x{3c8}'  => 'psi',      # Greek small letter psi
    '\x{3c9}'  => 'omega',    # Greek small letter omega
    '\x{3d1}'  => 'thetasym', # Greek theta symbol
    '\x{3d2}'  => 'upsih',    # Greek upsilon with hook symbol
    '\x{3d6}'  => 'piv',      # Greek pi symbol
    '\x{2002}' => 'ensp',     # en space
    '\x{2003}' => 'emsp',     # em space
    '\x{2009}' => 'thinsp',   # thin space
    '\x{200c}' => 'zwnj',     # zero width non-joiner
    '\x{200d}' => 'zwj',      # zero width joiner
    '\x{200e}' => 'lrm',      # left-to-right mark
    '\x{200f}' => 'rlm',      # right-to-left mark
    '\x{2013}' => 'ndash',    # en dash
    '\x{2014}' => 'mdash',    # em dash
    '\x{2018}' => 'lsquo',    # left single quotation mark
    '\x{2019}' => 'rsquo',    # right single quotation mark
    '\x{201a}' => 'sbquo',    # single low-9 quotation mark
    '\x{201c}' => 'ldquo',    # left double quotation mark
    '\x{201d}' => 'rdquo',    # right double quotation mark
    '\x{201e}' => 'bdquo',    # double low-9 quotation mark
    '\x{2020}' => 'dagger',   # dagger
    '\x{2021}' => 'Dagger',   # double dagger
    '\x{2022}' => 'bull',     # bullet
    '\x{2026}' => 'hellip',   # horizontal ellipsis
    '\x{2030}' => 'permil',   # per mille sign
    '\x{2032}' => 'prime',    # prime
    '\x{2033}' => 'Prime',    # double prime
    '\x{2039}' => 'lsaquo',   # single left-pointing angle quotation mark
    '\x{203a}' => 'rsaquo',   # single right-pointing angle quotation mark
    '\x{203e}' => 'oline',    # overline
    '\x{2044}' => 'frasl',    # fraction slash
    '\x{20ac}' => 'euro',     # euro sign
    '\x{2111}' => 'image',    # black-letter capital i
    '\x{2118}' => 'weierp',   # script capital pXCOMMAX Weierstrass p
    '\x{211c}' => 'real',     # black-letter capital r
    '\x{2122}' => 'trade',    # trademark sign
    '\x{2135}' => 'alefsym',  # alef symbol
    '\x{2190}' => 'larr',     # leftwards arrow
    '\x{2191}' => 'uarr',     # upwards arrow
    '\x{2192}' => 'rarr',     # rightwards arrow
    '\x{2193}' => 'darr',     # downwards arrow
    '\x{2194}' => 'harr',     # left right arrow
    '\x{21b5}' => 'crarr',    # downwards arrow with corner leftwards
    '\x{21d0}' => 'lArr',     # leftwards double arrow
    '\x{21d1}' => 'uArr',     # upwards double arrow
    '\x{21d2}' => 'rArr',     # rightwards double arrow
    '\x{21d3}' => 'dArr',     # downwards double arrow
    '\x{21d4}' => 'hArr',     # left right double arrow
    '\x{2200}' => 'forall',   # for all
    '\x{2202}' => 'part',     # partial differential
    '\x{2203}' => 'exist',    # there exists
    '\x{2205}' => 'empty',    # empty set
    '\x{2207}' => 'nabla',    # nabla
    '\x{2208}' => 'isin',     # element of
    '\x{2209}' => 'notin',    # not an element of
    '\x{220b}' => 'ni',       # contains as member
    '\x{220f}' => 'prod',     # n-ary product
    '\x{2211}' => 'sum',      # n-ary summation
    '\x{2212}' => 'minus',    # minus sign
    '\x{2217}' => 'lowast',   # asterisk operator
    '\x{221a}' => 'radic',    # square root
    '\x{221d}' => 'prop',     # proportional to
    '\x{221e}' => 'infin',    # infinity
    '\x{2220}' => 'ang',      # angle
    '\x{2227}' => 'and',      # logical and
    '\x{2228}' => 'or',       # logical or
    '\x{2229}' => 'cap',      # intersection
    '\x{222a}' => 'cup',      # union
    '\x{222b}' => 'int',      # integral
    '\x{2234}' => 'there4',   # therefore
    '\x{223c}' => 'sim',      # tilde operator
    '\x{2245}' => 'cong',     # congruent to
    '\x{2248}' => 'asymp',    # almost equal to
    '\x{2260}' => 'ne',       # not equal to
    '\x{2261}' => 'equiv',    # identical toXCOMMAX equivalent to
    '\x{2264}' => 'le',       # less-than or equal to
    '\x{2265}' => 'ge',       # greater-than or equal to
    '\x{2282}' => 'sub',      # subset of
    '\x{2283}' => 'sup',      # superset of
    '\x{2284}' => 'nsub',     # not a subset of
    '\x{2286}' => 'sube',     # subset of or equal to
    '\x{2287}' => 'supe',     # superset of or equal to
    '\x{2295}' => 'oplus',    # circled plus
    '\x{2297}' => 'otimes',   # circled times
    '\x{22a5}' => 'perp',     # up tack
    '\x{22c5}' => 'sdot',     # dot operator
    '\x{2308}' => 'lceil',    # left ceiling
    '\x{2309}' => 'rceil',    # right ceiling
    '\x{230a}' => 'lfloor',   # left floor
    '\x{230b}' => 'rfloor',   # right floor
    '\x{2329}' => 'lang',     # left-pointing angle bracket
    '\x{232a}' => 'rang',     # right-pointing angle bracket
    '\x{25ca}' => 'loz',      # lozenge
    '\x{2660}' => 'spades',   # black spade suit
    '\x{2663}' => 'clubs',    # black club suit
    '\x{2665}' => 'hearts',   # black heart suit
    '\x{2666}' => 'diams',    # black diamond suit
);

# Reverse the entity map for use in decoding
my %UNICODE_MAP = reverse %ENTITY_MAP;

sub encode_character {
    my ($self, $immune, $c) = @_;

    # immune chars: as-is
    return $c if any { $_ eq $c } @$immune;

    # alphanum chars: as-is
    return $c if $c =~ /[a-zA-Z0-9]/;

    # control chars: Unicode Replacement Character Entity
    my $o = ord($c);
    return '&#xfffd;'
        if ($o <= 0x1f && $o != "\t" && $o != "\n" && $o != "\r")
        or ($o >= 0x7f && $o <= 0x9f);

    # mapped entity: mapped entity
    return "&$ENTITY_MAP{$c};" if defined $ENTITY_MAP{$c};

    # everything else: hex code entity
    return sprintf '&#x%x;', $o;
}

sub decode_character {
    my ($self, $input) = @_;

    # &#x...; -> that Unicode character from hexidecimal
    return chr(hex($1)) if $$input =~ s/^&#[xX]([0-9a-fA-F]+);//;

    # &#...; -> that Unicode character from decimal
    return chr(0+$1) if $$input =~ s/^&#([0-9]+);//;

    # &...; -> the mapped Unicode char
    if ($$input =~ s/^&([a-zA-Z0-9]{2,8})(;?)//) {
        my $entity = $1;
        my $semi   = $2;

        # Backup until we find a matching entity (if any)
        while (length $entity > 0) {
            return $UNICODE_MAP{$entity} if defined $UNICODE_MAP{$entity};

            # Put back the semi-colon
            if ($semi) {
                $$input = $semi . $$input;
                $semi = '';
            }

            # If it's 2 or shorter now, then no match was found
            if (length $entity <= 2) {
                $$input = $entity . $$input;
                $entity = '';
            }

            # There's still a chance for a match, try again one less
            else {
                $$input = substr($entity, -1, 1, '') . $$input;
            }
        }

        return '&';
    }

    # Otherwise, NEXT!
    return substr $$input, 0, 1, ''; 
}

}

__PACKAGE__->meta->make_immutable;
