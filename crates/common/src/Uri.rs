//! URI parser compliant with 3GPP TS 29.500 §5.2.10.
//!
//! Implements the generic URI syntax defined in IETF RFC 3986, restricted to
//! ASCII as required by the 3GPP 5G Service-Based Interface (SBI) specifications.
//!
//! URI structure: `scheme ":" [ "//" authority ] path [ "?" query ] [ "#" fragment ]`
//!
//! Percent-encoded characters are decoded during parsing. Delimiter characters
//! encountered in their percent-encoded form (e.g. `%2F` for `/`) are treated
//! as literal data within their component, not as structural delimiters.
//!
//! Each type implements [`fmt::Display`] to re-encode the URI with correct
//! percent-encoding per component. [`Uri`] additionally implements
//! [`serde::Serialize`] (behind the `serde` feature) as the inverse of its
//! [`serde::Deserialize`] implementation.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::VecDeque;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use thiserror::Error;

// RFC 3986 §2.3 - Character class macros for use in match patterns.

/// `ALPHA = %x41-5A / %x61-7A`
macro_rules! alpha {
    () => {
        'a'..='z' | 'A'..='Z'
    };
}

/// `DIGIT = %x30-39`
macro_rules! digit {
    () => {
        '0'..='9'
    };
}

/// `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"`
macro_rules! unreserved {
    () => {
        alpha!() | digit!() | '-' | '.' | '_' | '~'
    };
}

/// `gen-delims = ":" / "/" / "?" / "#" / "[" / "]" / "@"`
macro_rules! gen_delims {
    () => {
        ':' | '/' | '?' | '#' | '[' | ']' | '@'
    };
}

/// `sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="`
macro_rules! sub_delims {
    () => {
        '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '='
    };
}

/// `reserved = gen-delims / sub-delims`
macro_rules! reserved {
    () => {
        gen_delims!() | sub_delims!()
    };
}

/// Characters that 3GPP TS 29.500 §5.2.10 requires to be percent-encoded
/// beyond the standard RFC 3986 reserved set.
macro_rules! reserved_3gpp {
    () => {
        '"' | '%' | '{' | '}' | ' '
    };
}

// Delimiter sets used to detect component boundaries during parsing.

/// Characters that terminate the authority component.
/// Per RFC 3986 §3.2, authority ends at `/`, `?`, or `#`.
macro_rules! authority_terminator {
    () => {
        '/' | '?' | '#'
    };
}

/// Characters that terminate the path component.
/// Per RFC 3986 §3.3, path ends at `?` or `#`.
macro_rules! path_terminator {
    () => {
        '?' | '#'
    };
}

/// Characters that terminate the query component.
/// Per RFC 3986 §3.4, query ends at `#`.
macro_rules! query_terminator {
    () => {
        '#'
    };
}

/// A parsed URI as defined by 3GPP TS 29.500 §5.2.10 and IETF RFC 3986.
///
/// Represents the decomposed components of an absolute URI:
/// ```text
/// scheme ":" [ "//" authority ] path [ "?" query ] [ "#" fragment ]
/// ```
///
/// Only absolute URIs (those with a scheme) are supported. Relative references
/// are rejected during parsing.
#[derive(Debug, Clone)]
pub struct Uri {
    /// The scheme component (e.g. `http`, `https`).
    pub scheme: Scheme,
    /// The authority component, present when the URI contains `//`.
    pub authority: Option<Authority>,
    /// The path component, split into decoded segments.
    pub path: Path,
    /// The query component (after `?`, before `#`), if present.
    pub query: Option<Query>,
    /// The fragment component (after `#`), if present.
    pub fragment: Option<Fragment>,
}

/// The scheme component of a URI (e.g. `http`, `https`, `urn`).
///
/// Per RFC 3986 §3.1: `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`
#[derive(Debug, Clone)]
pub struct Scheme {
    /// The scheme name in its original case.
    pub name: String,
}

/// The authority component of a URI, present when the URI begins with `//`.
///
/// Per RFC 3986 §3.2: `authority = [ userinfo "@" ] host [ ":" port ]`
#[derive(Debug, Clone)]
pub struct Authority {
    /// The userinfo subcomponent (before `@`), if present.
    pub user_info: Option<UserInfo>,
    /// The host subcomponent (IP address or domain name).
    pub host: Host,
    /// The port number, if present and non-empty.
    pub port: Option<u16>,
}

/// The userinfo subcomponent of a URI authority.
///
/// Per RFC 3986 §3.2.1: `userinfo = *( unreserved / pct-encoded / sub-delims / ":" )`
///
/// The first `:` splits the userinfo into username and password.
/// Use of the `user:password` format is deprecated by RFC 3986 §3.2.1.
#[derive(Debug, Clone)]
pub struct UserInfo {
    /// The username portion (before the first `:`).
    pub username: String,
    /// The password portion (after the first `:`), if a `:` was present.
    pub password: Option<String>,
}

/// The host subcomponent of a URI authority.
///
/// Per RFC 3986 §3.2.2, a host is identified as one of three forms
/// based on syntax:
/// - Brackets indicate an IP-literal (typically IPv6)
/// - Four dot-separated decimal octets indicate IPv4
/// - Anything else is a registered domain name
#[derive(Debug, Clone)]
pub enum Host {
    /// An IPv6 address (or IPv4-mapped IPv6) enclosed in brackets
    /// (e.g. `[::1]`, `[::ffff:192.168.1.1]`).
    IpLiteral(IpAddr),
    /// An IPv4 address in dotted-decimal notation (e.g. `192.168.1.1`).
    Ipv4(IpAddr),
    /// A registered domain name (e.g. `example.com`).
    DomainName(String),
}

/// The path component of a URI, split into decoded segments.
///
/// Per RFC 3986 §3.3, the path is a sequence of segments delimited by `/`.
/// The leading `/` is consumed during parsing and not stored. Each segment
/// is percent-decoded.
///
/// Examples:
/// - `/a/b/c` produces `["a", "b", "c"]`
/// - `/a/b/c/` produces `["a", "b", "c", ""]`
/// - `/` produces `[""]`
/// - (no path) produces `[""]`
#[derive(Debug, Clone)]
pub struct Path {
    /// The decoded path segments, in order.
    pub segments: Vec<String>,
}

/// The query component of a URI (the portion after `?` and before `#`).
///
/// Per RFC 3986 §3.4: `query = *( pchar / "/" / "?" )`
///
/// Stored in percent-decoded form. The leading `?` delimiter is not included.
#[derive(Debug, Clone)]
pub struct Query {
    /// The decoded query string.
    pub query: String,
}

/// The fragment component of a URI (the portion after `#`).
///
/// Per RFC 3986 §3.5: `fragment = *( pchar / "/" / "?" )`
///
/// Stored in percent-decoded form. The leading `#` delimiter is not included.
#[derive(Debug, Clone)]
pub struct Fragment {
    /// The decoded fragment string.
    pub fragment: String,
}

// --- Serde implementations (encoding) ---


/// Deserializes a [`Uri`] from a JSON string value.
///
/// The input must be a valid ASCII string containing an absolute URI.
/// Components are parsed sequentially: scheme, authority, path, query,
/// fragment. Percent-encoded sequences are decoded during parsing.
#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let uri = String::deserialize(deserializer)?;
        if !uri.is_ascii() {
            return Err(serde::de::Error::custom("URI contains non-ASCII characters"));
        }

        let mut uri: VecDeque<char> = uri.chars().collect();

        // Parse scheme
        let scheme = match Scheme::parse(&mut uri) {
            Ok(scheme) => scheme,
            Err(err) => return Err(serde::de::Error::custom(err)),
        };

        // Parse authority
        let authority = match Authority::parse(&mut uri) {
            Ok(authority) => authority,
            Err(err) => return Err(serde::de::Error::custom(err)),
        };

        // Parse path
        let path = match Path::parse(&mut uri) {
            Ok(path) => path,
            Err(err) => return Err(serde::de::Error::custom(err)),
        };

        // Parse query
        let query = match Query::parse(&mut uri) {
            Ok(query) => query,
            Err(err) => return Err(serde::de::Error::custom(err)),
        };

        // Parse fragment
        let fragment = match Fragment::parse(&mut uri) {
            Ok(fragment) => fragment,
            Err(err) => return Err(serde::de::Error::custom(err)),
        };

        Ok(Uri {
            scheme,
            authority,
            path,
            query,
            fragment,
        })
    }
}

/// Serializes a [`Uri`] as a string using its [`fmt::Display`] implementation.
///
/// Percent-encodes characters in each component according to the rules
/// defined in RFC 3986 for that component's position.
#[cfg(feature = "serde")]
impl Serialize for Uri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// --- Display implementations (encoding) ---

/// Re-encodes the full URI: `scheme ":" [ "//" authority ] path [ "?" query ] [ "#" fragment ]`
impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.scheme)?;
        if let Some(authority) = &self.authority {
            write!(f, "//{}", authority)?;
        }
        write!(f, "{}", self.path)?;
        if let Some(query) = &self.query {
            write!(f, "?{}", query)?;
        }
        if let Some(fragment) = &self.fragment {
            write!(f, "#{}", fragment)?;
        }
        Ok(())
    }
}

/// Outputs the scheme name verbatim
impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// Re-encodes the authority: `[ userinfo "@" ] host [ ":" port ]`
impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(user_info) = &self.user_info {
            write!(f, "{}@", user_info)?;
        }
        write!(f, "{}", self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }
        Ok(())
    }
}

/// Re-encodes the userinfo, percent-encoding characters outside
/// `unreserved / sub-delims` (plus `:` in the password portion).
impl fmt::Display for UserInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        pct_encode_to(f, &self.username, |c| matches!(c, unreserved!() | sub_delims!()))?;
        if let Some(password) = &self.password {
            write!(f, ":")?;
            pct_encode_to(f, password, |c| matches!(c, unreserved!() | sub_delims!() | ':'))?;
        }
        Ok(())
    }
}

/// Re-encodes the host. IP-literals are wrapped in brackets, IPv4 and
/// domain names are output directly (domain names are percent-encoded).
impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::IpLiteral(addr) => write!(f, "[{}]", addr),
            Host::Ipv4(addr) => write!(f, "{}", addr),
            Host::DomainName(name) => pct_encode_to(f, name, |c| matches!(c, unreserved!() | sub_delims!())),
        }
    }
}

/// Re-encodes the path as `"/" segment *( "/" segment )`.
///
/// Each segment is percent-encoded for the `pchar` character set
/// (`unreserved / sub-delims / ":" / "@"`).
impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, segment) in self.segments.iter().enumerate() {
            if i > 0 || !segment.is_empty() || self.segments.len() > 1 {
                write!(f, "/")?;
            }
            pct_encode_to(f, segment, |c| matches!(c, unreserved!() | sub_delims!() | ':' | '@'))?;
        }
        Ok(())
    }
}

/// Re-encodes the query string, percent-encoding characters outside
/// `pchar / "/" / "?"`.
impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        pct_encode_to(f, &self.query, |c| matches!(c, unreserved!() | sub_delims!() | ':' | '@' | '/' | '?'))
    }
}

/// Re-encodes the fragment string, percent-encoding characters outside
/// `pchar / "/" / "?"`.
impl fmt::Display for Fragment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        pct_encode_to(f, &self.fragment, |c| matches!(c, unreserved!() | sub_delims!() | ':' | '@' | '/' | '?'))
    }
}

// --- Parsing implementations ---

/// Errors that can occur when parsing a URI string.
#[derive(Debug, Error)]
pub enum UriParseError {
    /// The scheme component is missing or contains invalid characters.
    #[error("URI contains invalid scheme")]
    SchemeInvalid,
    /// The userinfo component contains invalid characters.
    #[error("URI contains invalid userinfo")]
    UserInfoInvalid,
    /// The host or port component is malformed.
    #[error("URI contains invalid host")]
    HostInvalid,
    /// The path component contains invalid characters.
    #[error("URI contains invalid path")]
    PathInvalid,
    /// The query component contains invalid characters.
    #[error("URI contains invalid query")]
    QueryInvalid,
    /// The fragment component contains invalid characters.
    #[error("URI contains invalid fragment")]
    FragmentInvalid,
    /// A `%`-encoded sequence is malformed (not followed by two hex digits).
    #[error("URI contains invalid percent-encoded characters")]
    PctDecodeInvalid,
}

impl Scheme {
    /// Parses the scheme component from the front of the deque.
    ///
    /// Consumes characters up to and including the `:` delimiter.
    /// The first character must be ALPHA; subsequent characters may be
    /// ALPHA, DIGIT, `+`, `-`, or `.`.
    fn parse(uri: &mut VecDeque<char>) -> Result<Self, UriParseError> {
        let mut scheme: Vec<char> = Vec::new();

        match uri.front() {
            Some(alpha!()) => {
                scheme.push(uri.pop_front().unwrap());
            }
            _ => return Err(UriParseError::SchemeInvalid),
        }

        loop {
            match uri.front() {
                Some(':') => {
                    uri.pop_front();
                    break;
                }
                Some(alpha!() | digit!() | '+' | '-' | '.') => {
                    scheme.push(uri.pop_front().unwrap());
                }
                Some(_) | None => return Err(UriParseError::SchemeInvalid),
            }
        }

        Ok(Self { name: scheme.into_iter().collect() })
    }
}

impl Authority {
    /// Parses the authority component if the deque starts with `//`.
    ///
    /// Consumes the `//` prefix, then parses userinfo, host, and port
    /// subcomponents in sequence. Returns `None` if no `//` prefix is present.
    fn parse(uri: &mut VecDeque<char>) -> Result<Option<Self>, UriParseError> {
        if uri.get(0) != Some(&'/') || uri.get(1) != Some(&'/') {
            return Ok(None);
        }

        uri.pop_front();
        uri.pop_front();

        let user_info = UserInfo::parse(uri)?;
        let host = Host::parse(uri)?;
        let port = Self::parse_port(uri)?;

        Ok(Some(Self { user_info, host, port }))
    }

    /// Parses the port subcomponent if the deque starts with `:`.
    ///
    /// Consumes the `:` delimiter and any following digits. Returns `None`
    /// if no `:` is present or if no digits follow it (empty port, which
    /// is valid per RFC 3986). The port value must fit in a `u16` (0-65535).
    fn parse_port(uri: &mut VecDeque<char>) -> Result<Option<u16>, UriParseError> {
        match uri.front() {
            Some(':') => {
                uri.pop_front();
            }
            _ => {
                return Ok(None);
            }
        }

        let mut port: Vec<char> = Vec::new();
        while let Some(c) = uri.front() {
            match c {
                authority_terminator!() => {
                    break;
                }
                digit!() => port.push(uri.pop_front().unwrap()),
                _ => return Err(UriParseError::HostInvalid),
            }
        }

        if port.is_empty() {
            return Ok(None);
        }

        match u16::from_str_radix(&port.into_iter().collect::<String>(), 10) {
            Ok(port) => Ok(Some(port)),
            Err(_) => Err(UriParseError::HostInvalid),
        }
    }
}

impl UserInfo {
    /// Parses the userinfo subcomponent if present.
    ///
    /// Uses non-consuming look-ahead to detect `@` within the authority
    /// bounds (before any `/`, `?`, or `#`). If found, consumes characters
    /// up to and including `@`. The first `:` encountered splits the content
    /// into username and password fields. Returns `None` if no `@` is found
    /// before an authority terminator.
    pub fn parse(uri: &mut VecDeque<char>) -> Result<Option<Self>, UriParseError> {
        // Look ahead for a userinfo component
        let mut has_user_info = false;
        for c in uri.iter() {
            match c {
                '@' => {
                    has_user_info = true;
                    break;
                }
                authority_terminator!() => {
                    break;
                }
                _ => {}
            }
        }

        if !has_user_info {
            return Ok(None);
        }

        let mut password: Option<Vec<char>> = None;
        let mut username: Vec<char> = Vec::new();

        while let Some(c) = uri.front() {
            match c {
                '@' => {
                    uri.pop_front();
                    break;
                }
                ':' => {
                    uri.pop_front();
                    password = Some(Vec::new());
                    break;
                }
                '%' => {
                    uri.pop_front();
                    username.push(pct_decode(uri)?);
                }
                unreserved!() | sub_delims!() => {
                    username.push(uri.pop_front().unwrap());
                }
                _ => {
                    return Err(UriParseError::UserInfoInvalid);
                }
            }
        }

        if let Some(password) = password.as_mut() {
            while let Some(c) = uri.front() {
                match c {
                    '@' => {
                        uri.pop_front();
                        break;
                    }
                    '%' => {
                        uri.pop_front();
                        password.push(pct_decode(uri)?);
                    }
                    unreserved!() | sub_delims!() | ':' => {
                        password.push(uri.pop_front().unwrap());
                    }
                    _ => {
                        return Err(UriParseError::UserInfoInvalid);
                    }
                }
            }
        }

        let username = username.into_iter().collect();
        let password = password.map(|p| p.into_iter().collect());

        Ok(Some(Self { username, password }))
    }
}

impl Host {
    /// Parses the host subcomponent from the front of the deque.
    ///
    /// Dispatches to [`Self::parse_ip_literal`] if the deque starts with `[`,
    /// otherwise to [`Self::parse_other`] for IPv4 addresses and domain names.
    /// Does not consume the trailing delimiter (`:`, `/`, `?`, `#`).
    pub fn parse(uri: &mut VecDeque<char>) -> Result<Host, UriParseError> {
        let is_ip_literal = uri.front() == Some(&'[');

        match is_ip_literal {
            true => Ok(Host::IpLiteral(Self::parse_ip_literal(uri)?)),
            false => Ok(Self::parse_other(uri)?),
        }
    }

    /// Parses an IP-literal host enclosed in brackets (`[` ... `]`).
    ///
    /// Consumes the opening `[`, collects hex digits, `:`, and `.`
    /// (for IPv4-mapped addresses like `[::ffff:192.168.1.1]`), then
    /// consumes the closing `]`. Validates the result with [`IpAddr::from_str`].
    fn parse_ip_literal(uri: &mut VecDeque<char>) -> Result<IpAddr, UriParseError> {
        let mut host: Vec<char> = Vec::new();

        uri.pop_front();

        loop {
            match uri.pop_front() {
                Some(']') => break,
                Some(c @ 'a'..='f' | c @ 'A'..='F' | c @ '0'..='9' | c @ ':' | c @ '.') => host.push(c),
                Some(_) | None => return Err(UriParseError::HostInvalid),
            }
        }

        match IpAddr::from_str(&host.into_iter().collect::<String>()) {
            Ok(ip_addr) => Ok(ip_addr),
            Err(_) => Err(UriParseError::HostInvalid),
        }
    }

    /// Parses a host as either an IPv4 address or a registered domain name.
    ///
    /// Splits the input into dot-delimited portions. If there are exactly 4
    /// portions and each parses as a `u8` (0-255), the host is treated as an
    /// IPv4 address. Otherwise, the portions are rejoined with `.` as a domain
    /// name. Does not consume the trailing delimiter.
    fn parse_other(uri: &mut VecDeque<char>) -> Result<Host, UriParseError> {
        let mut portions: Vec<String> = Vec::new();

        // Consume into portions delimited by '.'
        let mut portion = Vec::new();
        loop {
            match uri.front() {
                Some(':' | authority_terminator!()) | None => {
                    portions.push(portion.into_iter().collect());
                    break;
                }
                Some('%') => {
                    uri.pop_front();
                    portion.push(pct_decode(uri)?)
                }
                Some('.') => {
                    uri.pop_front();
                    portions.push(portion.into_iter().collect());
                    portion = Vec::new();
                }
                Some(unreserved!() | sub_delims!()) => {
                    portion.push(uri.pop_front().unwrap());
                }
                Some(_) => return Err(UriParseError::HostInvalid),
            }
        }

        // Attempt to parse IPv4 format
        if portions.len() == 4 {
            let mut ipv4_format = true;
            let mut ip_octets: [u8; 4] = [0; 4];

            for (i, portion) in portions.iter().enumerate() {
                match u8::from_str_radix(portion, 10) {
                    Ok(octet) => ip_octets[i] = octet,
                    Err(_) => {
                        ipv4_format = false;
                        break;
                    }
                }
            }

            if ipv4_format {
                let ip = Ipv4Addr::from_octets(ip_octets);
                return Ok(Host::Ipv4(IpAddr::V4(ip)));
            }
        }

        // Otherwise, assume domain name format
        let host = portions.join(".");
        Ok(Host::DomainName(host))
    }
}

impl Path {
    /// Parses the path component from the front of the deque.
    ///
    /// Consumes the leading `/` if present, then collects segments delimited
    /// by `/`. Stops at a path terminator (`?` or `#`) without consuming it.
    /// Each segment is percent-decoded during parsing.
    pub fn parse(uri: &mut VecDeque<char>) -> Result<Self, UriParseError> {
        let mut segments: Vec<String> = Vec::new();

        if uri.front() == Some(&'/') {
            uri.pop_front();
        }

        let mut segment: Vec<char> = Vec::new();
        while let Some(c) = uri.front() {
            match c {
                path_terminator!() => {
                    break;
                }
                '/' => {
                    uri.pop_front();
                    segments.push(segment.iter().collect());
                    segment = Vec::new();
                }
                '%' => {
                    uri.pop_front();
                    segment.push(pct_decode(uri)?);
                }
                unreserved!() | sub_delims!() | ':' | '@' => segment.push(uri.pop_front().unwrap()),
                _ => return Err(UriParseError::PathInvalid),
            }
        }

        segments.push(segment.iter().collect());

        Ok(Self { segments })
    }
}

impl Query {
    /// Parses the query component if the deque starts with `?`.
    ///
    /// Consumes the `?` delimiter and collects characters until `#` or
    /// end-of-input. Does not consume the `#` delimiter. Returns `None`
    /// if no `?` is present. The query string is percent-decoded.
    pub fn parse(uri: &mut VecDeque<char>) -> Result<Option<Self>, UriParseError> {
        let mut query: Vec<char> = Vec::new();

        if uri.front() == Some(&'?') {
            uri.pop_front();
        } else {
            return Ok(None);
        }

        while let Some(c) = uri.front() {
            match c {
                query_terminator!() => break,
                '%' => {
                    uri.pop_front();
                    query.push(pct_decode(uri)?);
                }
                unreserved!() | sub_delims!() | '/' | '?' | ':' | '@' => {
                    query.push(uri.pop_front().unwrap());
                }
                _ => return Err(UriParseError::QueryInvalid),
            }
        }

        Ok(Some(Self { query: query.into_iter().collect() }))
    }
}

impl Fragment {
    /// Parses the fragment component if the deque starts with `#`.
    ///
    /// Consumes the `#` delimiter and all remaining characters in the deque.
    /// Returns `None` if no `#` is present. The fragment string is
    /// percent-decoded.
    pub fn parse(uri: &mut VecDeque<char>) -> Result<Option<Self>, UriParseError> {
        let mut fragment: Vec<char> = Vec::new();

        if uri.front() == Some(&'#') {
            uri.pop_front();
        } else {
            return Ok(None);
        }

        while let Some(c) = uri.pop_front() {
            match c {
                '%' => fragment.push(pct_decode(uri)?),
                unreserved!() | sub_delims!() | '/' | '?' | ':' | '@' => {
                    fragment.push(c);
                }
                _ => return Err(UriParseError::FragmentInvalid),
            }
        }

        Ok(Some(Self {
            fragment: fragment.into_iter().collect(),
        }))
    }
}

// --- Percent-encoding helpers ---

/// Decodes a single percent-encoded sequence from the deque.
///
/// Expects the `%` to have already been consumed by the caller. Pops two
/// hex digits from the deque and converts them to the corresponding ASCII
/// character.
fn pct_decode(uri: &mut VecDeque<char>) -> Result<char, UriParseError> {
    macro_rules! pop_digit {
        () => {
            match uri.pop_front() {
                Some(c) => match c {
                    'a'..='f' | 'A'..='F' | '0'..='9' => c,
                    _ => return Err(UriParseError::PctDecodeInvalid),
                },
                None => return Err(UriParseError::PctDecodeInvalid),
            }
        };
    }

    let digit_1 = pop_digit!();
    let digit_2 = pop_digit!();

    let hex = format!("{}{}", digit_1, digit_2);

    let c = match u8::from_str_radix(&hex, 16) {
        Ok(c) => c,
        Err(_) => return Err(UriParseError::PctDecodeInvalid),
    };

    let c = match char::from_u32(c as u32) {
        Some(c) => c,
        None => return Err(UriParseError::PctDecodeInvalid),
    };

    Ok(c)
}

/// Writes `s` to the formatter, percent-encoding any character for which
/// `is_allowed` returns `false`.
///
/// Characters that were decoded from `%XX` sequences during parsing are
/// re-encoded here using uppercase hex digits, as recommended by
/// RFC 3986 §2.1.
fn pct_encode_to<F>(f: &mut fmt::Formatter<'_>, s: &str, is_allowed: F) -> fmt::Result
where
    F: Fn(char) -> bool,
{
    for c in s.chars() {
        if is_allowed(c) {
            write!(f, "{}", c)?;
        } else {
            write!(f, "%{:02X}", c as u32 as u8)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a URI string without requiring the serde feature.
    fn parse_uri(input: &str) -> Result<Uri, UriParseError> {
        assert!(input.is_ascii(), "test input must be ASCII");
        let mut deque: VecDeque<char> = input.chars().collect();
        let scheme = Scheme::parse(&mut deque)?;
        let authority = Authority::parse(&mut deque)?;
        let path = Path::parse(&mut deque)?;
        let query = Query::parse(&mut deque)?;
        let fragment = Fragment::parse(&mut deque)?;
        Ok(Uri { scheme, authority, path, query, fragment })
    }

    /// Asserts that the host is a [`Host::DomainName`] with the expected value.
    #[track_caller]
    fn assert_domain(host: &Host, expected: &str) {
        match host {
            Host::DomainName(name) => assert_eq!(name, expected),
            other => panic!("expected DomainName(\"{expected}\"), got {other:?}"),
        }
    }

    /// Asserts that the host is a [`Host::Ipv4`] with the expected address.
    #[track_caller]
    fn assert_ipv4(host: &Host, expected: &str) {
        match host {
            Host::Ipv4(addr) => assert_eq!(*addr, IpAddr::from_str(expected).unwrap()),
            other => panic!("expected Ipv4({expected}), got {other:?}"),
        }
    }

    /// Asserts that the host is a [`Host::IpLiteral`] with the expected address.
    #[track_caller]
    fn assert_ip_literal(host: &Host, expected: &str) {
        match host {
            Host::IpLiteral(addr) => assert_eq!(*addr, IpAddr::from_str(expected).unwrap()),
            other => panic!("expected IpLiteral({expected}), got {other:?}"),
        }
    }

    // ==================== Scheme ====================

    #[test]
    fn scheme_common_names() {
        assert_eq!(parse_uri("http://h").unwrap().scheme.name, "http");
        assert_eq!(parse_uri("https://h").unwrap().scheme.name, "https");
    }

    #[test]
    fn scheme_single_alpha() {
        assert_eq!(parse_uri("a://h").unwrap().scheme.name, "a");
    }

    #[test]
    fn scheme_all_allowed_chars() {
        // RFC 3986: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
        assert_eq!(parse_uri("a1+-.z://h").unwrap().scheme.name, "a1+-.z");
    }

    #[test]
    fn scheme_preserves_case() {
        assert_eq!(parse_uri("HTTP://h").unwrap().scheme.name, "HTTP");
        assert_eq!(parse_uri("HtTp://h").unwrap().scheme.name, "HtTp");
    }

    #[test]
    fn scheme_starting_with_digit_is_error() {
        assert!(parse_uri("1http://h").is_err());
    }

    #[test]
    fn scheme_empty_is_error() {
        assert!(parse_uri("://h").is_err());
    }

    #[test]
    fn scheme_missing_colon_is_error() {
        assert!(parse_uri("http").is_err());
    }

    // ==================== Authority presence ====================

    #[test]
    fn authority_present_with_double_slash() {
        let uri = parse_uri("http://host/path").unwrap();
        assert!(uri.authority.is_some());
    }

    #[test]
    fn authority_absent_without_double_slash() {
        let uri = parse_uri("mailto:user@example.com").unwrap();
        assert!(uri.authority.is_none());
        // '@' is valid in path-rootless via pchar
        assert_eq!(uri.path.segments, vec!["user@example.com"]);
    }

    // ==================== Host - Domain names ====================

    #[test]
    fn host_simple_domain() {
        let uri = parse_uri("http://example.com/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "example.com");
    }

    #[test]
    fn host_subdomain() {
        let uri = parse_uri("http://sub.example.com/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "sub.example.com");
    }

    #[test]
    fn host_localhost() {
        let uri = parse_uri("http://localhost/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "localhost");
    }

    #[test]
    fn host_five_dot_parts_is_domain() {
        let uri = parse_uri("http://a.b.c.d.e/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "a.b.c.d.e");
    }

    #[test]
    fn host_three_dot_parts_is_domain() {
        let uri = parse_uri("http://a.b.c/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "a.b.c");
    }

    #[test]
    fn host_3gpp_fqdn() {
        let uri = parse_uri("http://nrf.5gc.mnc001.mcc001.3gppnetwork.org/").unwrap();
        assert_domain(
            &uri.authority.unwrap().host,
            "nrf.5gc.mnc001.mcc001.3gppnetwork.org",
        );
    }

    // ==================== Host - IPv4 ====================

    #[test]
    fn host_ipv4_typical() {
        let uri = parse_uri("http://192.168.1.1/").unwrap();
        assert_ipv4(&uri.authority.unwrap().host, "192.168.1.1");
    }

    #[test]
    fn host_ipv4_all_zeros() {
        let uri = parse_uri("http://0.0.0.0/").unwrap();
        assert_ipv4(&uri.authority.unwrap().host, "0.0.0.0");
    }

    #[test]
    fn host_ipv4_max_octets() {
        let uri = parse_uri("http://255.255.255.255/").unwrap();
        assert_ipv4(&uri.authority.unwrap().host, "255.255.255.255");
    }

    #[test]
    fn host_ipv4_loopback() {
        let uri = parse_uri("http://127.0.0.1/").unwrap();
        assert_ipv4(&uri.authority.unwrap().host, "127.0.0.1");
    }

    #[test]
    fn host_octet_overflow_falls_back_to_domain() {
        let uri = parse_uri("http://256.1.1.1/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "256.1.1.1");
    }

    // ==================== Host - IPv6 literals ====================

    #[test]
    fn host_ipv6_loopback() {
        let uri = parse_uri("http://[::1]/").unwrap();
        assert_ip_literal(&uri.authority.unwrap().host, "::1");
    }

    #[test]
    fn host_ipv6_full_address() {
        let uri = parse_uri("http://[2001:db8:85a3::8a2e:370:7334]/").unwrap();
        assert_ip_literal(&uri.authority.unwrap().host, "2001:db8:85a3::8a2e:370:7334");
    }

    #[test]
    fn host_ipv6_mapped_v4() {
        let uri = parse_uri("http://[::ffff:192.168.1.1]/").unwrap();
        assert_ip_literal(&uri.authority.unwrap().host, "::ffff:192.168.1.1");
    }

    // ==================== Port ====================

    #[test]
    fn port_present() {
        let auth = parse_uri("http://host:8080/").unwrap().authority.unwrap();
        assert_eq!(auth.port, Some(8080));
    }

    #[test]
    fn port_absent() {
        let auth = parse_uri("http://host/").unwrap().authority.unwrap();
        assert_eq!(auth.port, None);
    }

    #[test]
    fn port_empty_after_colon() {
        // RFC 3986: port = *DIGIT — empty is valid, means absent
        let auth = parse_uri("http://host:/").unwrap().authority.unwrap();
        assert_eq!(auth.port, None);
    }

    #[test]
    fn port_zero() {
        let auth = parse_uri("http://host:0/").unwrap().authority.unwrap();
        assert_eq!(auth.port, Some(0));
    }

    #[test]
    fn port_max_u16() {
        let auth = parse_uri("http://host:65535/").unwrap().authority.unwrap();
        assert_eq!(auth.port, Some(65535));
    }

    #[test]
    fn port_overflow_is_error() {
        assert!(parse_uri("http://host:65536/").is_err());
    }

    #[test]
    fn port_non_digit_is_error() {
        assert!(parse_uri("http://host:abc/").is_err());
    }

    #[test]
    fn port_3gpp_nrf_default() {
        let auth = parse_uri("https://nrf:29510/").unwrap().authority.unwrap();
        assert_eq!(auth.port, Some(29510));
    }

    // ==================== UserInfo ====================

    #[test]
    fn userinfo_username_only() {
        let info = parse_uri("http://user@host/").unwrap()
            .authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "user");
        assert_eq!(info.password, None);
    }

    #[test]
    fn userinfo_with_password() {
        let info = parse_uri("http://user:pass@host/").unwrap()
            .authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "user");
        assert_eq!(info.password.as_deref(), Some("pass"));
    }

    #[test]
    fn userinfo_empty_password() {
        let info = parse_uri("http://user:@host/").unwrap()
            .authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "user");
        assert_eq!(info.password.as_deref(), Some(""));
    }

    #[test]
    fn userinfo_password_with_colons() {
        // RFC 3986: ':' is valid in the password portion of userinfo
        let info = parse_uri("http://user:p:a:ss@host/").unwrap()
            .authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "user");
        assert_eq!(info.password.as_deref(), Some("p:a:ss"));
    }

    #[test]
    fn userinfo_percent_encoded() {
        let info = parse_uri("http://us%40er:p%40ss@host/").unwrap()
            .authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "us@er");
        assert_eq!(info.password.as_deref(), Some("p@ss"));
    }

    #[test]
    fn userinfo_absent() {
        let auth = parse_uri("http://host/").unwrap().authority.unwrap();
        assert!(auth.user_info.is_none());
    }

    // ==================== Path ====================

    #[test]
    fn path_multiple_segments() {
        let uri = parse_uri("http://host/a/b/c").unwrap();
        assert_eq!(uri.path.segments, ["a", "b", "c"]);
    }

    #[test]
    fn path_single_segment() {
        let uri = parse_uri("http://host/path").unwrap();
        assert_eq!(uri.path.segments, ["path"]);
    }

    #[test]
    fn path_root_slash() {
        let uri = parse_uri("http://host/").unwrap();
        assert_eq!(uri.path.segments, [""]);
    }

    #[test]
    fn path_trailing_slash() {
        let uri = parse_uri("http://host/a/b/").unwrap();
        assert_eq!(uri.path.segments, ["a", "b", ""]);
    }

    #[test]
    fn path_pchar_colon_and_at() {
        let uri = parse_uri("http://host/a:b@c").unwrap();
        assert_eq!(uri.path.segments, ["a:b@c"]);
    }

    #[test]
    fn path_sub_delims() {
        let uri = parse_uri("http://host/a!b$c&d'e(f)g*h+i,j;k=l").unwrap();
        assert_eq!(uri.path.segments, ["a!b$c&d'e(f)g*h+i,j;k=l"]);
    }

    #[test]
    fn path_unreserved_chars() {
        let uri = parse_uri("http://host/a-b.c_d~e").unwrap();
        assert_eq!(uri.path.segments, ["a-b.c_d~e"]);
    }

    #[test]
    fn path_pct_encoded_space() {
        let uri = parse_uri("http://host/hello%20world").unwrap();
        assert_eq!(uri.path.segments, ["hello world"]);
    }

    #[test]
    fn path_pct_encoded_slash_is_data() {
        // %2F decoded to '/' should stay within the segment, not split it
        let uri = parse_uri("http://host/a%2Fb").unwrap();
        assert_eq!(uri.path.segments, ["a/b"]);
    }

    #[test]
    fn path_before_query() {
        let uri = parse_uri("http://host/a/b?q").unwrap();
        assert_eq!(uri.path.segments, ["a", "b"]);
        assert!(uri.query.is_some());
    }

    #[test]
    fn path_before_fragment() {
        let uri = parse_uri("http://host/a/b#f").unwrap();
        assert_eq!(uri.path.segments, ["a", "b"]);
        assert!(uri.fragment.is_some());
    }

    // ==================== Query ====================

    #[test]
    fn query_key_value() {
        let q = parse_uri("http://h/?key=val").unwrap().query.unwrap();
        assert_eq!(q.query, "key=val");
    }

    #[test]
    fn query_multiple_params() {
        let q = parse_uri("http://h/?a=1&b=2&c=3").unwrap().query.unwrap();
        assert_eq!(q.query, "a=1&b=2&c=3");
    }

    #[test]
    fn query_allows_slash_question_colon_at() {
        let q = parse_uri("http://h/?a/b?c:d@e").unwrap().query.unwrap();
        assert_eq!(q.query, "a/b?c:d@e");
    }

    #[test]
    fn query_pct_encoded_hash_is_data() {
        // %23 is '#' — must not be treated as fragment delimiter
        let uri = parse_uri("http://h/?q=%23").unwrap();
        assert_eq!(uri.query.unwrap().query, "q=#");
        assert!(uri.fragment.is_none());
    }

    #[test]
    fn query_absent() {
        assert!(parse_uri("http://h/path").unwrap().query.is_none());
    }

    #[test]
    fn query_empty() {
        let q = parse_uri("http://h/path?").unwrap().query.unwrap();
        assert_eq!(q.query, "");
    }

    #[test]
    fn query_before_fragment() {
        let uri = parse_uri("http://h/?q=1#frag").unwrap();
        assert_eq!(uri.query.unwrap().query, "q=1");
        assert_eq!(uri.fragment.unwrap().fragment, "frag");
    }

    // ==================== Fragment ====================

    #[test]
    fn fragment_simple() {
        let f = parse_uri("http://h/path#section").unwrap().fragment.unwrap();
        assert_eq!(f.fragment, "section");
    }

    #[test]
    fn fragment_allows_slash_question_colon_at() {
        let f = parse_uri("http://h/#a/b?c:d@e").unwrap().fragment.unwrap();
        assert_eq!(f.fragment, "a/b?c:d@e");
    }

    #[test]
    fn fragment_pct_encoded() {
        let f = parse_uri("http://h/#sec%20tion").unwrap().fragment.unwrap();
        assert_eq!(f.fragment, "sec tion");
    }

    #[test]
    fn fragment_absent() {
        assert!(parse_uri("http://h/path?q").unwrap().fragment.is_none());
    }

    #[test]
    fn fragment_empty() {
        let f = parse_uri("http://h/path#").unwrap().fragment.unwrap();
        assert_eq!(f.fragment, "");
    }

    // ==================== Full URI parsing ====================

    #[test]
    fn full_uri_all_components() {
        let uri = parse_uri("http://user:pass@example.com:8080/a/b/c?key=val#frag").unwrap();
        assert_eq!(uri.scheme.name, "http");
        let auth = uri.authority.unwrap();
        let info = auth.user_info.unwrap();
        assert_eq!(info.username, "user");
        assert_eq!(info.password.as_deref(), Some("pass"));
        assert_domain(&auth.host, "example.com");
        assert_eq!(auth.port, Some(8080));
        assert_eq!(uri.path.segments, ["a", "b", "c"]);
        assert_eq!(uri.query.unwrap().query, "key=val");
        assert_eq!(uri.fragment.unwrap().fragment, "frag");
    }

    #[test]
    fn full_uri_scheme_and_authority_only() {
        let uri = parse_uri("http://example.com").unwrap();
        assert_eq!(uri.scheme.name, "http");
        assert!(uri.authority.is_some());
        assert!(uri.query.is_none());
        assert!(uri.fragment.is_none());
    }

    #[test]
    fn full_uri_ipv6_with_port_and_path() {
        let uri = parse_uri("http://[::1]:8080/path").unwrap();
        let auth = uri.authority.unwrap();
        assert_ip_literal(&auth.host, "::1");
        assert_eq!(auth.port, Some(8080));
        assert_eq!(uri.path.segments, ["path"]);
    }

    // ==================== 3GPP SBI URIs (TS 29.500 §5.2.10) ====================

    #[test]
    fn sbi_nrf_discovery() {
        let uri = parse_uri(
            "https://nrf.5gc.mnc001.mcc001.3gppnetwork.org/nnrf-disc/v1/nf-instances?target-nf-type=AMF",
        ).unwrap();
        assert_eq!(uri.scheme.name, "https");
        assert_domain(
            &uri.authority.unwrap().host,
            "nrf.5gc.mnc001.mcc001.3gppnetwork.org",
        );
        assert_eq!(uri.path.segments, ["nnrf-disc", "v1", "nf-instances"]);
        assert_eq!(uri.query.unwrap().query, "target-nf-type=AMF");
    }

    #[test]
    fn sbi_nrf_registration() {
        let uri = parse_uri(
            "https://nrf.example.com/nnrf-nfm/v1/nf-instances/4947a69a-f61b-4bc1-b9da-47c9c5d14b64",
        ).unwrap();
        assert_eq!(uri.path.segments, [
            "nnrf-nfm", "v1", "nf-instances", "4947a69a-f61b-4bc1-b9da-47c9c5d14b64",
        ]);
    }

    #[test]
    fn sbi_amf_communication() {
        let uri = parse_uri(
            "https://amf.example.com/namf-comm/v1/ue-contexts/imsi-001010000000001",
        ).unwrap();
        assert_eq!(uri.path.segments, [
            "namf-comm", "v1", "ue-contexts", "imsi-001010000000001",
        ]);
    }

    #[test]
    fn sbi_with_api_prefix() {
        // TS 29.501: apiRoot may contain an API prefix subcomponent
        let uri = parse_uri(
            "https://nrf.example.com/3gpp-sbi/v1/nnrf-nfm/v1/nf-instances",
        ).unwrap();
        assert_eq!(uri.path.segments, [
            "3gpp-sbi", "v1", "nnrf-nfm", "v1", "nf-instances",
        ]);
    }

    #[test]
    fn sbi_ipv4_authority() {
        let uri = parse_uri("https://10.0.0.1:29510/nnrf-nfm/v1/nf-instances").unwrap();
        let auth = uri.authority.unwrap();
        assert_ipv4(&auth.host, "10.0.0.1");
        assert_eq!(auth.port, Some(29510));
    }

    #[test]
    fn sbi_ipv6_authority() {
        let uri = parse_uri("https://[2001:db8::1]:29510/nnrf-nfm/v1/nf-instances").unwrap();
        let auth = uri.authority.unwrap();
        assert_ip_literal(&auth.host, "2001:db8::1");
        assert_eq!(auth.port, Some(29510));
    }

    #[test]
    fn sbi_smf_pdu_session() {
        let uri = parse_uri(
            "https://smf.example.com/nsmf-pdusession/v1/sm-contexts",
        ).unwrap();
        assert_eq!(uri.path.segments, ["nsmf-pdusession", "v1", "sm-contexts"]);
    }

    #[test]
    fn sbi_udm_subscriber_data() {
        let uri = parse_uri(
            "https://udm.example.com/nudm-sdm/v2/imsi-001010000000001/nssai",
        ).unwrap();
        assert_eq!(uri.path.segments, [
            "nudm-sdm", "v2", "imsi-001010000000001", "nssai",
        ]);
    }

    // ==================== Display / roundtrip ====================

    #[test]
    fn display_simple_roundtrip() {
        let input = "http://example.com/path";
        assert_eq!(parse_uri(input).unwrap().to_string(), input);
    }

    #[test]
    fn display_all_components_roundtrip() {
        let input = "http://user:pass@host:8080/a/b?q=1#frag";
        assert_eq!(parse_uri(input).unwrap().to_string(), input);
    }

    #[test]
    fn display_ipv6_roundtrip() {
        let input = "http://[::1]:8080/path";
        assert_eq!(parse_uri(input).unwrap().to_string(), input);
    }

    #[test]
    fn display_ipv4_roundtrip() {
        let input = "http://192.168.1.1/path";
        assert_eq!(parse_uri(input).unwrap().to_string(), input);
    }

    #[test]
    fn display_trailing_slash_roundtrip() {
        let input = "http://host/a/b/";
        assert_eq!(parse_uri(input).unwrap().to_string(), input);
    }

    #[test]
    fn display_sbi_roundtrip() {
        let input = "https://nrf.example.com:29510/nnrf-disc/v1/nf-instances?target-nf-type=AMF";
        assert_eq!(parse_uri(input).unwrap().to_string(), input);
    }

    #[test]
    fn display_query_special_chars_roundtrip() {
        // '/', '?', ':', '@' are allowed unencoded in query
        let input = "http://host/path?a/b?c:d@e";
        assert_eq!(parse_uri(input).unwrap().to_string(), input);
    }

    #[test]
    fn display_fragment_special_chars_roundtrip() {
        let input = "http://host/path#a/b?c:d@e";
        assert_eq!(parse_uri(input).unwrap().to_string(), input);
    }

    // ==================== Percent-encoding in Display ====================

    #[test]
    fn display_encodes_space_in_path() {
        let uri = parse_uri("http://host/hello%20world").unwrap();
        assert_eq!(uri.path.segments, ["hello world"]);
        assert_eq!(uri.to_string(), "http://host/hello%20world");
    }

    #[test]
    fn display_encodes_hash_and_question_in_path() {
        let uri = parse_uri("http://host/a%23b%3Fc").unwrap();
        assert_eq!(uri.path.segments, ["a#b?c"]);
        assert_eq!(uri.to_string(), "http://host/a%23b%3Fc");
    }

    #[test]
    fn display_normalizes_hex_to_uppercase() {
        // Input has lowercase %2f, output should use uppercase %2F
        let uri = parse_uri("http://host/a%2fb").unwrap();
        assert_eq!(uri.path.segments, ["a/b"]);
        assert_eq!(uri.to_string(), "http://host/a%2Fb");
    }

    #[test]
    fn display_encodes_at_in_userinfo() {
        let uri = parse_uri("http://us%40er@host/path").unwrap();
        assert_eq!(uri.authority.as_ref().unwrap().user_info.as_ref().unwrap().username, "us@er");
        assert_eq!(uri.to_string(), "http://us%40er@host/path");
    }

    #[test]
    fn display_query_encodes_hash() {
        let q = Query { query: "a=#".to_string() };
        assert_eq!(q.to_string(), "a=%23");
    }

    #[test]
    fn display_fragment_encodes_hash() {
        let f = Fragment { fragment: "sec#tion".to_string() };
        assert_eq!(f.to_string(), "sec%23tion");
    }

    // ==================== Display for constructed values ====================

    #[test]
    fn display_scheme() {
        assert_eq!(Scheme { name: "https".into() }.to_string(), "https");
    }

    #[test]
    fn display_authority_full() {
        let a = Authority {
            user_info: Some(UserInfo {
                username: "user".into(),
                password: Some("pass".into()),
            }),
            host: Host::DomainName("example.com".into()),
            port: Some(8080),
        };
        assert_eq!(a.to_string(), "user:pass@example.com:8080");
    }

    #[test]
    fn display_authority_host_only() {
        let a = Authority {
            user_info: None,
            host: Host::DomainName("example.com".into()),
            port: None,
        };
        assert_eq!(a.to_string(), "example.com");
    }

    #[test]
    fn display_path_segments() {
        let p = Path { segments: vec!["a".into(), "b".into(), "c".into()] };
        assert_eq!(p.to_string(), "/a/b/c");
    }

    #[test]
    fn display_path_encodes_special_chars() {
        let p = Path { segments: vec!["hello world".into()] };
        assert_eq!(p.to_string(), "/hello%20world");
    }

    #[test]
    fn display_path_single_empty_segment() {
        // Single empty segment (from "/" or no-path) should produce no output
        let p = Path { segments: vec!["".into()] };
        assert_eq!(p.to_string(), "");
    }

    #[test]
    fn display_path_trailing_slash_via_empty_final() {
        let p = Path { segments: vec!["a".into(), "".into()] };
        assert_eq!(p.to_string(), "/a/");
    }

    // ==================== 3GPP §5.2.10 reserved chars ====================

    #[test]
    fn tgpp_reserved_literal_rejected() {
        // Characters from reserved_3gpp (" % { } space) must be percent-encoded.
        // In their literal form the parser rejects them (not in unreserved/sub-delims).
        assert!(parse_uri("http://host/path with space").is_err());
        assert!(parse_uri("http://host/path{value}").is_err());
        assert!(parse_uri("http://host/path\"quoted\"").is_err());
    }

    #[test]
    fn tgpp_reserved_accepted_when_pct_encoded() {
        let uri = parse_uri("http://host/path%20with%20space").unwrap();
        assert_eq!(uri.path.segments, ["path with space"]);

        let uri = parse_uri("http://host/path%7Bvalue%7D").unwrap();
        assert_eq!(uri.path.segments, ["path{value}"]);

        let uri = parse_uri("http://host/path%22quoted%22").unwrap();
        assert_eq!(uri.path.segments, ["path\"quoted\""]);
    }

    #[test]
    fn tgpp_reserved_re_encoded_on_output() {
        let uri = parse_uri("http://host/path%20with%20space").unwrap();
        assert_eq!(uri.to_string(), "http://host/path%20with%20space");

        let uri = parse_uri("http://host/path%7Bvalue%7D").unwrap();
        assert_eq!(uri.to_string(), "http://host/path%7Bvalue%7D");
    }

    // ==================== Percent-encoding edge cases ====================

    #[test]
    fn pct_encoding_case_insensitive_input() {
        // Both %2F and %2f should decode to '/'
        assert_eq!(
            parse_uri("http://host/a%2Fb").unwrap().path.segments,
            ["a/b"],
        );
        assert_eq!(
            parse_uri("http://host/a%2fb").unwrap().path.segments,
            ["a/b"],
        );
    }

    #[test]
    fn pct_encoding_null_byte() {
        let uri = parse_uri("http://host/a%00b").unwrap();
        assert_eq!(uri.path.segments, ["a\0b"]);
    }

    #[test]
    fn pct_encoding_all_hex_digits() {
        // %41 = 'A', %5A = 'Z', %61 = 'a', %7A = 'z'
        let uri = parse_uri("http://host/%41%5A%61%7A").unwrap();
        assert_eq!(uri.path.segments, ["AZaz"]);
    }

    // ==================== Error cases ====================

    #[test]
    fn error_pct_truncated_one_digit() {
        assert!(parse_uri("http://host/%2").is_err());
    }

    #[test]
    fn error_pct_truncated_bare() {
        assert!(parse_uri("http://host/%").is_err());
    }

    #[test]
    fn error_pct_non_hex_digits() {
        assert!(parse_uri("http://host/%GG").is_err());
    }

    #[test]
    fn error_pct_non_hex_second_digit() {
        assert!(parse_uri("http://host/%2Z").is_err());
    }

    #[test]
    fn error_bracket_in_host() {
        assert!(parse_uri("http://ho[st/").is_err());
    }

    #[test]
    fn error_invalid_ipv6_literal() {
        assert!(parse_uri("http://[not-valid]/").is_err());
    }

    #[test]
    fn error_unclosed_bracket() {
        assert!(parse_uri("http://[::1/").is_err());
    }
}
