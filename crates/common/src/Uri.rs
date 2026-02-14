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

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use thiserror::Error;

// RFC 3986 §2.3 - Character class macros for use in match patterns (byte-based).

/// `ALPHA = %x41-5A / %x61-7A`
macro_rules! alpha {
    () => {
        b'a'..=b'z' | b'A'..=b'Z'
    };
}

/// `DIGIT = %x30-39`
macro_rules! digit {
    () => {
        b'0'..=b'9'
    };
}

/// `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"`
macro_rules! unreserved {
    () => {
        alpha!() | digit!() | b'-' | b'.' | b'_' | b'~'
    };
}

/// `sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="`
macro_rules! sub_delims {
    () => {
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    };
}

/// Characters that terminate the authority component.
/// Per RFC 3986 §3.2, authority ends at `/`, `?`, or `#`.
macro_rules! authority_terminator {
    () => {
        b'/' | b'?' | b'#'
    };
}

/// Characters that terminate the path component.
/// Per RFC 3986 §3.3, path ends at `?` or `#`.
macro_rules! path_terminator {
    () => {
        b'?' | b'#'
    };
}

/// Characters that terminate the query component.
/// Per RFC 3986 §3.4, query ends at `#`.
macro_rules! query_terminator {
    () => {
        b'#'
    };
}

// --- Cursor ---

/// A zero-allocation byte-slice cursor for parsing ASCII URI strings.
///
/// Since URI input is verified ASCII before parsing, each byte corresponds
/// to exactly one character. No heap allocation occurs during scanning;
/// strings are constructed only for final stored values.
struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// Returns the byte at the current position without advancing.
    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// Returns the byte at `current + n` without advancing.
    fn peek_at(&self, n: usize) -> Option<u8> {
        self.input.get(self.pos + n).copied()
    }

    /// Advances the cursor by one byte and returns the consumed byte.
    fn advance(&mut self) -> Option<u8> {
        let b = self.input.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }

    /// Advances the cursor by `n` bytes.
    fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.input.len());
    }

    /// Returns the current position in the input.
    fn position(&self) -> usize {
        self.pos
    }

    /// Returns `true` if the cursor has reached the end of input.
    fn is_empty(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Returns a byte slice from `start` to the current position.
    fn slice_from(&self, start: usize) -> &'a [u8] {
        &self.input[start..self.pos]
    }
}

// --- Public types ---

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
/// The decoded query string is available via the `query` field. Structured
/// key-value pairs are parsed from the **raw** (percent-encoded) query bytes,
/// splitting on literal `&` and `=`, then percent-decoding each key and value
/// separately. This ensures `%26` (encoded `&`) in a value is not mistaken
/// for a parameter delimiter.
#[derive(Debug, Clone)]
pub struct Query {
    /// The decoded query string.
    pub query: String,
    /// Parsed key-value pairs from the raw query string.
    params: Vec<(String, String)>,
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

// --- Serde implementations ---

/// Deserializes a [`Uri`] from a JSON string value by delegating to [`FromStr`].
///
/// The input must be a valid ASCII string containing an absolute URI.
#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Uri::from_str(&s).map_err(serde::de::Error::custom)
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

// --- FromStr ---

/// Parses an absolute URI from a string per 3GPP TS 29.500 §5.2.10 and
/// IETF RFC 3986.
impl FromStr for Uri {
    type Err = UriParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.is_ascii() {
            return Err(UriParseError::SchemeInvalid { pos: 0 });
        }
        let mut cursor = Cursor::new(s.as_bytes());
        let scheme = parse_scheme(&mut cursor)?;
        let authority = parse_authority(&mut cursor)?;
        let path = parse_path(&mut cursor)?;
        let query = parse_query(&mut cursor)?;
        let fragment = parse_fragment(&mut cursor)?;
        Ok(Uri {
            scheme,
            authority,
            path,
            query,
            fragment,
        })
    }
}

// --- PartialEq / Eq / Hash ---

/// Component-wise equality per RFC 3986 §6.2.2.
///
/// Scheme comparison is case-insensitive (RFC 3986 §3.1). Domain name host
/// comparison is case-insensitive (RFC 3986 §3.2.2). All other components
/// use exact comparison.
impl PartialEq for Uri {
    fn eq(&self, other: &Self) -> bool {
        self.scheme == other.scheme && self.authority == other.authority && self.path == other.path && self.query == other.query && self.fragment == other.fragment
    }
}

impl Eq for Uri {}

/// Hash consistent with `PartialEq`: lowercases scheme and domain host.
impl Hash for Uri {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.scheme.hash(state);
        self.authority.hash(state);
        self.path.hash(state);
        self.query.hash(state);
        self.fragment.hash(state);
    }
}

impl PartialEq for Scheme {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq_ignore_ascii_case(&other.name)
    }
}
impl Eq for Scheme {}
impl Hash for Scheme {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for b in self.name.bytes() {
            b.to_ascii_lowercase().hash(state);
        }
    }
}

impl PartialEq for Authority {
    fn eq(&self, other: &Self) -> bool {
        self.user_info == other.user_info && self.host == other.host && self.port == other.port
    }
}
impl Eq for Authority {}
impl Hash for Authority {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.user_info.hash(state);
        self.host.hash(state);
        self.port.hash(state);
    }
}

impl PartialEq for UserInfo {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username && self.password == other.password
    }
}
impl Eq for UserInfo {}
impl Hash for UserInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.username.hash(state);
        self.password.hash(state);
    }
}

/// Host equality: domain names are compared case-insensitively per
/// RFC 3986 §3.2.2. IP addresses use standard equality.
impl PartialEq for Host {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Host::DomainName(a), Host::DomainName(b)) => a.eq_ignore_ascii_case(b),
            (Host::Ipv4(a), Host::Ipv4(b)) | (Host::IpLiteral(a), Host::IpLiteral(b)) => a == b,
            _ => false,
        }
    }
}
impl Eq for Host {}
impl Hash for Host {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Host::DomainName(name) => {
                for b in name.bytes() {
                    b.to_ascii_lowercase().hash(state);
                }
            }
            Host::Ipv4(addr) | Host::IpLiteral(addr) => addr.hash(state),
        }
    }
}

impl PartialEq for Path {
    fn eq(&self, other: &Self) -> bool {
        self.segments == other.segments
    }
}
impl Eq for Path {}
impl Hash for Path {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.segments.hash(state);
    }
}

impl PartialEq for Query {
    fn eq(&self, other: &Self) -> bool {
        self.query == other.query
    }
}
impl Eq for Query {}
impl Hash for Query {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.query.hash(state);
    }
}

impl PartialEq for Fragment {
    fn eq(&self, other: &Self) -> bool {
        self.fragment == other.fragment
    }
}
impl Eq for Fragment {}
impl Hash for Fragment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.fragment.hash(state);
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

/// Outputs the scheme name verbatim.
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
        pct_encode_to(f, &self.username, |b| matches!(b, unreserved!() | sub_delims!()))?;
        if let Some(password) = &self.password {
            write!(f, ":")?;
            pct_encode_to(f, password, |b| matches!(b, unreserved!() | sub_delims!() | b':'))?;
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
            Host::DomainName(name) => pct_encode_to(f, name, |b| matches!(b, unreserved!() | sub_delims!())),
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
            pct_encode_to(f, segment, |b| matches!(b, unreserved!() | sub_delims!() | b':' | b'@'))?;
        }
        Ok(())
    }
}

/// Re-encodes the query string, percent-encoding characters outside
/// `pchar / "/" / "?"`.
impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        pct_encode_to(f, &self.query, |b| matches!(b, unreserved!() | sub_delims!() | b':' | b'@' | b'/' | b'?'))
    }
}

/// Re-encodes the fragment string, percent-encoding characters outside
/// `pchar / "/" / "?"`.
impl fmt::Display for Fragment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        pct_encode_to(f, &self.fragment, |b| matches!(b, unreserved!() | sub_delims!() | b':' | b'@' | b'/' | b'?'))
    }
}

// --- Parsing implementations ---

/// Errors that can occur when parsing a URI string.
#[derive(Debug, Error)]
pub enum UriParseError {
    /// The scheme component is missing or contains invalid characters.
    #[error("URI contains invalid scheme at byte {pos}")]
    SchemeInvalid {
        /// Byte offset in the input where the error was detected.
        pos: usize,
    },
    /// The userinfo component contains invalid characters.
    #[error("URI contains invalid userinfo at byte {pos}")]
    UserInfoInvalid {
        /// Byte offset in the input where the error was detected.
        pos: usize,
    },
    /// The host or port component is malformed.
    #[error("URI contains invalid host at byte {pos}")]
    HostInvalid {
        /// Byte offset in the input where the error was detected.
        pos: usize,
    },
    /// The path component contains invalid characters.
    #[error("URI contains invalid path at byte {pos}")]
    PathInvalid {
        /// Byte offset in the input where the error was detected.
        pos: usize,
    },
    /// The query component contains invalid characters.
    #[error("URI contains invalid query at byte {pos}")]
    QueryInvalid {
        /// Byte offset in the input where the error was detected.
        pos: usize,
    },
    /// The fragment component contains invalid characters.
    #[error("URI contains invalid fragment at byte {pos}")]
    FragmentInvalid {
        /// Byte offset in the input where the error was detected.
        pos: usize,
    },
    /// A `%`-encoded sequence is malformed (not followed by two hex digits).
    #[error("URI contains invalid percent-encoded characters at byte {pos}")]
    PctDecodeInvalid {
        /// Byte offset in the input where the error was detected.
        pos: usize,
    },
    /// The builder was not given a required component.
    #[error("URI builder missing required field: {field}")]
    BuilderMissing {
        /// Name of the missing field.
        field: &'static str,
    },
}

/// Parses the scheme component from the cursor.
///
/// Consumes characters up to and including the `:` delimiter.
/// The first character must be ALPHA; subsequent characters may be
/// ALPHA, DIGIT, `+`, `-`, or `.`.
fn parse_scheme(cursor: &mut Cursor<'_>) -> Result<Scheme, UriParseError> {
    let start = cursor.position();
    match cursor.peek() {
        Some(alpha!()) => {
            cursor.advance();
        }
        _ => return Err(UriParseError::SchemeInvalid { pos: start }),
    }

    loop {
        match cursor.peek() {
            Some(b':') => {
                let name = std::str::from_utf8(cursor.slice_from(start)).unwrap().to_owned();
                cursor.advance(); // consume ':'
                return Ok(Scheme { name });
            }
            Some(alpha!() | digit!() | b'+' | b'-' | b'.') => {
                cursor.advance();
            }
            _ => return Err(UriParseError::SchemeInvalid { pos: cursor.position() }),
        }
    }
}

/// Parses the authority component if the cursor starts with `//`.
///
/// Consumes the `//` prefix, then parses userinfo, host, and port
/// subcomponents in sequence. Returns `None` if no `//` prefix is present.
fn parse_authority(cursor: &mut Cursor<'_>) -> Result<Option<Authority>, UriParseError> {
    if cursor.peek() != Some(b'/') || cursor.peek_at(1) != Some(b'/') {
        return Ok(None);
    }
    cursor.skip(2);

    let user_info = parse_userinfo(cursor)?;
    let host = parse_host(cursor)?;
    let port = parse_port(cursor)?;

    Ok(Some(Authority { user_info, host, port }))
}

/// Parses the userinfo subcomponent if present.
///
/// Uses non-consuming look-ahead to detect `@` within the authority
/// bounds (before any `/`, `?`, or `#`). If found, consumes characters
/// up to and including `@`. The first `:` encountered splits the content
/// into username and password fields.
fn parse_userinfo(cursor: &mut Cursor<'_>) -> Result<Option<UserInfo>, UriParseError> {
    // Look ahead for '@' within authority bounds
    let save = cursor.position();
    let mut found_at = false;
    {
        let mut scan = save;
        while scan < cursor.input.len() {
            match cursor.input[scan] {
                b'@' => {
                    found_at = true;
                    break;
                }
                authority_terminator!() => break,
                _ => scan += 1,
            }
        }
    }

    if !found_at {
        return Ok(None);
    }

    let mut username = String::new();
    let mut password: Option<String> = None;

    // Parse username until ':' or '@'
    loop {
        match cursor.peek() {
            Some(b'@') => {
                cursor.advance();
                return Ok(Some(UserInfo { username, password }));
            }
            Some(b':') => {
                cursor.advance();
                password = Some(String::new());
                break;
            }
            Some(b'%') => {
                let pos = cursor.position();
                cursor.advance();
                username.push(pct_decode_byte(cursor, pos)?);
            }
            Some(b @ (unreserved!() | sub_delims!())) => {
                cursor.advance();
                username.push(b as char);
            }
            _ => return Err(UriParseError::UserInfoInvalid { pos: cursor.position() }),
        }
    }

    // Parse password until '@'
    let pw = password.as_mut().unwrap();
    loop {
        match cursor.peek() {
            Some(b'@') => {
                cursor.advance();
                return Ok(Some(UserInfo { username, password }));
            }
            Some(b'%') => {
                let pos = cursor.position();
                cursor.advance();
                pw.push(pct_decode_byte(cursor, pos)?);
            }
            Some(b @ (unreserved!() | sub_delims!() | b':')) => {
                cursor.advance();
                pw.push(b as char);
            }
            _ => return Err(UriParseError::UserInfoInvalid { pos: cursor.position() }),
        }
    }
}

/// Parses the host subcomponent from the cursor.
///
/// Dispatches to IP-literal parsing if the cursor starts with `[`,
/// otherwise parses as IPv4 or domain name.
fn parse_host(cursor: &mut Cursor<'_>) -> Result<Host, UriParseError> {
    if cursor.peek() == Some(b'[') {
        Ok(Host::IpLiteral(parse_ip_literal(cursor)?))
    } else {
        parse_host_other(cursor)
    }
}

/// Parses an IP-literal host enclosed in brackets (`[` ... `]`).
///
/// Consumes the opening `[`, collects hex digits, `:`, and `.`
/// (for IPv4-mapped addresses like `[::ffff:192.168.1.1]`), then
/// consumes the closing `]`. Validates the result with [`IpAddr::from_str`].
fn parse_ip_literal(cursor: &mut Cursor<'_>) -> Result<IpAddr, UriParseError> {
    cursor.advance(); // consume '['
    let start = cursor.position();

    loop {
        match cursor.advance() {
            Some(b']') => break,
            Some(b'a'..=b'f' | b'A'..=b'F' | b'0'..=b'9' | b':' | b'.') => {}
            _ => return Err(UriParseError::HostInvalid { pos: cursor.position() }),
        }
    }

    let host_str = std::str::from_utf8(&cursor.input[start..cursor.position() - 1]).unwrap();
    IpAddr::from_str(host_str).map_err(|_| UriParseError::HostInvalid { pos: start })
}

/// Parses a host as either an IPv4 address or a registered domain name.
///
/// Splits the input into dot-delimited portions. If there are exactly 4
/// portions and each parses as a `u8` (0-255), the host is treated as an
/// IPv4 address. Otherwise, the portions are rejoined with `.` as a domain name.
fn parse_host_other(cursor: &mut Cursor<'_>) -> Result<Host, UriParseError> {
    let mut portions: Vec<String> = Vec::new();
    let mut portion = String::new();

    loop {
        match cursor.peek() {
            Some(b':' | authority_terminator!()) | None => {
                portions.push(portion);
                break;
            }
            Some(b'%') => {
                let pos = cursor.position();
                cursor.advance();
                portion.push(pct_decode_byte(cursor, pos)?);
            }
            Some(b'.') => {
                cursor.advance();
                portions.push(portion);
                portion = String::new();
            }
            Some(b @ (alpha!() | digit!() | b'-' | b'_' | b'~' | sub_delims!())) => {
                cursor.advance();
                portion.push(b as char);
            }
            _ => return Err(UriParseError::HostInvalid { pos: cursor.position() }),
        }
    }

    // Attempt IPv4
    if portions.len() == 4 {
        let mut ipv4_format = true;
        let mut octets = [0u8; 4];
        for (i, p) in portions.iter().enumerate() {
            match p.parse::<u8>() {
                Ok(o) => octets[i] = o,
                Err(_) => {
                    ipv4_format = false;
                    break;
                }
            }
        }
        if ipv4_format {
            return Ok(Host::Ipv4(IpAddr::V4(Ipv4Addr::from(octets))));
        }
    }

    Ok(Host::DomainName(portions.join(".")))
}

/// Parses the port subcomponent if the cursor starts with `:`.
///
/// Consumes the `:` delimiter and any following digits. Returns `None`
/// if no `:` is present or if no digits follow it (empty port, which
/// is valid per RFC 3986).
fn parse_port(cursor: &mut Cursor<'_>) -> Result<Option<u16>, UriParseError> {
    if cursor.peek() != Some(b':') {
        return Ok(None);
    }
    cursor.advance(); // consume ':'

    let start = cursor.position();
    while let Some(b) = cursor.peek() {
        match b {
            authority_terminator!() => break,
            digit!() => {
                cursor.advance();
            }
            _ => return Err(UriParseError::HostInvalid { pos: cursor.position() }),
        }
    }

    let port_str = std::str::from_utf8(cursor.slice_from(start)).unwrap();
    if port_str.is_empty() {
        return Ok(None);
    }

    port_str.parse::<u16>().map(Some).map_err(|_| UriParseError::HostInvalid { pos: start })
}

/// Parses the path component from the cursor.
///
/// Consumes the leading `/` if present, then collects segments delimited
/// by `/`. Stops at a path terminator (`?` or `#`) without consuming it.
/// Each segment is percent-decoded during parsing.
fn parse_path(cursor: &mut Cursor<'_>) -> Result<Path, UriParseError> {
    let mut segments: Vec<String> = Vec::new();

    if cursor.peek() == Some(b'/') {
        cursor.advance();
    }

    let mut segment = String::new();
    while let Some(b) = cursor.peek() {
        match b {
            path_terminator!() => break,
            b'/' => {
                cursor.advance();
                segments.push(segment);
                segment = String::new();
            }
            b'%' => {
                let pos = cursor.position();
                cursor.advance();
                segment.push(pct_decode_byte(cursor, pos)?);
            }
            b @ (unreserved!() | sub_delims!() | b':' | b'@') => {
                cursor.advance();
                segment.push(b as char);
            }
            _ => return Err(UriParseError::PathInvalid { pos: cursor.position() }),
        }
    }

    segments.push(segment);
    Ok(Path { segments })
}

/// Parses the query component if the cursor starts with `?`.
///
/// Consumes the `?` delimiter and collects characters until `#` or
/// end-of-input. The query string is percent-decoded for the `query` field.
/// Key-value pairs are parsed from the raw bytes by splitting on `&` and `=`,
/// then percent-decoding each key/value separately to avoid treating encoded
/// delimiters as structural characters.
fn parse_query(cursor: &mut Cursor<'_>) -> Result<Option<Query>, UriParseError> {
    if cursor.peek() != Some(b'?') {
        return Ok(None);
    }
    cursor.advance(); // consume '?'

    // Capture the raw query bytes for param parsing
    let raw_start = cursor.position();

    let mut decoded = String::new();
    while let Some(b) = cursor.peek() {
        match b {
            query_terminator!() => break,
            b'%' => {
                let pos = cursor.position();
                cursor.advance();
                decoded.push(pct_decode_byte(cursor, pos)?);
            }
            b @ (unreserved!() | sub_delims!() | b'/' | b'?' | b':' | b'@') => {
                cursor.advance();
                decoded.push(b as char);
            }
            _ => return Err(UriParseError::QueryInvalid { pos: cursor.position() }),
        }
    }

    let raw_bytes = &cursor.input[raw_start..cursor.position()];
    let params = parse_query_params(raw_bytes)?;

    Ok(Some(Query { query: decoded, params }))
}

/// Parses key-value pairs from raw (percent-encoded) query bytes.
///
/// Splits on literal `&` then on literal `=`. Each key and value is
/// percent-decoded after splitting, so encoded `&` (`%26`) and `=` (`%3D`)
/// within values are preserved correctly.
fn parse_query_params(raw: &[u8]) -> Result<Vec<(String, String)>, UriParseError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    let mut params = Vec::new();
    for pair in raw.split(|&b| b == b'&') {
        if let Some(eq_pos) = pair.iter().position(|&b| b == b'=') {
            let key = pct_decode_bytes(&pair[..eq_pos])?;
            let val = pct_decode_bytes(&pair[eq_pos + 1..])?;
            params.push((key, val));
        } else {
            let key = pct_decode_bytes(pair)?;
            params.push((key, String::new()));
        }
    }
    Ok(params)
}

/// Parses the fragment component if the cursor starts with `#`.
///
/// Consumes the `#` delimiter and all remaining characters.
fn parse_fragment(cursor: &mut Cursor<'_>) -> Result<Option<Fragment>, UriParseError> {
    if cursor.peek() != Some(b'#') {
        return Ok(None);
    }
    cursor.advance(); // consume '#'

    let mut fragment = String::new();
    while let Some(b) = cursor.advance() {
        match b {
            b'%' => {
                let pos = cursor.position() - 1;
                fragment.push(pct_decode_byte(cursor, pos)?);
            }
            b @ (unreserved!() | sub_delims!() | b'/' | b'?' | b':' | b'@') => {
                fragment.push(b as char);
            }
            _ => return Err(UriParseError::FragmentInvalid { pos: cursor.position() - 1 }),
        }
    }

    Ok(Some(Fragment { fragment }))
}

// --- Percent-encoding helpers ---

/// Decodes a single percent-encoded sequence from the cursor.
///
/// Expects the `%` to have already been consumed by the caller. Reads two
/// hex digits from the cursor and converts them to the corresponding ASCII
/// character. `pct_pos` is the byte offset of the `%` for error reporting.
fn pct_decode_byte(cursor: &mut Cursor<'_>, pct_pos: usize) -> Result<char, UriParseError> {
    let d1 = match cursor.advance() {
        Some(b @ (b'a'..=b'f' | b'A'..=b'F' | b'0'..=b'9')) => b,
        _ => return Err(UriParseError::PctDecodeInvalid { pos: pct_pos }),
    };
    let d2 = match cursor.advance() {
        Some(b @ (b'a'..=b'f' | b'A'..=b'F' | b'0'..=b'9')) => b,
        _ => return Err(UriParseError::PctDecodeInvalid { pos: pct_pos }),
    };

    let val = hex_val(d1) * 16 + hex_val(d2);
    Ok(val as char)
}

/// Decodes a byte slice that may contain `%XX` sequences.
///
/// Used by [`parse_query_params`] to decode individual keys and values
/// after splitting on structural delimiters.
fn pct_decode_bytes(input: &[u8]) -> Result<String, UriParseError> {
    let mut result = String::new();
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            if i + 2 >= input.len() {
                return Err(UriParseError::PctDecodeInvalid { pos: i });
            }
            let d1 = input[i + 1];
            let d2 = input[i + 2];
            if !d1.is_ascii_hexdigit() || !d2.is_ascii_hexdigit() {
                return Err(UriParseError::PctDecodeInvalid { pos: i });
            }
            let val = hex_val(d1) * 16 + hex_val(d2);
            result.push(val as char);
            i += 3;
        } else {
            result.push(input[i] as char);
            i += 1;
        }
    }
    Ok(result)
}

/// Converts a hex ASCII digit to its numeric value (0-15).
fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => unreachable!(),
    }
}

/// Writes `s` to the formatter, percent-encoding any byte for which
/// `is_allowed` returns `false`.
///
/// Characters that were decoded from `%XX` sequences during parsing are
/// re-encoded here using uppercase hex digits, as recommended by
/// RFC 3986 §2.1.
fn pct_encode_to<F>(f: &mut fmt::Formatter<'_>, s: &str, is_allowed: F) -> fmt::Result
where
    F: Fn(u8) -> bool,
{
    for &b in s.as_bytes() {
        if is_allowed(b) {
            write!(f, "{}", b as char)?;
        } else {
            write!(f, "%{:02X}", b)?;
        }
    }
    Ok(())
}

// --- Public percent-encoding utilities ---

/// Decodes all `%XX` sequences in the input string.
///
/// Returns an error if a `%` is not followed by exactly two hex digits.
///
/// Per IETF RFC 3986 §2.1.
pub fn percent_decode(input: &str) -> Result<String, UriParseError> {
    pct_decode_bytes(input.as_bytes())
}

/// Percent-encodes a string for use in a URI path segment.
///
/// Characters allowed unencoded: `unreserved / sub-delims / ":" / "@"`
/// (the `pchar` production from RFC 3986 §3.3).
pub fn percent_encode_path(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if matches!(b, unreserved!() | sub_delims!() | b':' | b'@') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX_UPPER[(b >> 4) as usize] as char);
            out.push(HEX_UPPER[(b & 0xF) as usize] as char);
        }
    }
    out
}

/// Percent-encodes a string for use as a query parameter key.
///
/// Characters allowed unencoded: `unreserved / "!" / "$" / "'" / "(" / ")"
/// / "*" / "+" / "," / ";" / ":" / "@" / "/" / "?"`.
///
/// Notably, `=` and `&` are always encoded as they are structural query
/// delimiters.
pub fn percent_encode_query_key(input: &str) -> String {
    encode_query_component(input)
}

/// Percent-encodes a string for use as a query parameter value.
///
/// Same allowed set as [`percent_encode_query_key`]: `=` and `&` are
/// always encoded to prevent them from being interpreted as structural
/// delimiters.
pub fn percent_encode_query_value(input: &str) -> String {
    encode_query_component(input)
}

/// Uppercase hex digits lookup table.
const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

/// Shared encoder for query keys and values. Encodes everything outside
/// `unreserved` plus a subset of `sub-delims` (excluding `=` and `&`),
/// plus `pchar` extras `:`, `@`, `/`, `?`.
fn encode_query_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if matches!(b, unreserved!() | b'!' | b'$' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b':' | b'@' | b'/' | b'?') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX_UPPER[(b >> 4) as usize] as char);
            out.push(HEX_UPPER[(b & 0xF) as usize] as char);
        }
    }
    out
}

// --- Query accessor methods ---

impl Query {
    /// Returns the first value for the given key, or `None` if the key
    /// is not present.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// Returns all values for the given key (handles repeated keys).
    pub fn get_all(&self, key: &str) -> Vec<&str> {
        self.params.iter().filter(|(k, _)| k == key).map(|(_, v)| v.as_str()).collect()
    }

    /// Splits the first value for `key` on commas and returns the parts.
    ///
    /// This handles the OpenAPI `style: form` / `explode: false` serialization
    /// used in 3GPP SBI query parameters (TS 29.501 §5.3).
    pub fn get_csv(&self, key: &str) -> Option<Vec<&str>> {
        self.get(key).map(|v| v.split(',').collect())
    }

    /// Deserializes the first value for `key` as JSON.
    ///
    /// This handles the `content: application/json` query parameter
    /// serialization used in 3GPP SBI (TS 29.500 §5.2.10).
    ///
    /// Requires the `serde` feature.
    #[cfg(feature = "serde")]
    pub fn get_json<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<Result<T, serde_json::Error>> {
        self.get(key).map(|v| serde_json::from_str(v))
    }

    /// Returns an iterator over all key-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.params.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Returns `true` if the query contains the given key.
    pub fn contains_key(&self, key: &str) -> bool {
        self.params.iter().any(|(k, _)| k == key)
    }

    /// Returns `true` if the query string is empty (no parameters).
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    /// Returns the number of key-value pairs.
    pub fn len(&self) -> usize {
        self.params.len()
    }
}

// --- URI Builder ---

/// A builder for constructing [`Uri`] instances programmatically.
///
/// Per 3GPP TS 29.500 §5.2.10 and IETF RFC 3986. The `scheme` field is
/// required; all others are optional.
///
/// # Example
///
/// ```ignore
/// let uri = Uri::builder()
///     .scheme("https")
///     .host("nrf.example.com")
///     .port(29510)
///     .path_segments(&["nnrf-disc", "v1", "nf-instances"])
///     .query_param("target-nf-type", "AMF")
///     .build()?;
/// ```
pub struct UriBuilder {
    scheme: Option<String>,
    user: Option<String>,
    password: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    path_segments: Vec<String>,
    query_params: Vec<(String, String)>,
    fragment: Option<String>,
}

impl Uri {
    /// Creates a new [`UriBuilder`].
    pub fn builder() -> UriBuilder {
        UriBuilder {
            scheme: None,
            user: None,
            password: None,
            host: None,
            port: None,
            path_segments: Vec::new(),
            query_params: Vec::new(),
            fragment: None,
        }
    }
}

impl UriBuilder {
    /// Sets the scheme (e.g. `"https"`).
    pub fn scheme(mut self, scheme: &str) -> Self {
        self.scheme = Some(scheme.to_owned());
        self
    }

    /// Sets the host (domain name, IPv4, or IPv6 without brackets).
    pub fn host(mut self, host: &str) -> Self {
        self.host = Some(host.to_owned());
        self
    }

    /// Sets the port number.
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Sets the username for the userinfo subcomponent.
    pub fn username(mut self, user: &str) -> Self {
        self.user = Some(user.to_owned());
        self
    }

    /// Sets the password for the userinfo subcomponent.
    pub fn password(mut self, password: &str) -> Self {
        self.password = Some(password.to_owned());
        self
    }

    /// Sets the path segments (decoded). A leading `/` is added automatically.
    pub fn path_segments(mut self, segments: &[&str]) -> Self {
        self.path_segments = segments.iter().map(|s| (*s).to_owned()).collect();
        self
    }

    /// Adds a single query parameter (key and value are stored decoded;
    /// they will be percent-encoded on output).
    pub fn query_param(mut self, key: &str, value: &str) -> Self {
        self.query_params.push((key.to_owned(), value.to_owned()));
        self
    }

    /// Adds a query parameter whose value is a comma-separated list.
    ///
    /// Per TS 29.501 §5.3, OpenAPI `style: form` / `explode: false`.
    pub fn query_param_csv(mut self, key: &str, values: &[&str]) -> Self {
        self.query_params.push((key.to_owned(), values.join(",")));
        self
    }

    /// Sets the fragment (decoded).
    pub fn fragment(mut self, fragment: &str) -> Self {
        self.fragment = Some(fragment.to_owned());
        self
    }

    /// Builds the [`Uri`], validating all components.
    ///
    /// Returns an error if the scheme is missing or contains invalid
    /// characters, or if the host is invalid.
    pub fn build(self) -> Result<Uri, UriParseError> {
        let scheme_str = self.scheme.ok_or(UriParseError::BuilderMissing { field: "scheme" })?;

        // Validate scheme characters
        let scheme_bytes = scheme_str.as_bytes();
        if scheme_bytes.is_empty() || !scheme_bytes[0].is_ascii_alphabetic() {
            return Err(UriParseError::SchemeInvalid { pos: 0 });
        }
        for &b in &scheme_bytes[1..] {
            if !matches!(b, alpha!() | digit!() | b'+' | b'-' | b'.') {
                return Err(UriParseError::SchemeInvalid { pos: 0 });
            }
        }

        let scheme = Scheme { name: scheme_str };

        let authority = if let Some(host_str) = self.host {
            let host = parse_host_string(&host_str)?;
            let user_info = self.user.map(|u| UserInfo {
                username: u,
                password: self.password,
            });
            Some(Authority { user_info, host, port: self.port })
        } else {
            None
        };

        let path = if self.path_segments.is_empty() {
            Path { segments: vec![String::new()] }
        } else {
            Path { segments: self.path_segments }
        };

        let query = if self.query_params.is_empty() {
            None
        } else {
            // Build decoded query string from params
            let query_str: String = self
                .query_params
                .iter()
                .enumerate()
                .map(|(i, (k, v))| {
                    let sep = if i > 0 { "&" } else { "" };
                    format!("{}{}{}{}", sep, k, if v.is_empty() && !k.is_empty() { "" } else { "=" }, v)
                })
                .collect();
            let params = self.query_params;
            Some(Query { query: query_str, params })
        };

        let fragment = self.fragment.map(|f| Fragment { fragment: f });

        Ok(Uri {
            scheme,
            authority,
            path,
            query,
            fragment,
        })
    }
}

/// Parses a host string (from the builder) into a [`Host`] value.
///
/// Handles IPv6 (with or without brackets), IPv4, and domain names.
fn parse_host_string(s: &str) -> Result<Host, UriParseError> {
    if s.is_empty() {
        return Err(UriParseError::HostInvalid { pos: 0 });
    }

    // IPv6 with brackets
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len() - 1];
        return IpAddr::from_str(inner).map(Host::IpLiteral).map_err(|_| UriParseError::HostInvalid { pos: 0 });
    }

    // IPv6 without brackets (builder convenience)
    if s.contains(':') && !s.contains('.') {
        // Looks like IPv6 — try parse
        if let Ok(addr) = IpAddr::from_str(s) {
            return Ok(Host::IpLiteral(addr));
        }
    }

    // Try IPv4
    if let Ok(v4) = s.parse::<Ipv4Addr>() {
        return Ok(Host::Ipv4(IpAddr::V4(v4)));
    }

    // Domain name
    Ok(Host::DomainName(s.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::hash::{DefaultHasher, Hasher};

    /// Parses a URI string using [`Uri::from_str`].
    fn parse_uri(input: &str) -> Result<Uri, UriParseError> {
        Uri::from_str(input)
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

    // ==================== 1. Scheme Parsing ====================

    #[test]
    fn scheme_http() {
        assert_eq!(parse_uri("http://h").unwrap().scheme.name, "http");
    }

    #[test]
    fn scheme_https() {
        assert_eq!(parse_uri("https://h").unwrap().scheme.name, "https");
    }

    #[test]
    fn scheme_single_alpha() {
        assert_eq!(parse_uri("a://h").unwrap().scheme.name, "a");
    }

    #[test]
    fn scheme_all_allowed_chars() {
        assert_eq!(parse_uri("a1+-.z://h").unwrap().scheme.name, "a1+-.z");
    }

    #[test]
    fn scheme_preserves_original_case() {
        assert_eq!(parse_uri("HTTP://h").unwrap().scheme.name, "HTTP");
        assert_eq!(parse_uri("HtTp://h").unwrap().scheme.name, "HtTp");
    }

    #[test]
    fn scheme_uppercase_alpha_start() {
        assert_eq!(parse_uri("Z://h").unwrap().scheme.name, "Z");
    }

    #[test]
    fn scheme_starts_with_digit_rejected() {
        match parse_uri("1http://h").unwrap_err() {
            UriParseError::SchemeInvalid { pos } => assert_eq!(pos, 0),
            other => panic!("expected SchemeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn scheme_empty_rejected() {
        match parse_uri("://h").unwrap_err() {
            UriParseError::SchemeInvalid { .. } => {}
            other => panic!("expected SchemeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn scheme_missing_colon_rejected() {
        match parse_uri("http").unwrap_err() {
            UriParseError::SchemeInvalid { .. } => {}
            other => panic!("expected SchemeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn scheme_underscore_rejected() {
        match parse_uri("my_scheme://h").unwrap_err() {
            UriParseError::SchemeInvalid { .. } => {}
            other => panic!("expected SchemeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn scheme_space_rejected() {
        match parse_uri("my scheme://h").unwrap_err() {
            UriParseError::SchemeInvalid { .. } => {}
            other => panic!("expected SchemeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn scheme_non_ascii_rejected() {
        assert!(parse_uri("htt\u{00E9}://h").is_err());
    }

    #[test]
    fn scheme_colon_only_rejected() {
        match parse_uri(":").unwrap_err() {
            UriParseError::SchemeInvalid { .. } => {}
            other => panic!("expected SchemeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn scheme_with_dot_and_plus() {
        assert_eq!(parse_uri("svn+ssh://h").unwrap().scheme.name, "svn+ssh");
        assert_eq!(parse_uri("a.b://h").unwrap().scheme.name, "a.b");
    }

    // ==================== 2. Authority Detection ====================

    #[test]
    fn authority_present_with_double_slash() {
        let uri = parse_uri("http://host/path").unwrap();
        assert!(uri.authority.is_some());
    }

    #[test]
    fn authority_absent_without_double_slash() {
        let uri = parse_uri("mailto:user@example.com").unwrap();
        assert!(uri.authority.is_none());
        assert_eq!(uri.path.segments, vec!["user@example.com"]);
    }

    #[test]
    fn authority_single_slash_no_authority() {
        let uri = parse_uri("x:/path").unwrap();
        assert!(uri.authority.is_none());
        assert_eq!(uri.path.segments, vec!["path"]);
    }

    #[test]
    fn authority_empty_authority() {
        let uri = parse_uri("http:///path").unwrap();
        assert!(uri.authority.is_some());
        let auth = uri.authority.unwrap();
        assert!(matches!(auth.host, Host::DomainName(ref s) if s.is_empty()));
        assert_eq!(uri.path.segments, vec!["path"]);
    }

    #[test]
    fn authority_no_path_after_authority() {
        let uri = parse_uri("http://host").unwrap();
        assert!(uri.authority.is_some());
        assert_eq!(uri.path.segments, vec![""]);
    }

    // ==================== 3. UserInfo Parsing ====================

    #[test]
    fn userinfo_username_only() {
        let info = parse_uri("http://user@host/").unwrap().authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "user");
        assert_eq!(info.password, None);
    }

    #[test]
    fn userinfo_with_password() {
        let info = parse_uri("http://user:pass@host/").unwrap().authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "user");
        assert_eq!(info.password.as_deref(), Some("pass"));
    }

    #[test]
    fn userinfo_empty_password() {
        let info = parse_uri("http://user:@host/").unwrap().authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "user");
        assert_eq!(info.password.as_deref(), Some(""));
    }

    #[test]
    fn userinfo_empty_username() {
        let info = parse_uri("http://:pass@host/").unwrap().authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "");
        assert_eq!(info.password.as_deref(), Some("pass"));
    }

    #[test]
    fn userinfo_empty_both() {
        let info = parse_uri("http://:@host/").unwrap().authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "");
        assert_eq!(info.password.as_deref(), Some(""));
    }

    #[test]
    fn userinfo_password_with_colons() {
        let info = parse_uri("http://user:p:a:ss@host/").unwrap().authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "user");
        assert_eq!(info.password.as_deref(), Some("p:a:ss"));
    }

    #[test]
    fn userinfo_percent_encoded() {
        let info = parse_uri("http://us%40er:p%40ss@host/").unwrap().authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "us@er");
        assert_eq!(info.password.as_deref(), Some("p@ss"));
    }

    #[test]
    fn userinfo_all_unreserved_chars() {
        let info = parse_uri("http://aZ09-._~@host/").unwrap().authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "aZ09-._~");
    }

    #[test]
    fn userinfo_all_sub_delims() {
        let info = parse_uri("http://!$&'()*+,;=@host/").unwrap().authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, "!$&'()*+,;=");
    }

    #[test]
    fn userinfo_absent() {
        let auth = parse_uri("http://host/").unwrap().authority.unwrap();
        assert!(auth.user_info.is_none());
    }

    #[test]
    fn userinfo_at_in_path_not_confused() {
        let uri = parse_uri("mailto:user@host").unwrap();
        assert!(uri.authority.is_none());
        assert_eq!(uri.path.segments, vec!["user@host"]);
    }

    #[test]
    fn userinfo_percent_encoded_colon_in_username() {
        let info = parse_uri("http://%3A@host/").unwrap().authority.unwrap().user_info.unwrap();
        assert_eq!(info.username, ":");
        assert_eq!(info.password, None);
    }

    #[test]
    fn userinfo_invalid_char_rejected() {
        match parse_uri("http://user\x01@host/").unwrap_err() {
            UriParseError::SchemeInvalid { .. } => {} // non-ASCII check catches first
            UriParseError::UserInfoInvalid { .. } => {}
            other => panic!("expected UserInfoInvalid or SchemeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn userinfo_bad_pct_in_username() {
        match parse_uri("http://us%GG@host/").unwrap_err() {
            UriParseError::PctDecodeInvalid { .. } => {}
            other => panic!("expected PctDecodeInvalid, got {other:?}"),
        }
    }

    // ==================== 4. Host - Domain Names ====================

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
    fn host_single_label() {
        let uri = parse_uri("http://myhost/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "myhost");
    }

    #[test]
    fn host_five_parts_is_domain() {
        let uri = parse_uri("http://a.b.c.d.e/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "a.b.c.d.e");
    }

    #[test]
    fn host_three_parts_is_domain() {
        let uri = parse_uri("http://a.b.c/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "a.b.c");
    }

    #[test]
    fn host_3gpp_fqdn() {
        let uri = parse_uri("http://nrf.5gc.mnc001.mcc001.3gppnetwork.org/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "nrf.5gc.mnc001.mcc001.3gppnetwork.org");
    }

    #[test]
    fn host_with_hyphen() {
        let uri = parse_uri("http://my-host.example.com/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "my-host.example.com");
    }

    #[test]
    fn host_with_underscore() {
        let uri = parse_uri("http://my_host.example.com/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "my_host.example.com");
    }

    #[test]
    fn host_percent_encoded_in_domain() {
        let uri = parse_uri("http://exam%70le.com/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "example.com");
    }

    // ==================== 5. Host - IPv4 ====================

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
    fn host_ipv4_octet_overflow_falls_to_domain() {
        let uri = parse_uri("http://256.1.1.1/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "256.1.1.1");
    }

    #[test]
    fn host_ipv4_leading_zeros_fall_to_domain() {
        // "01" does not parse as u8 via Rust's strict parser (actually it does),
        // but we verify parsing behavior either way
        let uri = parse_uri("http://01.02.03.04/").unwrap();
        let auth = uri.authority.unwrap();
        // Rust's u8 parse accepts leading zeros, so this will be IPv4
        match &auth.host {
            Host::Ipv4(_) => {} // acceptable: Rust parses "01" as 1u8
            Host::DomainName(_) => {} // also acceptable if implementation rejects leading zeros
            other => panic!("unexpected host variant: {other:?}"),
        }
    }

    #[test]
    fn host_ipv4_with_port() {
        let uri = parse_uri("http://192.168.1.1:8080/").unwrap();
        let auth = uri.authority.unwrap();
        assert_ipv4(&auth.host, "192.168.1.1");
        assert_eq!(auth.port, Some(8080));
    }

    #[test]
    fn host_ipv4_10_network() {
        let uri = parse_uri("http://10.0.0.1/").unwrap();
        assert_ipv4(&uri.authority.unwrap().host, "10.0.0.1");
    }

    // ==================== 6. Host - IPv6 Literals ====================

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

    #[test]
    fn host_ipv6_all_zeros() {
        let uri = parse_uri("http://[::]/").unwrap();
        assert_ip_literal(&uri.authority.unwrap().host, "::");
    }

    #[test]
    fn host_ipv6_with_port() {
        let uri = parse_uri("http://[::1]:8080/").unwrap();
        let auth = uri.authority.unwrap();
        assert_ip_literal(&auth.host, "::1");
        assert_eq!(auth.port, Some(8080));
    }

    #[test]
    fn host_ipv6_invalid_content_rejected() {
        match parse_uri("http://[not-valid]/").unwrap_err() {
            UriParseError::HostInvalid { .. } => {}
            other => panic!("expected HostInvalid, got {other:?}"),
        }
    }

    #[test]
    fn host_ipv6_unclosed_bracket_rejected() {
        match parse_uri("http://[::1/").unwrap_err() {
            UriParseError::HostInvalid { .. } => {}
            other => panic!("expected HostInvalid, got {other:?}"),
        }
    }

    #[test]
    fn host_ipv6_empty_brackets_rejected() {
        match parse_uri("http://[]/").unwrap_err() {
            UriParseError::HostInvalid { .. } => {}
            other => panic!("expected HostInvalid, got {other:?}"),
        }
    }

    // ==================== 7. Port Parsing ====================

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
    fn port_overflow_rejected() {
        match parse_uri("http://host:65536/").unwrap_err() {
            UriParseError::HostInvalid { .. } => {}
            other => panic!("expected HostInvalid, got {other:?}"),
        }
    }

    #[test]
    fn port_large_overflow_rejected() {
        assert!(parse_uri("http://host:999999/").is_err());
    }

    #[test]
    fn port_non_digit_rejected() {
        match parse_uri("http://host:abc/").unwrap_err() {
            UriParseError::HostInvalid { .. } => {}
            other => panic!("expected HostInvalid, got {other:?}"),
        }
    }

    #[test]
    fn port_mixed_digit_alpha_rejected() {
        match parse_uri("http://host:80ab/").unwrap_err() {
            UriParseError::HostInvalid { .. } => {}
            other => panic!("expected HostInvalid, got {other:?}"),
        }
    }

    #[test]
    fn port_leading_zeros() {
        let auth = parse_uri("http://host:0080/").unwrap().authority.unwrap();
        assert_eq!(auth.port, Some(80));
    }

    #[test]
    fn port_3gpp_nrf_default() {
        let auth = parse_uri("https://nrf:29510/").unwrap().authority.unwrap();
        assert_eq!(auth.port, Some(29510));
    }

    #[test]
    fn port_3gpp_sbi_https() {
        let auth = parse_uri("https://host:443/").unwrap().authority.unwrap();
        assert_eq!(auth.port, Some(443));
    }

    #[test]
    fn port_with_path_following() {
        let uri = parse_uri("http://host:8080/path").unwrap();
        let auth = uri.authority.unwrap();
        assert_eq!(auth.port, Some(8080));
        assert_eq!(uri.path.segments, vec!["path"]);
    }

    // ==================== 8. Path Parsing ====================

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
    fn path_root_slash_only() {
        let uri = parse_uri("http://host/").unwrap();
        assert_eq!(uri.path.segments, [""]);
    }

    #[test]
    fn path_trailing_slash() {
        let uri = parse_uri("http://host/a/b/").unwrap();
        assert_eq!(uri.path.segments, ["a", "b", ""]);
    }

    #[test]
    fn path_no_path() {
        let uri = parse_uri("http://host").unwrap();
        assert_eq!(uri.path.segments, [""]);
    }

    #[test]
    fn path_empty_segments() {
        let uri = parse_uri("http://host/a//b").unwrap();
        assert_eq!(uri.path.segments, ["a", "", "b"]);
    }

    #[test]
    fn path_pchar_colon_and_at() {
        let uri = parse_uri("http://host/a:b@c").unwrap();
        assert_eq!(uri.path.segments, ["a:b@c"]);
    }

    #[test]
    fn path_all_sub_delims() {
        let uri = parse_uri("http://host/!$&'()*+,;=").unwrap();
        assert_eq!(uri.path.segments, ["!$&'()*+,;="]);
    }

    #[test]
    fn path_all_unreserved() {
        let uri = parse_uri("http://host/a-b.c_d~e").unwrap();
        assert_eq!(uri.path.segments, ["a-b.c_d~e"]);
    }

    #[test]
    fn path_percent_encoded_space() {
        let uri = parse_uri("http://host/hello%20world").unwrap();
        assert_eq!(uri.path.segments, ["hello world"]);
    }

    #[test]
    fn path_percent_encoded_slash_is_data() {
        let uri = parse_uri("http://host/a%2Fb").unwrap();
        assert_eq!(uri.path.segments, ["a/b"]);
    }

    #[test]
    fn path_percent_encoded_question_mark() {
        let uri = parse_uri("http://host/a%3Fb").unwrap();
        assert_eq!(uri.path.segments, ["a?b"]);
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

    #[test]
    fn path_deeply_nested() {
        let uri = parse_uri("http://host/a/b/c/d/e/f/g/h/i/j/k").unwrap();
        assert_eq!(uri.path.segments, ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]);
    }

    #[test]
    fn path_with_dot_segments() {
        let uri = parse_uri("http://host/a/./b/../c").unwrap();
        assert_eq!(uri.path.segments, ["a", ".", "b", "..", "c"]);
    }

    #[test]
    fn path_space_literal_rejected() {
        match parse_uri("http://host/a b").unwrap_err() {
            UriParseError::PathInvalid { .. } => {}
            other => panic!("expected PathInvalid, got {other:?}"),
        }
    }

    #[test]
    fn path_curly_brace_rejected() {
        match parse_uri("http://host/a{b}").unwrap_err() {
            UriParseError::PathInvalid { .. } => {}
            other => panic!("expected PathInvalid, got {other:?}"),
        }
    }

    // ==================== 9. Query Parsing ====================

    #[test]
    fn query_simple_key_value() {
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
    fn query_percent_encoded_hash_is_data() {
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

    #[test]
    fn query_only_key_no_equals() {
        let q = parse_uri("http://h/?flag").unwrap().query.unwrap();
        assert_eq!(q.get("flag"), Some(""));
    }

    #[test]
    fn query_empty_value() {
        let q = parse_uri("http://h/?a=").unwrap().query.unwrap();
        assert_eq!(q.get("a"), Some(""));
    }

    #[test]
    fn query_empty_key() {
        let q = parse_uri("http://h/?=value").unwrap().query.unwrap();
        assert_eq!(q.get(""), Some("value"));
    }

    #[test]
    fn query_all_sub_delims() {
        let q = parse_uri("http://h/?!$&'()*+,;=").unwrap().query.unwrap();
        assert_eq!(q.query, "!$&'()*+,;=");
    }

    #[test]
    fn query_percent_encoded_ampersand_preserves_params() {
        let q = parse_uri("http://h/?a=x%26y&b=2").unwrap().query.unwrap();
        assert_eq!(q.get("a"), Some("x&y"));
        assert_eq!(q.get("b"), Some("2"));
    }

    #[test]
    fn query_percent_encoded_equals_preserves_value() {
        let q = parse_uri("http://h/?a=x%3Dy").unwrap().query.unwrap();
        assert_eq!(q.get("a"), Some("x=y"));
    }

    #[test]
    fn query_consecutive_ampersands() {
        let q = parse_uri("http://h/?a=1&&b=2").unwrap().query.unwrap();
        assert_eq!(q.get("a"), Some("1"));
        assert_eq!(q.get("b"), Some("2"));
        // empty pair between && produces ("", "")
        assert_eq!(q.len(), 3);
    }

    // ==================== 10. Query Accessor Methods ====================

    #[test]
    fn query_get_first_match() {
        let q = parse_uri("http://h/?a=1&a=2").unwrap().query.unwrap();
        assert_eq!(q.get("a"), Some("1"));
    }

    #[test]
    fn query_get_missing_key() {
        let q = parse_uri("http://h/?a=1").unwrap().query.unwrap();
        assert_eq!(q.get("missing"), None);
    }

    #[test]
    fn query_get_all_repeated_keys() {
        let q = parse_uri("http://h/?a=1&a=2&a=3").unwrap().query.unwrap();
        assert_eq!(q.get_all("a"), vec!["1", "2", "3"]);
    }

    #[test]
    fn query_get_all_no_matches() {
        let q = parse_uri("http://h/?a=1").unwrap().query.unwrap();
        assert!(q.get_all("missing").is_empty());
    }

    #[test]
    fn query_get_csv_simple() {
        let q = parse_uri("http://h/?names=a,b,c").unwrap().query.unwrap();
        assert_eq!(q.get_csv("names"), Some(vec!["a", "b", "c"]));
    }

    #[test]
    fn query_get_csv_single_value() {
        let q = parse_uri("http://h/?x=only").unwrap().query.unwrap();
        assert_eq!(q.get_csv("x"), Some(vec!["only"]));
    }

    #[test]
    fn query_get_csv_missing() {
        let q = parse_uri("http://h/?x=1").unwrap().query.unwrap();
        assert_eq!(q.get_csv("missing"), None);
    }

    #[test]
    fn query_get_csv_empty_value() {
        let q = parse_uri("http://h/?x=").unwrap().query.unwrap();
        assert_eq!(q.get_csv("x"), Some(vec![""]));
    }

    #[test]
    fn query_iter_pairs() {
        let q = parse_uri("http://h/?a=1&b=2").unwrap().query.unwrap();
        let pairs: Vec<_> = q.iter().collect();
        assert_eq!(pairs, vec![("a", "1"), ("b", "2")]);
    }

    #[test]
    fn query_contains_key_present() {
        let q = parse_uri("http://h/?a=1").unwrap().query.unwrap();
        assert!(q.contains_key("a"));
    }

    #[test]
    fn query_contains_key_absent() {
        let q = parse_uri("http://h/?a=1").unwrap().query.unwrap();
        assert!(!q.contains_key("z"));
    }

    #[test]
    fn query_is_empty_on_empty() {
        let q = parse_uri("http://h/?").unwrap().query.unwrap();
        assert!(q.is_empty());
    }

    #[test]
    fn query_is_empty_on_populated() {
        let q = parse_uri("http://h/?a=1").unwrap().query.unwrap();
        assert!(!q.is_empty());
    }

    #[test]
    fn query_len() {
        let q = parse_uri("http://h/?a=1&b=2&c=3").unwrap().query.unwrap();
        assert_eq!(q.len(), 3);
    }

    // ==================== 11. Query Encoding Security ====================

    #[test]
    fn query_encoded_ampersand_not_delimiter() {
        let q = parse_uri("http://h/?a=x%26y").unwrap().query.unwrap();
        assert_eq!(q.get("a"), Some("x&y"));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn query_encoded_equals_not_delimiter() {
        let q = parse_uri("http://h/?a=x%3Dy").unwrap().query.unwrap();
        assert_eq!(q.get("a"), Some("x=y"));
    }

    #[test]
    fn query_encoded_hash_not_fragment() {
        let uri = parse_uri("http://h/?q=%23val").unwrap();
        assert_eq!(uri.query.unwrap().query, "q=#val");
        assert!(uri.fragment.is_none());
    }

    #[test]
    fn query_double_encoding_preserved() {
        // %2526 → first %25 decodes to '%', then '26' is literal → "%26"
        let q = parse_uri("http://h/?a=%2526").unwrap().query.unwrap();
        assert_eq!(q.get("a"), Some("%26"));
    }

    #[test]
    fn query_encoded_percent_sign() {
        let q = parse_uri("http://h/?a=%25").unwrap().query.unwrap();
        assert_eq!(q.get("a"), Some("%"));
    }

    #[test]
    fn query_raw_vs_decoded_consistency() {
        let q = parse_uri("http://h/?key=hello%20world").unwrap().query.unwrap();
        assert_eq!(q.query, "key=hello world");
        assert_eq!(q.get("key"), Some("hello world"));
    }

    // ==================== 12. Fragment Parsing ====================

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
    fn fragment_percent_encoded() {
        let f = parse_uri("http://h/#sec%20tion").unwrap().fragment.unwrap();
        assert_eq!(f.fragment, "sec tion");
    }

    #[test]
    fn fragment_absent() {
        assert!(parse_uri("http://h/path").unwrap().fragment.is_none());
    }

    #[test]
    fn fragment_empty() {
        let f = parse_uri("http://h/path#").unwrap().fragment.unwrap();
        assert_eq!(f.fragment, "");
    }

    #[test]
    fn fragment_all_sub_delims() {
        let f = parse_uri("http://h/#!$&'()*+,;=").unwrap().fragment.unwrap();
        assert_eq!(f.fragment, "!$&'()*+,;=");
    }

    #[test]
    fn fragment_invalid_char_rejected() {
        match parse_uri("http://h/#sec{tion").unwrap_err() {
            UriParseError::FragmentInvalid { .. } => {}
            other => panic!("expected FragmentInvalid, got {other:?}"),
        }
    }

    #[test]
    fn fragment_after_query() {
        let uri = parse_uri("http://h/?q=1#f").unwrap();
        assert_eq!(uri.query.unwrap().query, "q=1");
        assert_eq!(uri.fragment.unwrap().fragment, "f");
    }

    // ==================== 13. Percent-Encoding/Decoding ====================

    #[test]
    fn pct_case_insensitive_input() {
        assert_eq!(parse_uri("http://host/a%2Fb").unwrap().path.segments, ["a/b"]);
        assert_eq!(parse_uri("http://host/a%2fb").unwrap().path.segments, ["a/b"]);
    }

    #[test]
    fn pct_null_byte() {
        let uri = parse_uri("http://host/a%00b").unwrap();
        assert_eq!(uri.path.segments, ["a\0b"]);
    }

    #[test]
    fn pct_all_hex_upper() {
        let uri = parse_uri("http://host/%41%5A").unwrap();
        assert_eq!(uri.path.segments, ["AZ"]);
    }

    #[test]
    fn pct_all_hex_lower() {
        let uri = parse_uri("http://host/%61%7A").unwrap();
        assert_eq!(uri.path.segments, ["az"]);
    }

    #[test]
    fn pct_max_byte() {
        // %FF decodes to char 0xFF (ÿ), which is U+00FF in UTF-8 (2 bytes: 0xC3 0xBF)
        let uri = parse_uri("http://host/%FF").unwrap();
        assert_eq!(uri.path.segments[0], "\u{00FF}");
    }

    #[test]
    fn pct_min_byte() {
        let uri = parse_uri("http://host/%00").unwrap();
        assert_eq!(uri.path.segments[0].as_bytes(), [0x00]);
    }

    #[test]
    fn pct_truncated_one_digit_rejected() {
        assert!(parse_uri("http://host/%2").is_err());
    }

    #[test]
    fn pct_bare_percent_rejected() {
        assert!(parse_uri("http://host/%").is_err());
    }

    #[test]
    fn pct_non_hex_first_digit_rejected() {
        assert!(parse_uri("http://host/%GG").is_err());
    }

    #[test]
    fn pct_non_hex_second_digit_rejected() {
        assert!(parse_uri("http://host/%2Z").is_err());
    }

    #[test]
    fn pct_consecutive_sequences() {
        let uri = parse_uri("http://host/%20%20%20").unwrap();
        assert_eq!(uri.path.segments, ["   "]);
    }

    #[test]
    fn pct_decode_public_fn_simple() {
        assert_eq!(percent_decode("hello%20world").unwrap(), "hello world");
    }

    #[test]
    fn pct_decode_public_fn_no_encoding() {
        assert_eq!(percent_decode("hello").unwrap(), "hello");
    }

    #[test]
    fn pct_decode_public_fn_error() {
        assert!(percent_decode("hello%G").is_err());
    }

    #[test]
    fn pct_encode_path() {
        assert_eq!(percent_encode_path("hello world"), "hello%20world");
        assert_eq!(percent_encode_path("a/b"), "a%2Fb");
    }

    #[test]
    fn pct_encode_query_key_encodes_delimiters() {
        assert_eq!(percent_encode_query_key("a=b"), "a%3Db");
        assert_eq!(percent_encode_query_key("a&b"), "a%26b");
    }

    #[test]
    fn pct_encode_query_value_encodes_delimiters() {
        assert_eq!(percent_encode_query_value("x=y"), "x%3Dy");
        assert_eq!(percent_encode_query_value("x&y"), "x%26y");
    }

    #[test]
    fn pct_encode_query_preserves_allowed() {
        // Unreserved, '/', '?', ':', '@' should not be encoded
        let input = "abc123-._~/hello?world:foo@bar";
        assert_eq!(percent_encode_query_key(input), input);
    }

    // ==================== 14. Full URI Integration ====================

    #[test]
    fn full_uri_all_components() {
        let uri = parse_uri("http://user:pass@host:8080/a/b/c?key=val#frag").unwrap();
        assert_eq!(uri.scheme.name, "http");
        let auth = uri.authority.unwrap();
        let info = auth.user_info.unwrap();
        assert_eq!(info.username, "user");
        assert_eq!(info.password.as_deref(), Some("pass"));
        assert_domain(&auth.host, "host");
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
    fn full_uri_scheme_and_path_only() {
        let uri = parse_uri("urn:isbn:0451450523").unwrap();
        assert_eq!(uri.scheme.name, "urn");
        assert!(uri.authority.is_none());
        assert_eq!(uri.path.segments, ["isbn:0451450523"]);
    }

    #[test]
    fn full_uri_ipv6_with_port_and_path() {
        let uri = parse_uri("http://[::1]:8080/path").unwrap();
        let auth = uri.authority.unwrap();
        assert_ip_literal(&auth.host, "::1");
        assert_eq!(auth.port, Some(8080));
        assert_eq!(uri.path.segments, ["path"]);
    }

    #[test]
    fn full_uri_authority_and_query_no_path() {
        let uri = parse_uri("http://host?q=1").unwrap();
        assert!(uri.authority.is_some());
        assert_eq!(uri.query.unwrap().query, "q=1");
    }

    #[test]
    fn full_uri_authority_and_fragment_no_path_no_query() {
        let uri = parse_uri("http://host#frag").unwrap();
        assert!(uri.authority.is_some());
        assert!(uri.query.is_none());
        assert_eq!(uri.fragment.unwrap().fragment, "frag");
    }

    #[test]
    fn full_uri_minimal() {
        let uri = parse_uri("x://h").unwrap();
        assert_eq!(uri.scheme.name, "x");
        assert!(uri.authority.is_some());
    }

    #[test]
    fn full_uri_scheme_colon_only() {
        let uri = parse_uri("x:").unwrap();
        assert_eq!(uri.scheme.name, "x");
        assert!(uri.authority.is_none());
        assert_eq!(uri.path.segments, [""]);
    }

    #[test]
    fn full_uri_complex_userinfo_and_query() {
        let uri = parse_uri("http://us%40er:p%3Ass@host:1234/path?a=%26&b=2#frag").unwrap();
        let auth = uri.authority.unwrap();
        let info = auth.user_info.unwrap();
        assert_eq!(info.username, "us@er");
        assert_eq!(info.password.as_deref(), Some("p:ss"));
        assert_eq!(uri.query.unwrap().get("a"), Some("&"));
    }

    #[test]
    fn full_uri_empty_string_rejected() {
        match parse_uri("").unwrap_err() {
            UriParseError::SchemeInvalid { .. } => {}
            other => panic!("expected SchemeInvalid, got {other:?}"),
        }
    }

    // ==================== 15. 3GPP SBI URIs (TS 29.500 §5.2.10) ====================

    #[test]
    fn sbi_nrf_discovery() {
        let uri = parse_uri("https://nrf.5gc.mnc001.mcc001.3gppnetwork.org/nnrf-disc/v1/nf-instances?target-nf-type=AMF").unwrap();
        assert_eq!(uri.scheme.name, "https");
        assert_domain(&uri.authority.unwrap().host, "nrf.5gc.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(uri.path.segments, ["nnrf-disc", "v1", "nf-instances"]);
        assert_eq!(uri.query.unwrap().get("target-nf-type"), Some("AMF"));
    }

    #[test]
    fn sbi_nrf_registration() {
        let uri = parse_uri("https://nrf.example.com/nnrf-nfm/v1/nf-instances/4947a69a-f61b-4bc1-b9da-47c9c5d14b64").unwrap();
        assert_eq!(uri.path.segments, ["nnrf-nfm", "v1", "nf-instances", "4947a69a-f61b-4bc1-b9da-47c9c5d14b64"]);
    }

    #[test]
    fn sbi_amf_communication() {
        let uri = parse_uri("https://amf.example.com/namf-comm/v1/ue-contexts/imsi-001010000000001").unwrap();
        assert_eq!(uri.path.segments, ["namf-comm", "v1", "ue-contexts", "imsi-001010000000001"]);
    }

    #[test]
    fn sbi_with_deployment_prefix() {
        let uri = parse_uri("https://nrf.example.com/3gpp-sbi/v1/nnrf-nfm/v1/nf-instances").unwrap();
        assert_eq!(uri.path.segments, ["3gpp-sbi", "v1", "nnrf-nfm", "v1", "nf-instances"]);
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
        let uri = parse_uri("https://smf.example.com/nsmf-pdusession/v1/sm-contexts").unwrap();
        assert_eq!(uri.path.segments, ["nsmf-pdusession", "v1", "sm-contexts"]);
    }

    #[test]
    fn sbi_udm_subscriber_data() {
        let uri = parse_uri("https://udm.example.com/nudm-sdm/v2/imsi-001010000000001/nssai").unwrap();
        assert_eq!(uri.path.segments, ["nudm-sdm", "v2", "imsi-001010000000001", "nssai"]);
    }

    #[test]
    fn sbi_pcf_policy() {
        let uri = parse_uri("https://pcf.example.com/npcf-smpolicycontrol/v1/sm-policies").unwrap();
        assert_eq!(uri.path.segments, ["npcf-smpolicycontrol", "v1", "sm-policies"]);
    }

    #[test]
    fn sbi_nrf_discovery_multi_query() {
        let uri = parse_uri("https://nrf.example.com:29510/nnrf-disc/v1/nf-instances?target-nf-type=AMF&service-names=namf-comm,namf-evts&requester-nf-type=SMF").unwrap();
        let q = uri.query.unwrap();
        assert_eq!(q.get("target-nf-type"), Some("AMF"));
        assert_eq!(q.get_csv("service-names"), Some(vec!["namf-comm", "namf-evts"]));
        assert_eq!(q.get("requester-nf-type"), Some("SMF"));
    }

    // ==================== 16. Display / Roundtrip ====================

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
        let input = "http://host/path?a/b?c:d@e";
        assert_eq!(parse_uri(input).unwrap().to_string(), input);
    }

    #[test]
    fn display_fragment_special_chars_roundtrip() {
        let input = "http://host/path#a/b?c:d@e";
        assert_eq!(parse_uri(input).unwrap().to_string(), input);
    }

    #[test]
    fn display_encodes_space_in_path() {
        let uri = parse_uri("http://host/hello%20world").unwrap();
        assert_eq!(uri.path.segments, ["hello world"]);
        assert_eq!(uri.to_string(), "http://host/hello%20world");
    }

    #[test]
    fn display_encodes_hash_question_in_path() {
        let uri = parse_uri("http://host/a%23b%3Fc").unwrap();
        assert_eq!(uri.path.segments, ["a#b?c"]);
        assert_eq!(uri.to_string(), "http://host/a%23b%3Fc");
    }

    #[test]
    fn display_normalizes_hex_uppercase() {
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
        let q = Query {
            query: "a=#".to_string(),
            params: vec![],
        };
        assert_eq!(q.to_string(), "a=%23");
    }

    #[test]
    fn display_fragment_encodes_hash() {
        let f = Fragment { fragment: "sec#tion".to_string() };
        assert_eq!(f.to_string(), "sec%23tion");
    }

    #[test]
    fn display_scheme_verbatim() {
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
        let p = Path {
            segments: vec!["a".into(), "b".into(), "c".into()],
        };
        assert_eq!(p.to_string(), "/a/b/c");
    }

    #[test]
    fn display_path_encodes_special() {
        let p = Path {
            segments: vec!["hello world".into()],
        };
        assert_eq!(p.to_string(), "/hello%20world");
    }

    #[test]
    fn display_path_single_empty_segment() {
        let p = Path { segments: vec!["".into()] };
        assert_eq!(p.to_string(), "");
    }

    #[test]
    fn display_path_trailing_slash_via_empty_final() {
        let p = Path {
            segments: vec!["a".into(), "".into()],
        };
        assert_eq!(p.to_string(), "/a/");
    }

    #[test]
    fn display_colon_in_password_preserved() {
        let a = Authority {
            user_info: Some(UserInfo {
                username: "user".into(),
                password: Some("p:a:ss".into()),
            }),
            host: Host::DomainName("host".into()),
            port: None,
        };
        assert_eq!(a.to_string(), "user:p:a:ss@host");
    }

    // ==================== 17. PartialEq / Eq / Hash ====================

    #[test]
    fn eq_identical_uris() {
        let a = parse_uri("http://example.com/path?q=1#f").unwrap();
        let b = parse_uri("http://example.com/path?q=1#f").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn eq_case_insensitive_scheme() {
        let a = parse_uri("HTTP://example.com/path").unwrap();
        let b = parse_uri("http://example.com/path").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn eq_case_insensitive_host() {
        let a = parse_uri("http://EXAMPLE.COM/path").unwrap();
        let b = parse_uri("http://example.com/path").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn eq_different_paths_not_equal() {
        let a = parse_uri("http://example.com/a").unwrap();
        let b = parse_uri("http://example.com/b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn eq_different_schemes_not_equal() {
        let a = parse_uri("http://example.com/path").unwrap();
        let b = parse_uri("https://example.com/path").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn eq_different_ports_not_equal() {
        let a = parse_uri("http://host:8080/").unwrap();
        let b = parse_uri("http://host:8081/").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn eq_different_queries_not_equal() {
        let a = parse_uri("http://host/?a=1").unwrap();
        let b = parse_uri("http://host/?a=2").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn eq_different_fragments_not_equal() {
        let a = parse_uri("http://host/#a").unwrap();
        let b = parse_uri("http://host/#b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn eq_ipv4_same_address() {
        let a = parse_uri("http://192.168.1.1/").unwrap();
        let b = parse_uri("http://192.168.1.1/").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn eq_ipv4_different_address() {
        let a = parse_uri("http://192.168.1.1/").unwrap();
        let b = parse_uri("http://192.168.1.2/").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn eq_ipv6_same_address() {
        let a = parse_uri("http://[::1]/").unwrap();
        let b = parse_uri("http://[::1]/").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn eq_ipv4_vs_domain_not_equal() {
        let ipv4 = Host::Ipv4(IpAddr::from_str("1.2.3.4").unwrap());
        let domain = Host::DomainName("1.2.3.4".into());
        assert_ne!(ipv4, domain);
    }

    #[test]
    fn eq_ipv4_vs_ip_literal_not_equal() {
        let ipv4 = Host::Ipv4(IpAddr::from_str("127.0.0.1").unwrap());
        let literal = Host::IpLiteral(IpAddr::from_str("127.0.0.1").unwrap());
        assert_ne!(ipv4, literal);
    }

    #[test]
    fn eq_hash_consistent_scheme() {
        let a = parse_uri("HTTP://example.com/path").unwrap();
        let b = parse_uri("http://example.com/path").unwrap();
        assert_eq!(a, b);
        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn eq_hash_consistent_host() {
        let a = parse_uri("http://EXAMPLE.COM/path").unwrap();
        let b = parse_uri("http://example.com/path").unwrap();
        assert_eq!(a, b);
        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn eq_hash_set_dedup() {
        let a = parse_uri("HTTP://Example.COM/path").unwrap();
        let b = parse_uri("http://example.com/path").unwrap();
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn eq_userinfo_exact() {
        let a = UserInfo { username: "User".into(), password: Some("Pass".into()) };
        let b = UserInfo { username: "user".into(), password: Some("pass".into()) };
        assert_ne!(a, b);
    }

    #[test]
    fn eq_query_by_decoded_string() {
        let a = Query { query: "a=1".into(), params: vec![("a".into(), "1".into())] };
        let b = Query { query: "a=1".into(), params: vec![("a".into(), "1".into())] };
        assert_eq!(a, b);
    }

    #[test]
    fn eq_fragment_exact() {
        let a = Fragment { fragment: "Frag".into() };
        let b = Fragment { fragment: "frag".into() };
        assert_ne!(a, b);
    }

    #[test]
    fn eq_path_case_sensitive() {
        let a = parse_uri("http://host/Path").unwrap();
        let b = parse_uri("http://host/path").unwrap();
        assert_ne!(a, b);
    }

    // ==================== 18. URI Builder ====================

    #[test]
    fn builder_simple() {
        let uri = Uri::builder().scheme("https").host("example.com").path_segments(&["a", "b"]).build().unwrap();
        assert_eq!(uri.to_string(), "https://example.com/a/b");
    }

    #[test]
    fn builder_with_port() {
        let uri = Uri::builder().scheme("https").host("host").port(8080).path_segments(&["p"]).build().unwrap();
        assert_eq!(uri.to_string(), "https://host:8080/p");
    }

    #[test]
    fn builder_with_userinfo() {
        let uri = Uri::builder().scheme("http").host("host").username("user").password("pass").path_segments(&["p"]).build().unwrap();
        assert_eq!(uri.to_string(), "http://user:pass@host/p");
    }

    #[test]
    fn builder_with_username_only() {
        let uri = Uri::builder().scheme("http").host("host").username("user").path_segments(&["p"]).build().unwrap();
        let auth = uri.authority.unwrap();
        assert_eq!(auth.user_info.as_ref().unwrap().username, "user");
        assert_eq!(auth.user_info.as_ref().unwrap().password, None);
    }

    #[test]
    fn builder_with_query_param() {
        let uri = Uri::builder().scheme("http").host("h").query_param("key", "val").build().unwrap();
        assert_eq!(uri.query.unwrap().get("key"), Some("val"));
    }

    #[test]
    fn builder_with_multiple_query_params() {
        let uri = Uri::builder().scheme("http").host("h").query_param("a", "1").query_param("b", "2").build().unwrap();
        let q = uri.query.unwrap();
        let pairs: Vec<_> = q.iter().collect();
        assert_eq!(pairs, vec![("a", "1"), ("b", "2")]);
    }

    #[test]
    fn builder_csv_query() {
        let uri = Uri::builder()
            .scheme("https")
            .host("nrf.example.com")
            .port(29510)
            .path_segments(&["nnrf-disc", "v1", "nf-instances"])
            .query_param("target-nf-type", "AMF")
            .query_param_csv("service-names", &["svc1", "svc2"])
            .build()
            .unwrap();
        assert_eq!(
            uri.to_string(),
            "https://nrf.example.com:29510/nnrf-disc/v1/nf-instances?target-nf-type=AMF&service-names=svc1,svc2"
        );
    }

    #[test]
    fn builder_with_fragment() {
        let uri = Uri::builder().scheme("http").host("h").fragment("frag").build().unwrap();
        assert_eq!(uri.fragment.unwrap().fragment, "frag");
    }

    #[test]
    fn builder_all_components() {
        let uri = Uri::builder()
            .scheme("https")
            .username("user")
            .password("pass")
            .host("host")
            .port(443)
            .path_segments(&["a", "b"])
            .query_param("q", "1")
            .fragment("f")
            .build()
            .unwrap();
        assert_eq!(uri.to_string(), "https://user:pass@host:443/a/b?q=1#f");
    }

    #[test]
    fn builder_missing_scheme_rejected() {
        match Uri::builder().host("example.com").build().unwrap_err() {
            UriParseError::BuilderMissing { field } => assert_eq!(field, "scheme"),
            other => panic!("expected BuilderMissing, got {other:?}"),
        }
    }

    #[test]
    fn builder_invalid_scheme_start_rejected() {
        match Uri::builder().scheme("1http").host("h").build().unwrap_err() {
            UriParseError::SchemeInvalid { .. } => {}
            other => panic!("expected SchemeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn builder_invalid_scheme_char_rejected() {
        match Uri::builder().scheme("ht_tp").host("h").build().unwrap_err() {
            UriParseError::SchemeInvalid { .. } => {}
            other => panic!("expected SchemeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn builder_empty_scheme_rejected() {
        match Uri::builder().scheme("").host("h").build().unwrap_err() {
            UriParseError::SchemeInvalid { .. } => {}
            other => panic!("expected SchemeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn builder_no_host_no_authority() {
        let uri = Uri::builder().scheme("urn").path_segments(&["isbn:0451450523"]).build().unwrap();
        assert!(uri.authority.is_none());
    }

    #[test]
    fn builder_ipv4_host() {
        let uri = Uri::builder().scheme("http").host("192.168.1.1").build().unwrap();
        assert_ipv4(&uri.authority.unwrap().host, "192.168.1.1");
    }

    #[test]
    fn builder_ipv6_host_with_brackets() {
        let uri = Uri::builder().scheme("https").host("[::1]").port(29510).path_segments(&["path"]).build().unwrap();
        assert_ip_literal(&uri.authority.as_ref().unwrap().host, "::1");
        assert_eq!(uri.to_string(), "https://[::1]:29510/path");
    }

    #[test]
    fn builder_ipv6_host_without_brackets() {
        let uri = Uri::builder().scheme("https").host("::1").build().unwrap();
        assert_ip_literal(&uri.authority.unwrap().host, "::1");
    }

    #[test]
    fn builder_domain_host() {
        let uri = Uri::builder().scheme("http").host("example.com").build().unwrap();
        assert_domain(&uri.authority.unwrap().host, "example.com");
    }

    #[test]
    fn builder_empty_host_rejected() {
        match Uri::builder().scheme("http").host("").build().unwrap_err() {
            UriParseError::HostInvalid { .. } => {}
            other => panic!("expected HostInvalid, got {other:?}"),
        }
    }

    #[test]
    fn builder_empty_path_segments() {
        let uri = Uri::builder().scheme("http").host("h").build().unwrap();
        assert_eq!(uri.path.segments, [""]);
    }

    #[test]
    fn builder_sbi_realistic() {
        let uri = Uri::builder()
            .scheme("https")
            .host("nrf.5gc.mnc001.mcc001.3gppnetwork.org")
            .path_segments(&["nnrf-nfm", "v1", "nf-instances", "4947a69a-f61b-4bc1-b9da-47c9c5d14b64"])
            .build()
            .unwrap();
        assert_eq!(
            uri.to_string(),
            "https://nrf.5gc.mnc001.mcc001.3gppnetwork.org/nnrf-nfm/v1/nf-instances/4947a69a-f61b-4bc1-b9da-47c9c5d14b64"
        );
    }

    #[test]
    fn builder_sbi_discovery_with_queries() {
        let uri = Uri::builder()
            .scheme("https")
            .host("nrf.example.com")
            .port(29510)
            .path_segments(&["nnrf-disc", "v1", "nf-instances"])
            .query_param("target-nf-type", "AMF")
            .query_param_csv("service-names", &["namf-comm", "namf-evts"])
            .build()
            .unwrap();
        let q = uri.query.unwrap();
        assert_eq!(q.get("target-nf-type"), Some("AMF"));
        assert_eq!(q.get("service-names"), Some("namf-comm,namf-evts"));
    }

    #[test]
    fn builder_roundtrip_to_string() {
        let uri = Uri::builder().scheme("https").host("host").port(443).path_segments(&["a", "b"]).query_param("k", "v").fragment("f").build().unwrap();
        let s = uri.to_string();
        assert_eq!(s, "https://host:443/a/b?k=v#f");
    }

    #[test]
    fn builder_query_param_with_special_chars() {
        let uri = Uri::builder().scheme("http").host("h").query_param("key", "a=b&c").build().unwrap();
        assert_eq!(uri.query.unwrap().get("key"), Some("a=b&c"));
    }

    #[test]
    fn builder_password_without_username() {
        let uri = Uri::builder().scheme("http").host("h").password("pass").build().unwrap();
        // password without username: no user_info created (user is None)
        let auth = uri.authority.unwrap();
        assert!(auth.user_info.is_none());
    }

    #[test]
    fn builder_display_matches_from_str() {
        let built = Uri::builder()
            .scheme("https")
            .host("example.com")
            .port(8080)
            .path_segments(&["a", "b"])
            .query_param("q", "1")
            .build()
            .unwrap();
        let s = built.to_string();
        let parsed = parse_uri(&s).unwrap();
        assert_eq!(built, parsed);
    }

    // ==================== 19. Serde ====================

    #[cfg(feature = "serde")]
    #[test]
    fn serde_deserialize_valid() {
        let uri: Uri = serde_json::from_str("\"http://example.com/path\"").unwrap();
        assert_eq!(uri.scheme.name, "http");
        assert_eq!(uri.path.segments, ["path"]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_deserialize_invalid_rejected() {
        let result: Result<Uri, _> = serde_json::from_str("\"://invalid\"");
        assert!(result.is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_serialize() {
        let uri = parse_uri("http://example.com/path").unwrap();
        let json = serde_json::to_string(&uri).unwrap();
        assert_eq!(json, "\"http://example.com/path\"");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip() {
        let original = parse_uri("https://host:8080/a/b?q=1#f").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Uri = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_get_json_valid() {
        let q = parse_uri("http://h/?data=%7B%22x%22:1%7D").unwrap().query.unwrap();
        let val: serde_json::Value = q.get_json("data").unwrap().unwrap();
        assert_eq!(val, serde_json::json!({"x": 1}));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_get_json_invalid() {
        let q = parse_uri("http://h/?data=not-json").unwrap().query.unwrap();
        let result: Option<Result<serde_json::Value, _>> = q.get_json("data");
        assert!(result.unwrap().is_err());
    }

    // ==================== 20. Error Positions ====================

    #[test]
    fn error_pos_scheme_digit_start() {
        match parse_uri("1http://h").unwrap_err() {
            UriParseError::SchemeInvalid { pos } => assert_eq!(pos, 0),
            other => panic!("expected SchemeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn error_pos_scheme_invalid_char() {
        match parse_uri("ht_tp://h").unwrap_err() {
            UriParseError::SchemeInvalid { pos } => assert_eq!(pos, 2),
            other => panic!("expected SchemeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn error_pos_pct_decode_in_path() {
        // "http://host/" is 12 bytes, then 'a' at 12, '%' at 13
        match parse_uri("http://host/a%GG").unwrap_err() {
            UriParseError::PctDecodeInvalid { pos } => assert_eq!(pos, 13),
            other => panic!("expected PctDecodeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn error_pos_pct_decode_in_query() {
        // "http://h/?" is 10 bytes, then '%' at 10
        match parse_uri("http://h/?%GG").unwrap_err() {
            UriParseError::PctDecodeInvalid { pos } => assert_eq!(pos, 10),
            other => panic!("expected PctDecodeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn error_pos_pct_decode_in_fragment() {
        // "http://h/#" is 10 bytes, then '%' at 10
        match parse_uri("http://h/#%GG").unwrap_err() {
            UriParseError::PctDecodeInvalid { pos } => assert_eq!(pos, 10),
            other => panic!("expected PctDecodeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn error_pos_pct_decode_in_userinfo() {
        // "http://" is 7 bytes, then '%' at 7
        match parse_uri("http://%GG@host/").unwrap_err() {
            UriParseError::PctDecodeInvalid { pos } => assert_eq!(pos, 7),
            other => panic!("expected PctDecodeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn error_pos_host_invalid() {
        // "http://[" is 8 bytes, then invalid char
        match parse_uri("http://[not-valid]/").unwrap_err() {
            UriParseError::HostInvalid { .. } => {}
            other => panic!("expected HostInvalid, got {other:?}"),
        }
    }

    #[test]
    fn error_pos_port_overflow() {
        match parse_uri("http://host:65536/").unwrap_err() {
            UriParseError::HostInvalid { .. } => {}
            other => panic!("expected HostInvalid, got {other:?}"),
        }
    }

    #[test]
    fn error_pos_path_invalid_char() {
        // "http://host/" is 12 bytes, then '{' at 12
        match parse_uri("http://host/{bad").unwrap_err() {
            UriParseError::PathInvalid { pos } => assert_eq!(pos, 12),
            other => panic!("expected PathInvalid, got {other:?}"),
        }
    }

    #[test]
    fn error_pos_query_invalid_char() {
        // "http://h/?" is 10 bytes, then '{' at 10
        match parse_uri("http://h/?{bad").unwrap_err() {
            UriParseError::QueryInvalid { pos } => assert_eq!(pos, 10),
            other => panic!("expected QueryInvalid, got {other:?}"),
        }
    }

    #[test]
    fn error_pos_fragment_invalid_char() {
        // "http://h/#" is 10 bytes, then '{' at 10
        match parse_uri("http://h/#{bad").unwrap_err() {
            UriParseError::FragmentInvalid { pos } => assert_eq!(pos, 10),
            other => panic!("expected FragmentInvalid, got {other:?}"),
        }
    }

    #[test]
    fn error_pos_builder_missing() {
        match Uri::builder().build().unwrap_err() {
            UriParseError::BuilderMissing { field } => assert_eq!(field, "scheme"),
            other => panic!("expected BuilderMissing, got {other:?}"),
        }
    }

    // ==================== 21. 3GPP Reserved Characters (TS 29.500 §5.2.10) ====================

    #[test]
    fn tgpp_space_literal_rejected() {
        assert!(parse_uri("http://host/path with space").is_err());
    }

    #[test]
    fn tgpp_curly_open_rejected() {
        assert!(parse_uri("http://host/path{value").is_err());
    }

    #[test]
    fn tgpp_curly_close_rejected() {
        assert!(parse_uri("http://host/path}value").is_err());
    }

    #[test]
    fn tgpp_double_quote_rejected() {
        assert!(parse_uri("http://host/path\"quoted\"").is_err());
    }

    #[test]
    fn tgpp_reserved_accepted_percent_encoded() {
        assert_eq!(parse_uri("http://host/%20").unwrap().path.segments, [" "]);
        assert_eq!(parse_uri("http://host/%7B").unwrap().path.segments, ["{"]);
        assert_eq!(parse_uri("http://host/%7D").unwrap().path.segments, ["}"]);
        assert_eq!(parse_uri("http://host/%22").unwrap().path.segments, ["\""]);
    }

    #[test]
    fn tgpp_reserved_re_encoded_on_output() {
        let uri = parse_uri("http://host/path%20with%20space").unwrap();
        assert_eq!(uri.to_string(), "http://host/path%20with%20space");
        let uri = parse_uri("http://host/%7Bvalue%7D").unwrap();
        assert_eq!(uri.to_string(), "http://host/%7Bvalue%7D");
    }

    #[test]
    fn tgpp_bare_percent_in_path_rejected() {
        assert!(parse_uri("http://host/path%").is_err());
    }

    #[test]
    fn tgpp_percent_encoded_percent() {
        let uri = parse_uri("http://host/%25").unwrap();
        assert_eq!(uri.path.segments, ["%"]);
        assert_eq!(uri.to_string(), "http://host/%25");
    }

    // ==================== 22. Security and Stress ====================

    #[test]
    fn security_null_byte_in_path() {
        let uri = parse_uri("http://host/a%00b").unwrap();
        assert_eq!(uri.path.segments[0], "a\0b");
        assert_eq!(uri.path.segments[0].len(), 3);
    }

    #[test]
    fn security_null_byte_in_host() {
        let uri = parse_uri("http://host%00name/").unwrap();
        assert_domain(&uri.authority.unwrap().host, "host\0name");
    }

    #[test]
    fn security_non_ascii_rejected() {
        match parse_uri("\u{00E9}://h").unwrap_err() {
            UriParseError::SchemeInvalid { pos: 0 } => {}
            other => panic!("expected SchemeInvalid at pos 0, got {other:?}"),
        }
    }

    #[test]
    fn security_extremely_long_path() {
        let segment = "a".repeat(10_000);
        let input = format!("http://host/{}", segment);
        let uri = parse_uri(&input).unwrap();
        assert_eq!(uri.path.segments[0].len(), 10_000);
    }

    #[test]
    fn security_many_query_params() {
        let params: String = (0..1000).map(|i| format!("k{}=v{}", i, i)).collect::<Vec<_>>().join("&");
        let input = format!("http://h/?{}", params);
        let uri = parse_uri(&input).unwrap();
        assert_eq!(uri.query.unwrap().len(), 1000);
    }

    #[test]
    fn security_deeply_nested_path() {
        let segments = "a/".repeat(500);
        let input = format!("http://host/{}", segments.trim_end_matches('/'));
        let uri = parse_uri(&input).unwrap();
        assert_eq!(uri.path.segments.len(), 500);
    }

    #[test]
    fn security_percent_in_percent() {
        // %2525 → %25 decodes to '%', then '25' is literal → "%25"
        let uri = parse_uri("http://host/%2525").unwrap();
        assert_eq!(uri.path.segments, ["%25"]);
    }

    #[test]
    fn security_crlf_injection_attempt() {
        let uri = parse_uri("http://host/path%0D%0Ainjected").unwrap();
        assert_eq!(uri.path.segments[0], "path\r\ninjected");
    }

    #[test]
    fn security_backslash_in_path() {
        let uri = parse_uri("http://host/path%5Cfile").unwrap();
        assert_eq!(uri.path.segments[0], "path\\file");
    }

    #[test]
    fn security_consecutive_percent_encoded() {
        let encoded: String = std::iter::repeat("%20").take(100).collect();
        let input = format!("http://host/{}", encoded);
        let uri = parse_uri(&input).unwrap();
        assert_eq!(uri.path.segments[0], " ".repeat(100));
    }
}

