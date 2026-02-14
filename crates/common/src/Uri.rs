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
        assert_domain(&uri.authority.unwrap().host, "nrf.5gc.mnc001.mcc001.3gppnetwork.org");
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
    fn userinfo_password_with_colons() {
        // RFC 3986: ':' is valid in the password portion of userinfo
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
        let uri = parse_uri("https://nrf.5gc.mnc001.mcc001.3gppnetwork.org/nnrf-disc/v1/nf-instances?target-nf-type=AMF").unwrap();
        assert_eq!(uri.scheme.name, "https");
        assert_domain(&uri.authority.unwrap().host, "nrf.5gc.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(uri.path.segments, ["nnrf-disc", "v1", "nf-instances"]);
        assert_eq!(uri.query.unwrap().query, "target-nf-type=AMF");
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
    fn sbi_with_api_prefix() {
        // TS 29.501: apiRoot may contain an API prefix subcomponent
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
        let p = Path {
            segments: vec!["a".into(), "b".into(), "c".into()],
        };
        assert_eq!(p.to_string(), "/a/b/c");
    }

    #[test]
    fn display_path_encodes_special_chars() {
        let p = Path {
            segments: vec!["hello world".into()],
        };
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
        let p = Path {
            segments: vec!["a".into(), "".into()],
        };
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
        assert_eq!(parse_uri("http://host/a%2Fb").unwrap().path.segments, ["a/b"]);
        assert_eq!(parse_uri("http://host/a%2fb").unwrap().path.segments, ["a/b"]);
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

    // ==================== NEW: FromStr ====================

    #[test]
    fn from_str_basic() {
        let uri: Uri = "http://example.com/path".parse().unwrap();
        assert_eq!(uri.scheme.name, "http");
        assert_eq!(uri.path.segments, ["path"]);
    }

    #[test]
    fn from_str_non_ascii_rejected() {
        assert!("http://example.com/p\u{00E9}th".parse::<Uri>().is_err());
    }

    // ==================== NEW: Builder ====================

    #[test]
    fn builder_simple() {
        let uri = Uri::builder().scheme("https").host("example.com").path_segments(&["a", "b"]).build().unwrap();
        assert_eq!(uri.to_string(), "https://example.com/a/b");
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
    fn builder_missing_scheme_error() {
        let err = Uri::builder().host("example.com").build();
        assert!(err.is_err());
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
    fn builder_ipv6_host() {
        let uri = Uri::builder().scheme("https").host("[::1]").port(29510).path_segments(&["path"]).build().unwrap();
        assert_eq!(uri.to_string(), "https://[::1]:29510/path");
    }

    #[test]
    fn builder_no_host_no_authority() {
        let uri = Uri::builder().scheme("urn").path_segments(&["isbn:0451450523"]).build().unwrap();
        assert!(uri.authority.is_none());
        assert_eq!(uri.to_string(), "urn:/isbn:0451450523");
    }

    // ==================== NEW: Query accessors ====================

    #[test]
    fn query_get() {
        let q = parse_uri("http://h/?a=1&b=2").unwrap().query.unwrap();
        assert_eq!(q.get("a"), Some("1"));
        assert_eq!(q.get("b"), Some("2"));
        assert_eq!(q.get("c"), None);
    }

    #[test]
    fn query_get_all() {
        let q = parse_uri("http://h/?a=1&a=2&a=3").unwrap().query.unwrap();
        assert_eq!(q.get_all("a"), vec!["1", "2", "3"]);
        assert!(q.get_all("b").is_empty());
    }

    #[test]
    fn query_get_csv() {
        let q = parse_uri("http://h/?names=svc1,svc2,svc3").unwrap().query.unwrap();
        assert_eq!(q.get_csv("names"), Some(vec!["svc1", "svc2", "svc3"]));
        assert_eq!(q.get_csv("missing"), None);
    }

    #[test]
    fn query_iter() {
        let q = parse_uri("http://h/?a=1&b=2").unwrap().query.unwrap();
        let pairs: Vec<_> = q.iter().collect();
        assert_eq!(pairs, vec![("a", "1"), ("b", "2")]);
    }

    #[test]
    fn query_contains_key() {
        let q = parse_uri("http://h/?a=1").unwrap().query.unwrap();
        assert!(q.contains_key("a"));
        assert!(!q.contains_key("b"));
    }

    #[test]
    fn query_is_empty_and_len() {
        let q_empty = parse_uri("http://h/?").unwrap().query.unwrap();
        assert!(q_empty.is_empty());
        assert_eq!(q_empty.len(), 0);

        let q = parse_uri("http://h/?a=1&b=2").unwrap().query.unwrap();
        assert!(!q.is_empty());
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn query_key_without_value() {
        let q = parse_uri("http://h/?flag&a=1").unwrap().query.unwrap();
        assert_eq!(q.get("flag"), Some(""));
        assert_eq!(q.get("a"), Some("1"));
    }

    #[test]
    fn query_empty_value() {
        let q = parse_uri("http://h/?a=&b=2").unwrap().query.unwrap();
        assert_eq!(q.get("a"), Some(""));
        assert_eq!(q.get("b"), Some("2"));
    }

    #[test]
    fn query_pct_encoded_ampersand_in_value() {
        // %26 is '&' — must NOT split parameters
        let q = parse_uri("http://h/?a=x%26y&b=2").unwrap().query.unwrap();
        assert_eq!(q.get("a"), Some("x&y"));
        assert_eq!(q.get("b"), Some("2"));
    }

    #[test]
    fn query_pct_encoded_equals_in_value() {
        // %3D is '=' — must NOT split key/value
        let q = parse_uri("http://h/?a=x%3Dy").unwrap().query.unwrap();
        assert_eq!(q.get("a"), Some("x=y"));
    }

    // ==================== NEW: Equality ====================

    #[test]
    fn eq_same_uri() {
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
    fn eq_hash_consistent() {
        let a = parse_uri("HTTP://Example.COM/path").unwrap();
        let b = parse_uri("http://example.com/path").unwrap();
        assert_eq!(a, b);

        let mut set = HashSet::new();
        set.insert(a);
        // b should be found in the set since it's equal to a
        // (We can't directly test this without implementing Hash for Uri in HashSet,
        // but we verify the hash values are the same)
        let mut ha = std::hash::DefaultHasher::new();
        parse_uri("HTTP://Example.COM/path").unwrap().hash(&mut ha);
        let hash_a = ha.finish();

        let mut hb = std::hash::DefaultHasher::new();
        parse_uri("http://example.com/path").unwrap().hash(&mut hb);
        let hash_b = hb.finish();

        assert_eq!(hash_a, hash_b);
    }

    // ==================== NEW: Error positions ====================

    #[test]
    fn error_scheme_position() {
        let err = parse_uri("1http://h").unwrap_err();
        match err {
            UriParseError::SchemeInvalid { pos } => assert_eq!(pos, 0),
            other => panic!("expected SchemeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn error_pct_decode_position() {
        let err = parse_uri("http://host/a%GG").unwrap_err();
        match err {
            UriParseError::PctDecodeInvalid { pos } => assert_eq!(pos, 13),
            other => panic!("expected PctDecodeInvalid, got {other:?}"),
        }
    }

    // ==================== NEW: Public percent-encoding utilities ====================

    #[test]
    fn percent_decode_simple() {
        assert_eq!(percent_decode("hello%20world").unwrap(), "hello world");
    }

    #[test]
    fn percent_decode_no_encoding() {
        assert_eq!(percent_decode("hello").unwrap(), "hello");
    }

    #[test]
    fn percent_decode_error() {
        assert!(percent_decode("hello%G").is_err());
    }

    #[test]
    fn percent_encode_path_encodes_special() {
        assert_eq!(percent_encode_path("hello world"), "hello%20world");
        assert_eq!(percent_encode_path("a/b"), "a%2Fb");
    }

    #[test]
    fn percent_encode_query_key_encodes_delimiters() {
        assert_eq!(percent_encode_query_key("a=b"), "a%3Db");
        assert_eq!(percent_encode_query_key("a&b"), "a%26b");
    }

    #[test]
    fn percent_encode_query_value_encodes_delimiters() {
        assert_eq!(percent_encode_query_value("x=y"), "x%3Dy");
        assert_eq!(percent_encode_query_value("x&y"), "x%26y");
    }
}
