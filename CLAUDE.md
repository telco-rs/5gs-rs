# 5gs-rs

A pure Rust implementation of the 3GPP 5G System (5GS) core network. This is a 5G Standalone (SA) implementation targeting **3GPP Release 19 (5G Advanced)**. The goal is to be the premier open-source 5G core.

## Guiding Principle

**Absolute, unconditional adherence to the 3GPP specifications is non-negotiable.** Every data type, API endpoint, procedure, state machine, timer, error code, and behavioral rule must faithfully implement the relevant 3GPP Technical Specifications. When in doubt, cite the exact TS number, section, and clause. Never guess at spec behavior — look it up or ask.

## Key 3GPP Specifications

These are the primary specifications. Always reference the Release 19 versions. If a specification is not available in Release 19, use the specification from the most recent release. 

Specifications may reference other specifications. If a specification references another specification, ensure that the referenced specification is also adhered to.

If a specification from a previous release references another specification, always ensure the latest version of the referenced specification is used.

Release 20 is in development. Do not implement Release 20.

| Spec | Title | Relevance |
|------|-------|-----------|
| TS 23.501 | System Architecture for the 5G System | Overall architecture, NF definitions, reference points |
| TS 23.502 | Procedures for the 5G System | Call flows, registration, session management procedures |
| TS 23.503 | Policy and Charging Control Framework | PCC rules, QoS model |
| TS 29.500 | Technical Realization of SBI | SBI framework, API conventions, URI structure, error handling |
| TS 29.501 | Principles and Guidelines for SBI | API design principles, versioning, resource naming |
| TS 29.510 | NRF Services | NF registration, discovery, management |
| TS 29.571 | Common Data Types | Shared data types across all SBI APIs (implemented in `ngs-common`) |
| TS 29.518 | AMF Services | Namf_Communication, Namf_EventExposure, etc. |
| TS 29.502 | SMF Services | Nsmf_PDUSession, etc. |
| TS 29.503 | UDM Services | Nudm_SDM, Nudm_UECM, etc. |
| TS 29.504 | UDR Services | Nudr_DataRepository |
| TS 29.505 | Usage of Structured Data | Subscription data schemas |
| TS 29.509 | AUSF Services | Nausf_UEAuthentication |
| TS 29.507 | PCF Services | Npcf_SMPolicyControl, etc. |

## Workspace Structure

```
crates/
├── common/           # ngs-common: TS 29.571 Common Data Types for SBI
├── nrf/              # ngc-nrf: NRF library — types, validation, service logic (TS 29.510)
├── nrf-server/       # ngc-nrf-server: Native binary (axum + tokio) for ngc-nrf
├── nrf-worker/       # ngc-nrf-worker: WASM Cloudflare Worker for ngc-nrf (future)
```

### Three-Layer Crate Architecture

Each NF is split into three layers to support multiple compilation targets:

1. **NF library** (`ngc-nrf`): All 3GPP service logic — types, validation, business rules, service functions. Framework-agnostic. No dependency on a specific HTTP framework or async runtime. This is the core of the NF.
2. **Native server** (`ngc-nrf-server`): Thin adapter that wires the NF library into `axum` + `tokio` for standard binary deployments (bare-metal, containers).
3. **WASM worker** (`ngc-nrf-worker`, future): Thin adapter that wires the NF library into the Cloudflare `worker` crate for edge deployments.

The NF library must remain target-agnostic. All HTTP framework and runtime dependencies belong in the server/worker crates only.

### Crate Naming Convention

Due to Rust's module system, names must begin with a letter. Thus, "ng" is used as a prefix in lieu of "5g".

- **`ngs-*`** (Next-Gen System): Shared libraries used across NFs (e.g., `ngs-common`)
- **`ngc-{nf}`** (Next-Gen Core): NF library crate (e.g., `ngc-nrf`)
- **`ngc-{nf}-server`**: Native binary adapter (e.g., `ngc-nrf-server`)
- **`ngc-{nf}-worker`**: WASM adapter (e.g., `ngc-nrf-worker`)

## SBI Requirements (TS 29.500)

Every NF must satisfy these baseline requirements from TS 29.500.

### Protocol (§5.2.1)

- All SBI communication **must** use HTTP/2 (IETF RFC 9113). HTTP/1.1 is not permitted between NFs.
- TLS 1.2 (RFC 5246) or TLS 1.3 (RFC 8446) is mandatory. Mutual TLS (mTLS) is the default NF authentication mechanism (TS 33.501 §13.3).
- OAuth 2.0 (RFC 6749) token-based authorization is supported via the NRF as authorization server.

### URI Structure (§5.2.10, TS 29.501 §4.4)

SBI URIs follow: `{apiRoot}/{apiName}/{apiVersion}/{resource}`

Where `apiRoot` is `{scheme}://{authority}[/{deploymentSpecificString}]` and `apiName` follows the convention `n{nfName}-{serviceName}` (e.g., `nnrf-disc`, `namf-comm`, `nsmf-pdusession`).

URI percent-encoding must comply with both RFC 3986 and the additional 3GPP restrictions in §5.2.10 (characters `"`, `%`, `{`, `}`, and space must always be percent-encoded).

### Body Encoding (§5.2.2)

Request/response bodies use JSON per IETF RFC 8259 — **not** percent-encoding:

- Content type: `application/json` (or `application/problem+json` for errors)
- Character encoding: UTF-8 (RFC 8259 §8.1), no BOM
- JSON string escaping per RFC 8259 §7 (backslash escapes for `"`, `\`, control characters; `\uXXXX` for Unicode)
- Binary data within JSON must be base64-encoded
- Multipart bodies use `multipart/related` when carrying both JSON and binary parts (e.g., N1/N2 containers in AMF/SMF interactions)

### Custom 3GPP Headers (§5.2.3.2)

All NFs must support these headers:

| Header                       | Reference    | Purpose                                  |
|------------------------------|--------------|------------------------------------------|
| `3gpp-Sbi-Message-Priority`  | §5.2.3.2.1   | Request priority (0 = highest)           |
| `3gpp-Sbi-Callback`          | §5.2.3.2.2   | Callback URI for async operations        |
| `3gpp-Sbi-Target-apiRoot`    | §5.2.3.2.3   | Target NF apiRoot when routing via SCP   |
| `3gpp-Sbi-Oci`               | §5.2.3.2.12  | Overload Control Information             |
| `3gpp-Sbi-Lci`               | §5.2.3.2.13  | Load Control Information                 |
| `3gpp-Sbi-NF-Peer-Info`      | §5.2.3.2.14  | Source/destination NF identification     |
| `3gpp-Sbi-Discovery-*`       | §5.2.3.2.3   | NF discovery delegation parameters (SCP) |
| `3gpp-Sbi-Routing-Binding`   | §5.2.3.2.4   | Binding indication for stateful routing  |

### Error Handling (§5.2.7, RFC 9457)

All error responses must use `ProblemDetails` (TS 29.571 §5.2.7.2) with content type `application/problem+json`:

- `type` — URI identifying the error type
- `title` — human-readable summary
- `status` — HTTP status code
- `detail` — human-readable explanation
- `cause` — machine-readable application-level error code (enumerated per-service in each NF spec, e.g., TS 29.510 §6.1.7 for NRF)
- `invalidParams` — array of invalid parameters for 400-class errors

### API Versioning (§5.2.4, TS 29.501 §4.3)

- Version in URI path: `/{apiName}/v{majorVersion}/{resource}`
- Full version is `{major}.{minor}.{patch}` (semver-like)
- Only major version appears in the URI; minor/patch are conveyed during NF registration and feature negotiation

### Feature Negotiation (§5.2.8)

Optional features are negotiated using `SupportedFeatures` — a hex-encoded bitmask. This appears in NF registration (TS 29.510) and in individual API request/response bodies.

### Subscription/Notification (§5.2.5)

Most NF services use a subscribe/notify pattern:

- Consumer sends a subscription request with a `callbackUri`
- Producer stores the subscription and POSTs notifications to the callback URI
- Subscriptions have an optional `expiry` time

### Overload and Load Control (§5.2.3.2.12, §5.2.3.2.13)

NFs signal load/overload state via `3gpp-Sbi-Oci` and `3gpp-Sbi-Lci` headers. Consumers must reduce traffic according to received overload control parameters.

## Architecture Patterns

### HTTP Stack (native server crates)

- **Runtime**: `tokio` (full features)
- **HTTP framework**: `axum`
- **HTTP middleware**: `tower-http`

### Common Dependencies (all crates)

- **Serialization**: `serde` (feature-gated where appropriate)
- **Validation**: `validator`

### Data Type Mapping

3GPP OpenAPI schema types map to Rust as follows:
- Required fields → direct types (e.g., `String`, `u16`)
- Optional fields → `Option<T>`
- Enumerations → Rust `enum`
- Structured types → `struct` with `#[derive(Debug, Clone, Serialize, Deserialize, Validate)]`
- Feature-gate serde derives with `#[cfg_attr(feature = "serde", derive(...))]` in the common crate

### ngs-common Scope

The `ngs-common` crate implements TS 29.571 and shared SBI infrastructure. It must provide:

- **URI types** — parsing and serialization per TS 29.500 §5.2.10 and RFC 3986
- **ProblemDetails** — error response body per TS 29.571 §5.2.7.2 and RFC 9457
- **3GPP SBI headers** — typed parsing/serialization for all `3gpp-Sbi-*` headers (TS 29.500 §5.2.3.2)
- **SupportedFeatures** — hex-encoded feature bitmask (TS 29.571 §5.2.2)
- **Base identity types** — SUPI (TS 23.501 §5.9.2), GPSI (TS 23.501 §5.9.4), PEI (TS 23.501 §5.9.3)
- **Network types** — PlmnId, Snssai, Tai, Guami, etc. (TS 29.571 §5.4)
- **Subscription/notification types** — callback URIs, expiry, notification structures (TS 29.500 §5.2.5)
- **Overload/load control types** — OCI and LCI structures (TS 29.500 §5.2.3.2.12–13)

### Module Organization

Each NF library crate organizes its SBI services as submodules:
```
crates/nrf/src/
├── lib.rs
├── config.rs
├── nfdiscovery/     # Nnrf_NFDiscovery service (TS 29.510 §6)
│   ├── mod.rs
│   └── types.rs
├── nfmanagement/    # Nnrf_NFManagement service (TS 29.510 §5)
│   ├── mod.rs
│   └── types.rs
```

Service module names are lowercased versions of the 3GPP service names without the NF prefix (e.g., `Nnrf_NFDiscovery` → `nfdiscovery`).

Each native server crate is a thin entrypoint:
```
crates/nrf-server/src/
├── main.rs          # tokio runtime bootstrap, axum router, server startup
```

## Coding Standards

### Rust Edition and Tooling

- **Edition**: 2024
- **Formatter**: `rustfmt` with `max_width = 190`
- Run `cargo fmt` before committing
- Run `cargo clippy` and fix all warnings

### File Naming

- Files that directly implement a single 3GPP-defined type use **PascalCase** matching the spec name: `ProblemDetails.rs`, `Uri.rs`
- All other files use standard Rust **snake_case**: `config.rs`, `mod.rs`

### Documentation

**Every doc comment must cite the authoritative specification.** No public type, field, function, module, or constant should exist without a spec reference. This includes 3GPP TSs, IETF RFCs, ITU-T recommendations, IEEE standards, or any other specification the code implements.

#### Format

Use `§` for section references. Always include the spec identifier and section number:

```rust
/// The NF profile as defined in 3GPP TS 29.510 §6.1.6.2.2.
```

```rust
/// Percent-encoding per IETF RFC 3986 §2.1.
```

```rust
/// SUPI format defined in 3GPP TS 23.501 §5.9.2, using the IMSI structure
/// from ITU-T E.212.
```

#### Rules

- **Module-level docs (`//!`)**: State what spec(s) the module implements, with section numbers
- **Structs/enums (`///`)**: Reference the exact spec table, clause, or OpenAPI schema that defines the type
- **Fields (`///`)**: Reference the spec if the field has spec-defined semantics, constraints, or allowed values (e.g., enumerations, value ranges, conditional presence rules)
- **Functions/methods (`///`)**: Reference the spec procedure, algorithm, or rule being implemented
- **Constants**: Reference the spec clause that defines the value
- **Inline comments (`//`)**: Use for implementation notes; spec references optional but encouraged for non-obvious logic derived from a spec
- **Multiple specs**: When code implements behavior at the intersection of multiple specs, cite all of them (e.g., a URI parser may cite both TS 29.500 and RFC 3986)
- **External specs**: 3GPP specifications frequently reference IETF RFCs (e.g., RFC 7230, RFC 6749, RFC 7515), ITU-T recommendations (e.g., E.212, E.164), and others. Always trace and cite the original spec, not just the 3GPP TS that references it

### Error Handling

- Use `thiserror` for error type definitions
- HTTP error responses must return `ProblemDetails` (TS 29.571 §5.2.7.2) as the response body with appropriate `application/problem+json` content type per TS 29.500 §5.2.7

### Testing

- Unit tests go in `#[cfg(test)] mod tests` at the bottom of the file they test
- Test against 3GPP-realistic values (e.g., PLMN IDs `001/01`, NRF FQDNs `nrf.5gc.mnc001.mcc001.3gppnetwork.org`, SBI URIs)
- Include tests for spec-mandated edge cases and error conditions

## Build & Run

```sh
cargo build                    # Build all crates
cargo test                     # Run all tests
cargo run -p ngc-nrf-server    # Run the NRF (native)
cargo clippy -- -D warnings    # Lint
cargo fmt --check              # Check formatting
```

## Spec Compliance Checklist (for contributors)

When implementing any feature, verify:

1. [ ] The data types exactly match the 3GPP OpenAPI definitions (field names, types, optionality, enumerations)
2. [ ] HTTP methods, status codes, and URI paths match the spec
3. [ ] Mandatory headers (e.g., `3gpp-Sbi-*` headers per TS 29.500 §5.2.3.2) are included
4. [ ] Error responses use ProblemDetails with correct `cause` values from the spec
5. [ ] Any timers or retransmission logic matches spec-defined values
6. [ ] JSON field names use exact casing from the 3GPP OpenAPI schemas (typically camelCase via `#[serde(rename = "...")]`)
