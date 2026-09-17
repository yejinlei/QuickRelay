//! Configuration key model: the four runtime-changeable groups, their keys,
//! value types, effective-timing granularity and the immutable-key registry.
//!
//! Architecture reference: `docs/architecture/architecture.md` §9.2 (changeable
//! items), §9.3 (restart-only items), §9.4 (invariants and rollback).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The four groups of runtime-changeable configuration (architecture §9.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Group {
    /// `max-bps` / `max-bw` / `max-rate` / `min-timeout` / `max-timeout` /
    /// `max-alloc-lifetime` / `max-alloc`
    RateLimit,
    /// `no-peer` / `no-data` / `no-channel`
    StreamFlags,
    /// `realm` / `static-secret` / `use-ephemeral-keys` / `users`
    Auth,
    /// `log-level` / `metrics-enable`
    Observability,
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RateLimit => "rate-limit",
            Self::StreamFlags => "stream-flags",
            Self::Auth => "auth",
            Self::Observability => "observability",
        })
    }
}

/// The three effective-timing granularities of architecture §9.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EffectiveTiming {
    /// Committed under the write lock and visible to every later decision point.
    Immediate,
    /// Committed now, applied to not-yet-expired entries at the next time-wheel tick.
    NextTimeoutScan,
    /// Applies only to allocations created after the change; existing
    /// allocations keep their negotiated limits for their whole lifetime.
    NewAllocation,
}

impl fmt::Display for EffectiveTiming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Immediate => "immediate",
            Self::NextTimeoutScan => "next-timeout-scan",
            Self::NewAllocation => "new-allocation",
        })
    }
}

/// Every configuration key the REST surface knows about.
///
/// The wire name is the kebab-case string in [`ConfigKey::NAME`]; it matches
/// the CLI flag and the TOML key, so operators never have to learn a second
/// spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConfigKey {
    // -- rate-limit & capacity -------------------------------------------
    MaxBps,
    MaxBw,
    MaxRate,
    MinTimeout,
    MaxTimeout,
    MaxAllocLifetime,
    MaxAlloc,
    // -- stream flags -----------------------------------------------------
    NoPeer,
    NoData,
    NoChannel,
    // -- auth -------------------------------------------------------------
    Realm,
    StaticSecret,
    UseEphemeralKeys,
    Users,
    // -- observability ----------------------------------------------------
    LogLevel,
    MetricsEnable,
}

/// A credential pair carried by the `users` key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Credential {
    pub user: String,
    pub password: String,
}

/// Typed configuration values.
///
/// The variant must match the key's declared type; mismatches are rejected
/// with HTTP 400 before any lock is taken (see [`RuntimeValidationError`]).
#[derive(Clone, Debug, PartialEq)]
pub enum KeyValue {
    /// Bounded unsigned integer.
    U64(u64),
    /// Switch.
    Bool(bool),
    /// Free-form string (`realm`, `log-level`).
    Str(String),
    /// Credential list. Carried only by `ConfigKey::Users`; the value is the
    /// **full effective list** (startup credentials plus runtime additions).
    Users(Vec<Credential>),
    /// The `static-secret` key. Kept separate from [`KeyValue::Str`] because
    /// secret material is redacted in every response and log line.
    Secret(String),
}

impl KeyValue {
    /// Value validation. Returns [`RuntimeValidationError`] for type mismatch
    /// and out-of-range values.
    ///
    /// Called before any lock is taken, so a rejected request never observes a
    /// partially applied patch (architecture §9.5).
    pub fn validate(self, key: ConfigKey) -> Result<Self, RuntimeValidationError> {
        match (key, self) {
            (k, KeyValue::U64(v)) => match numeric_range(k) {
                Some((lo, hi)) => {
                    if !(lo..=hi).contains(&v) {
                        return Err(RuntimeValidationError::new(
                            k,
                            format!("out of range: expected {lo}..={hi}, got {v}"),
                        ));
                    }
                    Ok(KeyValue::U64(v))
                }
                None => Err(RuntimeValidationError::new(
                    k,
                    format!("type mismatch: expected {}, got integer", key_type_name(k)),
                )),
            },
            (ConfigKey::NoPeer | ConfigKey::NoData | ConfigKey::NoChannel, KeyValue::Bool(v))
            | (ConfigKey::UseEphemeralKeys, KeyValue::Bool(v))
            | (ConfigKey::MetricsEnable, KeyValue::Bool(v)) => Ok(KeyValue::Bool(v)),
            (ConfigKey::Realm, KeyValue::Str(v)) => {
                let trimmed = v.trim();
                if trimmed.is_empty() || trimmed.len() > 255 || trimmed.contains(char::is_whitespace) {
                    return Err(RuntimeValidationError::new(
                        ConfigKey::Realm,
                        "realm must be 1..=255 non-whitespace characters",
                    ));
                }
                Ok(KeyValue::Str(trimmed.to_owned()))
            }
            (ConfigKey::LogLevel, KeyValue::Str(v)) => {
                if !matches!(v.as_str(), "trace" | "debug" | "info" | "warn" | "error" | "off") {
                    return Err(RuntimeValidationError::new(
                        ConfigKey::LogLevel,
                        "log-level must be one of trace, debug, info, warn, error, off",
                    ));
                }
                Ok(KeyValue::Str(v))
            }
            (ConfigKey::StaticSecret, KeyValue::Secret(v)) => {
                if v.trim().is_empty() {
                    return Err(RuntimeValidationError::new(
                        ConfigKey::StaticSecret,
                        "static-secret must be non-empty",
                    ));
                }
                Ok(KeyValue::Secret(v))
            }
            (ConfigKey::Users, KeyValue::Users(v)) => {
                if v.is_empty() {
                    return Err(RuntimeValidationError::new(ConfigKey::Users, "users must be non-empty"));
                }
                for c in &v {
                    if c.user.trim().is_empty()
                        || c.user.len() > 255
                        || c.user.contains(char::is_whitespace)
                    {
                        return Err(RuntimeValidationError::new(
                            ConfigKey::Users,
                            "user must be 1..=255 non-whitespace characters",
                        ));
                    }
                    if c.password.trim().is_empty() || c.password.len() > 512 {
                        return Err(RuntimeValidationError::new(
                            ConfigKey::Users,
                            "password must be 1..=512 non-whitespace characters",
                        ));
                    }
                }
                Ok(KeyValue::Users(v))
            }
            (k, other) => Err(RuntimeValidationError::new(
                k,
                format!("type mismatch: expected {}, got {}", key_type_name(k), value_type_name(&other)),
            )),
        }
    }
}

/// Human-readable expected type of a key, for the 400 error body.
fn key_type_name(k: ConfigKey) -> &'static str {
    match k {
        ConfigKey::MaxBps | ConfigKey::MaxBw | ConfigKey::MaxRate | ConfigKey::MinTimeout
        | ConfigKey::MaxTimeout | ConfigKey::MaxAllocLifetime | ConfigKey::MaxAlloc => "integer",
        ConfigKey::NoPeer | ConfigKey::NoData | ConfigKey::NoChannel | ConfigKey::UseEphemeralKeys
        | ConfigKey::MetricsEnable => "boolean",
        ConfigKey::Realm | ConfigKey::LogLevel => "string",
        ConfigKey::StaticSecret => "string (secret)",
        ConfigKey::Users => "array of {user, password}",
    }
}

/// Human-readable type of a value, for the 400 error body.
fn value_type_name(v: &KeyValue) -> &'static str {
    match v {
        KeyValue::U64(_) => "integer",
        KeyValue::Bool(_) => "boolean",
        KeyValue::Str(_) => "string",
        KeyValue::Secret(_) => "string",
        KeyValue::Users(_) => "array",
    }
}

/// Validation error produced by [`KeyValue::validate`].
#[derive(Debug)]
pub struct RuntimeValidationError {
    pub key: ConfigKey,
    pub message: String,
}

impl RuntimeValidationError {
    pub fn new(key: ConfigKey, message: impl Into<String>) -> Self {
        Self { key, message: message.into() }
    }
}

/// All changeable keys, in document order. Used by the snapshot endpoint and
/// by the generated documentation table.
pub const ALL_KEYS: &[ConfigKey] = &[
    ConfigKey::MaxBps,
    ConfigKey::MaxBw,
    ConfigKey::MaxRate,
    ConfigKey::MinTimeout,
    ConfigKey::MaxTimeout,
    ConfigKey::MaxAllocLifetime,
    ConfigKey::MaxAlloc,
    ConfigKey::NoPeer,
    ConfigKey::NoData,
    ConfigKey::NoChannel,
    ConfigKey::Realm,
    ConfigKey::StaticSecret,
    ConfigKey::UseEphemeralKeys,
    ConfigKey::Users,
    ConfigKey::LogLevel,
    ConfigKey::MetricsEnable,
];

/// Wire name of a key.
pub fn key_name(key: ConfigKey) -> &'static str {
    match key {
        ConfigKey::MaxBps => "max-bps",
        ConfigKey::MaxBw => "max-bw",
        ConfigKey::MaxRate => "max-rate",
        ConfigKey::MinTimeout => "min-timeout",
        ConfigKey::MaxTimeout => "max-timeout",
        ConfigKey::MaxAllocLifetime => "max-alloc-lifetime",
        ConfigKey::MaxAlloc => "max-alloc",
        ConfigKey::NoPeer => "no-peer",
        ConfigKey::NoData => "no-data",
        ConfigKey::NoChannel => "no-channel",
        ConfigKey::Realm => "realm",
        ConfigKey::StaticSecret => "static-secret",
        ConfigKey::UseEphemeralKeys => "use-ephemeral-keys",
        ConfigKey::Users => "users",
        ConfigKey::LogLevel => "log-level",
        ConfigKey::MetricsEnable => "metrics-enable",
    }
}

impl fmt::Display for ConfigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(key_name(*self))
    }
}

/// Parse a wire name into a key.
pub fn key_from_name(name: &str) -> Option<ConfigKey> {
    ALL_KEYS.iter().find(|k| key_name(*k) == name).copied()
}

/// Static metadata of a key: group, effective-timing granularity and whether
/// it belongs to the credential class (architecture §9.4).
#[derive(Clone, Copy, Debug)]
pub struct KeyMeta {
    pub group: Group,
    pub timing: EffectiveTiming,
    /// Credential-class keys: `users`, `static-secret`, `realm`. These reject
    /// `DELETE` with 409 (architecture §9.4).
    pub credential_class: bool,
}

pub fn key_meta(key: ConfigKey) -> KeyMeta {
    match key {
        ConfigKey::MaxBps | ConfigKey::MaxBw | ConfigKey::MaxRate => KeyMeta {
            group: Group::RateLimit,
            timing: EffectiveTiming::NewAllocation,
            credential_class: false,
        },
        ConfigKey::MinTimeout => KeyMeta {
            group: Group::RateLimit,
            timing: EffectiveTiming::Immediate,
            credential_class: false,
        },
        ConfigKey::MaxTimeout | ConfigKey::MaxAllocLifetime => KeyMeta {
            group: Group::RateLimit,
            timing: EffectiveTiming::NextTimeoutScan,
            credential_class: false,
        },
        ConfigKey::MaxAlloc => KeyMeta {
            group: Group::RateLimit,
            timing: EffectiveTiming::Immediate,
            credential_class: false,
        },
        ConfigKey::NoPeer | ConfigKey::NoData | ConfigKey::NoChannel => KeyMeta {
            group: Group::StreamFlags,
            timing: EffectiveTiming::Immediate,
            credential_class: false,
        },
        ConfigKey::Realm | ConfigKey::StaticSecret | ConfigKey::UseEphemeralKeys | ConfigKey::Users => KeyMeta {
            group: Group::Auth,
            timing: EffectiveTiming::Immediate,
            credential_class: true,
        },
        ConfigKey::LogLevel | ConfigKey::MetricsEnable => KeyMeta {
            group: Group::Observability,
            timing: EffectiveTiming::Immediate,
            credential_class: false,
        },
    }
}

/// Keys that **cannot** be changed at runtime and require a restart
/// (architecture §9.3). They are rejected with 409.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartRequiredKey {
    /// `--listening-ip` / `--listening-port`
    ListeningAddress,
    /// `--relay-range` / `--relay-ip`
    RelayRange,
    /// `--cert` / `--pkey` / `--cert-list`
    CertPaths,
    /// `--use-auth` / `--no-auth`
    AuthMode,
    /// REST listener address / port / TLS wrapping
    RestListener,
}

impl RestartRequiredKey {
    /// Wire names this restart-only item covers.
    pub fn names(&self) -> &'static [&'static str] {
        match self {
            Self::ListeningAddress => &["listening-ip", "listening-port", "listening-ipv6"],
            Self::RelayRange => &["relay-range", "relay-ip"],
            Self::CertPaths => &["cert", "pkey", "cert-list"],
            Self::AuthMode => &["use-auth", "no-auth"],
            Self::RestListener => &["rest-listening-ip", "rest-listening-port", "rest-tls"],
        }
    }
}

impl fmt::Display for RestartRequiredKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ListeningAddress => "listening address and port",
            Self::RelayRange => "relay range / relay ip",
            Self::CertPaths => "TLS certificate paths",
            Self::AuthMode => "authentication mode",
            Self::RestListener => "REST listener configuration",
        })
    }
}

/// Lookup table of restart-only names, used to give operators a precise
/// "you need a restart for this one" answer instead of a bare 409.
pub const ALL_RESTART_NAMES: [&str; 13] = [
    "listening-ip",
    "listening-port",
    "listening-ipv6",
    "relay-range",
    "relay-ip",
    "cert",
    "pkey",
    "cert-list",
    "use-auth",
    "no-auth",
    "rest-listening-ip",
    "rest-listening-port",
    "rest-tls",
];

/// One incoming change: a key and the raw JSON-ish value the operator sent.
#[derive(Debug)]
pub struct RequestPatch {
    values: BTreeMap<ConfigKey, KeyValue>,
}

impl RequestPatch {
    pub fn new() -> Self {
        Self { values: BTreeMap::new() }
    }

    pub fn insert(&mut self, key: ConfigKey, value: KeyValue) {
        // A repeated key in the same request is the operator's typo; keep the
        // first occurrence so behaviour is deterministic.
        self.values.entry(key).or_insert(value);
    }

    pub fn get(&self, key: ConfigKey) -> Option<&KeyValue> {
        self.values.get(&key)
    }

    pub fn contains(&self, key: ConfigKey) -> bool {
        self.values.contains_key(&key)
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = ConfigKey> + '_ {
        self.values.keys().copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (ConfigKey, &KeyValue)> + '_ {
        self.values.iter().map(|(k, v)| (*k, v))
    }

    /// Split into the validated keys (which go under the write lock) and the
    /// keys whose value failed validation (rejected with 400). The invalid
    /// keys are dropped from the patch, so a rejected request never leaves
    /// partial state behind.
    ///
    /// Keys that are unknown or restart-only are filtered out earlier, by
    /// [`key_from_name`], so they never reach here.
    pub fn validate_all(&mut self) -> (Vec<(ConfigKey, KeyValue)>, Vec<(ConfigKey, RuntimeValidationError)>) {
        let mut ok = Vec::new();
        let mut bad = Vec::new();
        let mut pending = std::collections::BTreeMap::new();
        std::mem::swap(&mut self.values, &mut pending);
        for (k, v) in pending {
            match v.validate(k) {
                Ok(v) => {
                    ok.push((k, v.clone()));
                    self.values.insert(k, v);
                }
                Err(e) => bad.push((k, e)),
            }
        }
        (ok, bad)
    }
}

impl Default for RequestPatch {
    fn default() -> Self {
        Self::new()
    }
}

/// The composed startup configuration: the file + CLI result handed to
/// [`super::ConfigController`] at boot. It is the immutable baseline that
/// `DELETE /api/v1/config/{key}` rolls back to.
#[derive(Clone, Debug, PartialEq)]
pub struct StartupConfig {
    pub max_bps: u64,
    pub max_bw: u64,
    pub max_rate: u64,
    pub min_timeout: u64,
    pub max_timeout: u64,
    pub max_alloc_lifetime: u64,
    pub max_alloc: u64,
    pub no_peer: bool,
    pub no_data: bool,
    pub no_channel: bool,
    pub realm: String,
    pub static_secret: Option<String>,
    pub use_ephemeral_keys: bool,
    pub users: BTreeSet<Credential>,
    pub log_level: String,
    pub metrics_enable: bool,
}

/// coturn-compatible defaults (`turnserver` defaults, see the protocol matrix).
impl Default for StartupConfig {
    fn default() -> Self {
        Self {
            max_bps: 0,
            max_bw: 0,
            max_rate: 0,
            min_timeout: 60,
            max_timeout: 600,
            max_alloc_lifetime: 0,
            max_alloc: 100_000,
            no_peer: false,
            no_data: false,
            no_channel: false,
            realm: "quickrelay.local".to_owned(),
            static_secret: None,
            use_ephemeral_keys: false,
            users: BTreeSet::new(),
            log_level: "info".to_owned(),
            metrics_enable: true,
        }
    }
}

impl StartupConfig {
    /// The started value of one key.
    pub fn started_value(&self, key: ConfigKey) -> KeyValue {
        match key {
            ConfigKey::MaxBps => KeyValue::U64(self.max_bps),
            ConfigKey::MaxBw => KeyValue::U64(self.max_bw),
            ConfigKey::MaxRate => KeyValue::U64(self.max_rate),
            ConfigKey::MinTimeout => KeyValue::U64(self.min_timeout),
            ConfigKey::MaxTimeout => KeyValue::U64(self.max_timeout),
            ConfigKey::MaxAllocLifetime => KeyValue::U64(self.max_alloc_lifetime),
            ConfigKey::MaxAlloc => KeyValue::U64(self.max_alloc),
            ConfigKey::NoPeer => KeyValue::Bool(self.no_peer),
            ConfigKey::NoData => KeyValue::Bool(self.no_data),
            ConfigKey::NoChannel => KeyValue::Bool(self.no_channel),
            ConfigKey::Realm => KeyValue::Str(self.realm.clone()),
            ConfigKey::StaticSecret => KeyValue::Secret(self.static_secret.clone().unwrap_or_default()),
            ConfigKey::UseEphemeralKeys => KeyValue::Bool(self.use_ephemeral_keys),
            ConfigKey::Users => KeyValue::Users(self.users.iter().cloned().collect()),
            ConfigKey::LogLevel => KeyValue::Str(self.log_level.clone()),
            ConfigKey::MetricsEnable => KeyValue::Bool(self.metrics_enable),
        }
    }

    /// Cross-field validation of the startup composition.
    pub fn validate(&self) -> Result<(), RuntimeValidationError> {
        let range_check = |key: ConfigKey, v: u64, lo: u64, hi: u64| -> Result<(), RuntimeValidationError> {
            if !(lo..=hi).contains(&v) {
                Err(RuntimeValidationError::new(key, format!("out of range: expected {lo}..={hi}, got {v}")))
            } else {
                Ok(())
            }
        };
        range_check(ConfigKey::MaxBps, self.max_bps, 0, 1_000_000_000_000)?;
        range_check(ConfigKey::MaxBw, self.max_bw, 0, 1_000_000_000_000)?;
        range_check(ConfigKey::MaxRate, self.max_rate, 0, 1_000_000_000_000)?;
        range_check(ConfigKey::MinTimeout, self.min_timeout, 1, 2_592_000)?;
        range_check(ConfigKey::MaxTimeout, self.max_timeout, 1, 2_592_000)?;
        range_check(ConfigKey::MaxAllocLifetime, self.max_alloc_lifetime, 0, 2_592_000)?;
        range_check(ConfigKey::MaxAlloc, self.max_alloc, 1, 10_000_000)?;
        if self.min_timeout > self.max_timeout {
            return Err(RuntimeValidationError::new(
                ConfigKey::MinTimeout,
                "min-timeout must be <= max-timeout",
            ));
        }
        Ok(())
    }
}

/// Value bounds of the numeric keys, shared by startup and runtime validation.
pub const BPS_MAX: u64 = 1_000_000_000_000;
pub const SECONDS_MAX: u64 = 2_592_000;
pub const ALLOC_MAX: u64 = 10_000_000;

/// Range of a numeric key, or `None` for non-numeric keys.
pub fn numeric_range(key: ConfigKey) -> Option<(u64, u64)> {
    match key {
        ConfigKey::MaxBps | ConfigKey::MaxBw | ConfigKey::MaxRate => Some((0, BPS_MAX)),
        ConfigKey::MinTimeout | ConfigKey::MaxTimeout => Some((1, SECONDS_MAX)),
        ConfigKey::MaxAllocLifetime => Some((0, SECONDS_MAX)),
        ConfigKey::MaxAlloc => Some((1, ALLOC_MAX)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_key_has_a_name_and_metadata() {
        for k in ALL_KEYS {
            let name = key_name(*k);
            assert!(!name.is_empty(), "{k:?}");
            assert_eq!(key_from_name(name), Some(*k));
            assert!(matches!(key_meta(*k).group, Group::RateLimit | Group::StreamFlags | Group::Auth | Group::Observability));
        }
        assert_eq!(ALL_KEYS.len(), 16);
    }

    #[test]
    fn rate_limit_keys_are_new_allocation_and_timeout_keys_are_scanned() {
        assert_eq!(key_meta(ConfigKey::MaxBps).timing, EffectiveTiming::NewAllocation);
        assert_eq!(key_meta(ConfigKey::MaxRate).timing, EffectiveTiming::NewAllocation);
        assert_eq!(key_meta(ConfigKey::MinTimeout).timing, EffectiveTiming::Immediate);
        assert_eq!(key_meta(ConfigKey::MaxTimeout).timing, EffectiveTiming::NextTimeoutScan);
        assert_eq!(key_meta(ConfigKey::MaxAllocLifetime).timing, EffectiveTiming::NextTimeoutScan);
    }

    #[test]
    fn credential_class_is_exactly_users_static_secret_realm() {
        for k in ALL_KEYS {
            let expected = matches!(*k, ConfigKey::Users | ConfigKey::StaticSecret | ConfigKey::Realm);
            assert_eq!(key_meta(*k).credential_class, expected, "{k:?}");
        }
    }

    #[test]
    fn unknown_names_resolve_to_none() {
        assert_eq!(key_from_name("nope"), None);
        assert_eq!(key_from_name("max_bps"), None);
    }

    #[test]
    fn numeric_out_of_range_is_rejected() {
        let err = KeyValue::U64(SECONDS_MAX + 1).validate(ConfigKey::MaxTimeout);
        let err = err.unwrap_err();
        assert_eq!(err.key, ConfigKey::MaxTimeout);
    }
}
