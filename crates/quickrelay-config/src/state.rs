//! `RuntimeConfig` and the `ConfigController` event hook.

use std::collections::BTreeSet;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::keys::{ALL_KEYS, Credential, ConfigKey, EffectiveTiming, KeyValue, KeyMeta, Group, StartupConfig};

/// One applied change, carried by [`ConfigChange`].
#[derive(Clone, Debug)]
pub struct ChangeEntry {
    pub key: ConfigKey,
    pub old_value: KeyValue,
    pub new_value: KeyValue,
}

/// Outcome of one request against the controller.
#[derive(Clone, Debug, Default)]
pub struct ChangeResult {
    /// Keys actually committed.
    pub applied: Vec<ChangeEntry>,
}

/// A runtime configuration change, the payload that leaves this crate.
///
/// Two consumers of this event are expected:
/// * **YEJ-147** — the `ConfigStore` trait / change-event channel. Implement
///   [`ConfigChangeHook`] and pass it to [`ConfigController::new`] so every
///   commit is forwarded.
/// * **YEJ-149** — the `config_changed` structured log / metrics sink. The
///   crate's own `tracing` call in [`ConfigController::commit`] already emits
///   the event with the field names of architecture §9.7.
///
/// No history is stored: this crate keeps exactly one committed state and
/// emits the event, then forgets it (architecture §9.6).
#[derive(Clone, Debug)]
pub struct ConfigChange {
    pub entries: Vec<ChangeEntry>,
    /// `patch`, `put` or `delete` — the operation that produced the change.
    pub kind: &'static str,
    /// Authentication method that performed the change: `bearer`, `hmac` or
    /// `anonymous` (tests). Never the credential itself.
    pub actor: String,
    /// Where the change came from: `rest` for HTTP requests.
    pub source: &'static str,
}

/// Sink for committed changes. The hook is invoked **after** the write lock is
/// released, so it may block without stalling writers or readers.
pub trait ConfigChangeHook: Send + Sync {
    fn on_change(&self, change: &ConfigChange);
}

/// The live runtime configuration: startup baseline plus applied overrides.
///
/// Read side contract (architecture §9.4 invariant 1): the packet-forwarding
/// hot path never touches this struct. The decision points that do touch it —
/// allocation creation, permission creation, channel binding, lifetime
/// clipping — take a [`RwLockReadGuard`] once and keep the cloned primitives
/// for the whole lifetime of the object they configure. Nothing here is
/// cached in `thread_local`.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
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
    /// Monotonic counter of committed change operations.
    pub revision: u64,
}

impl RuntimeConfig {
    pub fn from_startup(startup: &StartupConfig) -> Self {
        Self {
            max_bps: startup.max_bps,
            max_bw: startup.max_bw,
            max_rate: startup.max_rate,
            min_timeout: startup.min_timeout,
            max_timeout: startup.max_timeout,
            max_alloc_lifetime: startup.max_alloc_lifetime,
            max_alloc: startup.max_alloc,
            no_peer: startup.no_peer,
            no_data: startup.no_data,
            no_channel: startup.no_channel,
            realm: startup.realm.clone(),
            static_secret: startup.static_secret.clone(),
            use_ephemeral_keys: startup.use_ephemeral_keys,
            users: startup.users.clone(),
            log_level: startup.log_level.clone(),
            metrics_enable: startup.metrics_enable,
            revision: 0,
        }
    }

    /// The value this field held at startup.
    pub fn value(&self, key: ConfigKey) -> KeyValue {
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

    /// Write one already-validated value. Not used by the HTTP layer directly;
    /// it is the single place where key-to-field mapping lives, which is what
    /// keeps `apply` and `rollback` symmetric.
    pub fn set(&mut self, key: ConfigKey, value: &KeyValue) {
        match (key, value) {
            (ConfigKey::MaxBps, KeyValue::U64(v)) => self.max_bps = *v,
            (ConfigKey::MaxBw, KeyValue::U64(v)) => self.max_bw = *v,
            (ConfigKey::MaxRate, KeyValue::U64(v)) => self.max_rate = *v,
            (ConfigKey::MinTimeout, KeyValue::U64(v)) => self.min_timeout = *v,
            (ConfigKey::MaxTimeout, KeyValue::U64(v)) => self.max_timeout = *v,
            (ConfigKey::MaxAllocLifetime, KeyValue::U64(v)) => self.max_alloc_lifetime = *v,
            (ConfigKey::MaxAlloc, KeyValue::U64(v)) => self.max_alloc = *v,
            (ConfigKey::NoPeer, KeyValue::Bool(v)) => self.no_peer = *v,
            (ConfigKey::NoData, KeyValue::Bool(v)) => self.no_data = *v,
            (ConfigKey::NoChannel, KeyValue::Bool(v)) => self.no_channel = *v,
            (ConfigKey::Realm, KeyValue::Str(v)) => self.realm = v.clone(),
            (ConfigKey::StaticSecret, KeyValue::Secret(v)) => {
                self.static_secret = if v.is_empty() { None } else { Some(v.clone()) }
            }
            (ConfigKey::UseEphemeralKeys, KeyValue::Bool(v)) => self.use_ephemeral_keys = *v,
            (ConfigKey::Users, KeyValue::Users(v)) => self.users = v.iter().cloned().collect(),
            (ConfigKey::LogLevel, KeyValue::Str(v)) => self.log_level = v.clone(),
            (ConfigKey::MetricsEnable, KeyValue::Bool(v)) => self.metrics_enable = *v,
            _ => unreachable!("RuntimeConfig::set reached with a type mismatch after validation"),
        }
    }
}

/// The controller: `Arc<RwLock<RuntimeConfig>>` plus the immutable baseline
/// and the change hook (architecture §9.4).
#[derive(Clone)]
pub struct ConfigController {
    inner: Arc<Inner>,
}

struct Inner {
    /// Live state, mutated under the write lock.
    state: RwLock<RuntimeConfig>,
    /// The startup snapshot: the rollback target of `DELETE`.
    baseline: StartupConfig,
    hook: Option<Arc<dyn ConfigChangeHook>>,
    /// Whether metrics are exported, mirrored outside the lock so that the
    /// metrics sink does not need a `ConfigController` to answer 503.
    metrics_enabled: RwLock<bool>,
}

impl ConfigController {
    pub fn new(startup: StartupConfig, hook: Option<Arc<dyn ConfigChangeHook>>) -> Self {
        let state = RuntimeConfig::from_startup(&startup);
        let metrics_enabled = state.metrics_enable;
        Self {
            inner: Arc::new(Inner {
                state: RwLock::new(state),
                baseline: startup,
                hook,
                metrics_enabled: RwLock::new(metrics_enabled),
            }),
        }
    }

    /// Read-only view of the live state.
    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, RuntimeConfig> {
        self.inner.state.read()
    }

    /// The immutable startup baseline.
    pub fn baseline(&self) -> &StartupConfig {
        &self.inner.baseline
    }

    /// Read-only metrics switch, independent of the config lock so the
    /// `/metrics` handler never serialises behind a config write.
    pub fn metrics_enabled(&self) -> bool {
        *self.inner.metrics_enabled.read()
    }

    /// Write one or more validated values under a single write lock, publish
    /// the `config_changed` event, return the before/after entries.
    ///
    /// The lock is held for pure field assignment only: no I/O, no log
    /// formatting, no network calls (architecture §9.4 invariant 2,
    /// write-lock hold time < 1 ms).
    pub fn apply(&self, patch: &[(ConfigKey, KeyValue)], kind: &'static str, actor: &str) -> ChangeResult {
        let mut entries = Vec::new();
        let mut metrics_snapshot = false;
        {
            let mut state = self.inner.state.write();
            for (key, value) in patch {
                let old = state.value(*key);
                if old == *value {
                    // Idempotent: resending the same value is a no-op and must
                    // not bump the revision or emit an event.
                    continue;
                }
                state.set(*key, value);
                entries.push(ChangeEntry {
                    key: *key,
                    old_value: old,
                    new_value: value.clone(),
                });
            }
            if !entries.is_empty() {
                state.revision += 1;
                metrics_snapshot = state.metrics_enable;
            }
        }
        if entries.is_empty() {
            return ChangeResult { applied: entries };
        }
        // Mirror the switch outside the config lock so the `/metrics` handler
        // never serialises behind a config write.
        *self.inner.metrics_enabled.write() = metrics_snapshot;

        let change = ConfigChange {
            entries: entries.clone(),
            kind,
            actor: actor.to_owned(),
            source: "rest",
        };
        log_config_changed(&change);
        if let Some(hook) = &self.inner.hook {
            hook.on_change(&change);
        }
        ChangeResult { applied: entries }
    }

    /// Roll back one key to its startup value.
    ///
    /// Returns `None` when the key is of the credential class
    /// (`users`, `static-secret`, `realm`) — those must be rejected with 409,
    /// architecture §9.4.
    pub fn rollback_one(&self, key: ConfigKey, actor: &str) -> Option<ChangeResult> {
        if key_meta_credential_class(key) {
            return None;
        }
        let value = self.inner.baseline.started_value(key);
        let result = self.apply(&[(key, value)], "delete", actor);
        Some(result)
    }

    /// Whether a key currently differs from its startup value.
    pub fn is_overridden(&self, key: ConfigKey) -> bool {
        let state = self.read();
        state.value(key) != self.inner.baseline.started_value(key)
    }
}

fn key_meta_credential_class(key: ConfigKey) -> bool {
    key_meta(key).credential_class
}

fn key_meta(key: ConfigKey) -> KeyMeta {
    crate::keys::key_meta(key)
}

/// Emit the `config_changed` event described in architecture §9.7.
///
/// Field names are fixed: `key`, `old_value`, `new_value`, `source`, `actor`,
/// plus `kind` and `revision`. Credential-class values are redacted to
/// `<redacted>`.
fn log_config_changed(change: &ConfigChange) {
    for entry in &change.entries {
        let secret = key_meta(entry.key).credential_class;
        tracing::event!(
            tracing::Level::INFO,
            event = "config_changed",
            key = key_name(entry.key),
            group = %key_meta(entry.key).group,
            timing = %key_meta(entry.key).timing,
            kind = change.kind,
            source = change.source,
            actor = %change.actor,
            old_value = if secret { "<redacted>" } else { %display_value(&entry.old_value) },
            new_value = if secret { "<redacted>" } else { %display_value(&entry.new_value) },
        );
    }
}

fn key_name(key: ConfigKey) -> &'static str {
    crate::keys::key_name(key)
}

fn display_value(value: &KeyValue) -> String {
    match value {
        KeyValue::U64(v) => v.to_string(),
        KeyValue::Bool(v) => v.to_string(),
        KeyValue::Str(v) => v.clone(),
        KeyValue::Secret(_) => "<redacted>".to_owned(),
        KeyValue::Users(v) => format!("{} credential(s)", v.len()),
    }
}

