//! The local keychain (ADR 0022): what one device holds — its X25519
//! keypair, every org's epoch keys it has been granted, and every log's
//! data keys those unwrap — plus the local operations: create orgs,
//! add logs, invite devices, rotate on removal, and install wraps that
//! arrived through the distribution channel.
//!
//! This is wrap/unwrap only. Nothing here fetches or transports key
//! material; the rendezvous slice owns the channel, and adoption is
//! always an explicit call with a wrap in hand (ADR 0022).

use std::collections::HashMap;

use pursecraft_core::ids::{OrgId, ScopeId};
use pursecraft_core::wire::OpMeta;

use crate::envelope;
use crate::error::CryptoError;
use crate::keys::{
    DataKey, DeviceKeypair, DevicePublicKey, WrappedLogKey, WrappedOrgKey, open_log_wrap,
    open_org_wrap, wrap_log_key, wrap_org_key,
};

/// Which epochs an invite grants the invitee (ADR 0022): current only —
/// the newcomer reads from their join forward — or all held epochs,
/// granting readable history. The capture lane picks the policy; both
/// cost one call here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Grant {
    CurrentEpoch,
    AllEpochs,
}

/// The artifact of a rotation (ADR 0022): fresh keys for every log of
/// the org, wrapped for the survivors' devices. Hand these to the
/// distribution channel; nothing here sends anything.
#[derive(Clone, Debug)]
pub struct Rotation {
    /// The epoch the rotation minted.
    pub epoch: u64,
    /// The new org epoch key, one wrap per surviving device.
    pub org_wraps: Vec<WrappedOrgKey>,
    /// Fresh data keys for every log of the org, wrapped under the new
    /// epoch key.
    pub log_wraps: Vec<WrappedLogKey>,
}

/// What a device holds for one org: its epoch keys (current and history).
#[derive(Debug, Default)]
struct OrgKeys {
    epochs: HashMap<u64, DataKey>,
}

/// What a device holds for one log: its data keys per epoch, and the org
/// the log belongs to (rotation walks all of an org's logs, ADR 0021's
/// single revocation point).
#[derive(Debug)]
struct LogKeys {
    org: OrgId,
    epochs: HashMap<u64, DataKey>,
}

/// One device's keychain (ADR 0022). In-memory by design: a real client
/// rebuilds it from (device private key in the platform keystore) +
/// (wrapped keys re-fetched or cached by the app shell) — this slice
/// provides the wraps as versioned records and the operations to fold
/// them back in.
#[derive(Debug)]
pub struct KeyChain {
    device: DeviceKeypair,
    orgs: HashMap<OrgId, OrgKeys>,
    logs: HashMap<ScopeId, LogKeys>,
}

impl KeyChain {
    /// A keychain for `device`.
    pub fn new(device: DeviceKeypair) -> Self {
        Self {
            device,
            orgs: HashMap::new(),
            logs: HashMap::new(),
        }
    }

    /// This chain's device public key — what other members wrap to.
    pub fn device_public(&self) -> DevicePublicKey {
        self.device.public()
    }

    /// Mint an org's epoch-0 key and keep it. Returns the wrap to THIS
    /// device — the org creator's copy; the channel distributes wraps to
    /// later members (invites wrap from the holder side, so no other
    /// wrap is needed at creation). Refused if this chain knows the org
    /// AT ALL — a down-mint inside an org that already has history is
    /// exactly the misbinding this crate refuses.
    pub fn create_org(&mut self, org: OrgId) -> Result<WrappedOrgKey, CryptoError> {
        if self.orgs.contains_key(&org) {
            return Err(CryptoError::WrongKeySlot);
        }
        let key = DataKey::generate()?;
        let wrap = wrap_org_key(&self.device.public(), &org, 0, &key)?;
        self.orgs.entry(org).or_default().epochs.insert(0, key);
        Ok(wrap)
    }

    /// Mint a data key for `scope` (the org's own log or one of its
    /// budget logs) under the org's current epoch, and return the wrap
    /// under that epoch key — the record other members install. One log,
    /// one registration: re-adding a known scope would silently destroy
    /// every held epoch key for it (and a cross-org re-add would re-bind
    /// it, the hostile-input case installs refuse), so both are loud.
    /// New epochs for an existing log come from [`KeyChain::rotate`] or
    /// wraps, never from here.
    pub fn add_log(&mut self, org: OrgId, scope: ScopeId) -> Result<WrappedLogKey, CryptoError> {
        if self.logs.contains_key(&scope) {
            return Err(CryptoError::WrongKeySlot);
        }
        let epoch = self.current_epoch(&org).ok_or(CryptoError::MissingEpoch {
            scope: ScopeId::Org(org),
            epoch: 0,
            held: None,
        })?;
        let epoch_key = self.org_key(&org, epoch).ok_or(CryptoError::MissingEpoch {
            scope: ScopeId::Org(org),
            epoch,
            held: Some(epoch),
        })?;
        let key = DataKey::generate()?;
        let wrap = wrap_log_key(epoch_key, &scope, epoch, &key)?;
        self.logs.insert(
            scope,
            LogKeys {
                org,
                epochs: HashMap::from([(epoch, key)]),
            },
        );
        Ok(wrap)
    }

    /// Wrap this org's epoch key(s) to another device — an invite, or a
    /// new-device restore. The wraps are addressed to `device`; the
    /// channel carries them.
    pub fn wrap_org_keys_to(
        &self,
        org: &OrgId,
        device: &DevicePublicKey,
        grant: Grant,
    ) -> Result<Vec<WrappedOrgKey>, CryptoError> {
        let entry = self.orgs.get(org).ok_or(CryptoError::MissingEpoch {
            scope: ScopeId::Org(*org),
            epoch: 0,
            held: None,
        })?;
        let latest = entry.epochs.keys().copied().max().unwrap_or(0);
        let epochs = match grant {
            Grant::CurrentEpoch => vec![latest],
            Grant::AllEpochs => entry.epochs.keys().copied().collect(),
        };
        epochs
            .into_iter()
            .map(|epoch| {
                wrap_org_key(
                    device,
                    org,
                    epoch,
                    entry.epochs.get(&epoch).expect("keyed above"),
                )
            })
            .collect()
    }

    /// Rotate `org`: mint epoch+1 — a fresh org epoch key wrapped to each
    /// survivor device, and a fresh data key for every log of the org
    /// wrapped under it (ADR 0021: membership removal is the single
    /// revocation point; ADR 0022: never reuse a key across epochs).
    /// Survivors install the wraps addressed to them; the removed member
    /// receives nothing and holds only dead epochs.
    pub fn rotate(
        &mut self,
        org: &OrgId,
        survivors: &[DevicePublicKey],
    ) -> Result<Rotation, CryptoError> {
        let current = self.current_epoch(org).ok_or(CryptoError::MissingEpoch {
            scope: ScopeId::Org(*org),
            epoch: 0,
            held: None,
        })?;
        let new_epoch = current + 1;
        let new_org_key = DataKey::generate()?;
        let org_wraps = survivors
            .iter()
            .map(|device| wrap_org_key(device, org, new_epoch, &new_org_key))
            .collect::<Result<Vec<_>, _>>()?;
        // Rotate every log of the org — the org log itself and each
        // budget log (all scopes registered under this org).
        let mut log_wraps = Vec::new();
        for (scope, log) in &mut self.logs {
            if log.org != *org {
                continue;
            }
            let key = DataKey::generate()?;
            log_wraps.push(wrap_log_key(&new_org_key, scope, new_epoch, &key)?);
            log.epochs.insert(new_epoch, key);
        }
        self.orgs
            .get_mut(org)
            .expect("current_epoch returned Some")
            .epochs
            .insert(new_epoch, new_org_key);
        Ok(Rotation {
            epoch: new_epoch,
            org_wraps,
            log_wraps,
        })
    }

    /// Install an org-key wrap this device received (invite, restore, or
    /// rotation). The wrap must be addressed to this device; its
    /// `(org, epoch)` identity is authenticated by the construction
    /// itself (ADR 0022) — doctored wraps fail and nothing is stored.
    /// A slot already holding DIFFERENT material is a conflict — the
    /// concurrent-rotation race the channel must order (ADR 0022) — and
    /// is refused loudly; re-delivering the same key (at-least-once) is
    /// an idempotent no-op.
    pub fn install_org_wrap(&mut self, wrap: &WrappedOrgKey) -> Result<(), CryptoError> {
        let key = open_org_wrap(&self.device, wrap)?;
        let epochs = &mut self.orgs.entry(wrap.org).or_default().epochs;
        conflict_check(epochs.get(&wrap.epoch), &key)?;
        epochs.insert(wrap.epoch, key);
        Ok(())
    }

    /// Install a log-key wrap, opened with this org's same-epoch epoch
    /// key. Requires the org wrap first — the two-level hierarchy in
    /// action (ADR 0022).
    pub fn install_log_wrap(&mut self, wrap: &WrappedLogKey) -> Result<(), CryptoError> {
        let org = match &wrap.scope {
            ScopeId::Org(org) => *org,
            ScopeId::Budget(_) => {
                // The owning org of a budget log is not derivable from
                // the scope id (ADR 0021: discovery is the org log's
                // data); the caller must say which org's epoch key opens
                // it — see install_log_wrap_for_org.
                return Err(CryptoError::WrongKeySlot);
            }
        };
        self.install_log_wrap_inner(wrap, org)
    }

    /// Install a log-key wrap for a budget log, naming the owning org
    /// (known from the org log's Budget entity, ADR 0021).
    pub fn install_log_wrap_for_org(
        &mut self,
        wrap: &WrappedLogKey,
        org: &OrgId,
    ) -> Result<(), CryptoError> {
        self.install_log_wrap_inner(wrap, *org)
    }

    fn install_log_wrap_inner(
        &mut self,
        wrap: &WrappedLogKey,
        org: OrgId,
    ) -> Result<(), CryptoError> {
        // Structural guard: a scope already registered under one org
        // cannot gain keys through another — two orgs claiming one
        // budget id is hostile input (ADR 0021), refused here rather
        // than half-installed.
        if let Some(existing) = self.logs.get(&wrap.scope)
            && existing.org != org
        {
            return Err(CryptoError::WrongKeySlot);
        }
        let epoch_key = self
            .org_key(&org, wrap.epoch)
            .ok_or(CryptoError::MissingEpoch {
                scope: ScopeId::Org(org),
                epoch: wrap.epoch,
                held: self.current_epoch(&org),
            })?;
        let key = open_log_wrap(epoch_key, wrap)?;
        let entry = self.logs.entry(wrap.scope).or_insert_with(|| LogKeys {
            org,
            epochs: HashMap::new(),
        });
        // Same-slot conflict as in install_org_wrap: a differing key for
        // an epoch this chain already holds is the rotation race — loud.
        conflict_check(entry.epochs.get(&wrap.epoch), &key)?;
        entry.org = org;
        entry.epochs.insert(wrap.epoch, key);
        Ok(())
    }

    /// Seal one op's plaintext payload under the log's current-epoch data
    /// key, bound to the op's identity (ADR 0022 envelope v1).
    pub fn seal_payload(&self, meta: &OpMeta, plaintext: &[u8]) -> Result<String, CryptoError> {
        let (epoch, key) = self.latest_log_key(&meta.scope).ok_or_else(|| {
            let held = self.highest_log_epoch(&meta.scope);
            CryptoError::MissingEpoch {
                scope: meta.scope,
                epoch: held.unwrap_or(0),
                held,
            }
        })?;
        envelope::seal(key, epoch, &envelope::op_binding(meta), plaintext)
    }

    /// Open one op's envelope. Stale or absent epochs answer
    /// [`CryptoError::MissingEpoch`] before any decryption; everything
    /// the AEAD refuses answers [`CryptoError::Auth`] (ADR 0022).
    pub fn open_payload(&self, meta: &OpMeta, sealed: &str) -> Result<Vec<u8>, CryptoError> {
        let parsed = envelope::parse(sealed)?;
        let key =
            self.log_key(&meta.scope, parsed.epoch)
                .ok_or_else(|| CryptoError::MissingEpoch {
                    scope: meta.scope,
                    epoch: parsed.epoch,
                    held: self.highest_log_epoch(&meta.scope),
                })?;
        Ok(envelope::open(key, &parsed, &envelope::op_binding(meta))?.to_vec())
    }

    /// The org's current (highest held) epoch, if any.
    pub fn current_epoch(&self, org: &OrgId) -> Option<u64> {
        self.orgs
            .get(org)
            .and_then(|o| o.epochs.keys().copied().max())
    }

    fn org_key(&self, org: &OrgId, epoch: u64) -> Option<&DataKey> {
        self.orgs.get(org).and_then(|o| o.epochs.get(&epoch))
    }

    fn log_key(&self, scope: &ScopeId, epoch: u64) -> Option<&DataKey> {
        self.logs.get(scope).and_then(|l| l.epochs.get(&epoch))
    }

    fn highest_log_epoch(&self, scope: &ScopeId) -> Option<u64> {
        self.logs
            .get(scope)
            .and_then(|l| l.epochs.keys().copied().max())
    }

    fn latest_log_key(&self, scope: &ScopeId) -> Option<(u64, &DataKey)> {
        let epoch = self.highest_log_epoch(scope)?;
        Some((epoch, self.log_key(scope, epoch)?))
    }
}

/// Same-slot install policy (ADR 0022's rotation-race posture): a slot
/// may be filled once; DIFFERENT material for a held slot is a loud
/// conflict, identical material is an idempotent no-op (at-least-once
/// redelivery). The byte comparison is local idempotence bookkeeping on
/// keys this device already holds — not a protocol oracle — so plain
/// equality is fine here.
fn conflict_check(held: Option<&DataKey>, incoming: &DataKey) -> Result<(), CryptoError> {
    if held.is_some_and(|held| held.as_bytes() != incoming.as_bytes()) {
        return Err(CryptoError::WrongKeySlot);
    }
    Ok(())
}
