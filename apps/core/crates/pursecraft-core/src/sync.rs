//! The oplog sync engine (ADRs 0007, 0017): the transport-free rendezvous
//! model and the client session that applies remote deltas.
//!
//! [`OpLog`] is the in-memory shape of the future server: it assigns
//! canonical per-budget sequences and inspects only server-visible
//! metadata. [`SyncSession`] is the client: idempotent delta application
//! onto [`BudgetState`], an HLC that absorbs every received op, and a
//! monotonic `last_seen` cursor.

use std::collections::HashMap;
use std::fmt;

use crate::hlc::Hlc;
use crate::ids::{BudgetId, OpId};
use crate::ops::{Applied, ApplyError, BudgetState, Op};

/// An op stamped with its canonical per-budget sequence (ADR 0007).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SequencedOp {
    pub seq: u64,
    pub op: Op,
}

/// A rejected append — corruption or a scoping violation is loud, never
/// merged (ADRs 0008, 0017).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LogError {
    /// The op is scoped to a budget other than this log's ([ADR 0008]).
    BudgetMismatch {
        op_budget: BudgetId,
        log_budget: BudgetId,
    },
    /// The same `op_id` was appended with different content. `op_id` must
    /// uniquely identify an op or convergence breaks, so a collision is
    /// surfaced instead of resolved (ADR 0017).
    OpIdConflict { op_id: OpId },
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetMismatch {
                op_budget,
                log_budget,
            } => write!(
                f,
                "op budget {op_budget} does not belong to op log {log_budget}"
            ),
            Self::OpIdConflict { op_id } => {
                write!(f, "op id {op_id} re-appended with different content")
            }
        }
    }
}

impl std::error::Error for LogError {}

/// The append-only, per-budget canonical op log — the rendezvous model of
/// [ADR 0007] as an in-memory type the future server drives. Sequences are
/// dense and 1-based; append order is the canonical order. Only
/// server-visible metadata (`op_id`, `budget_id`) is ever inspected
/// ([ADR 0009]).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct OpLog {
    budget_id: Option<BudgetId>,
    ops: Vec<SequencedOp>,
    seen: HashMap<OpId, u64>,
}

impl OpLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an op; returns its canonical sequence. Re-appending an
    /// identical op returns the original sequence (safe retries,
    /// [ADR 0007]). Errors leave the log untouched.
    pub fn append(&mut self, op: Op) -> Result<u64, LogError> {
        if let Some(&seq) = self.seen.get(&op.op_id) {
            if self.ops[seq as usize - 1].op == op {
                return Ok(seq);
            }
            return Err(LogError::OpIdConflict { op_id: op.op_id });
        }
        if let Some(log_budget) = self.budget_id
            && log_budget != op.budget_id
        {
            return Err(LogError::BudgetMismatch {
                op_budget: op.budget_id,
                log_budget,
            });
        }
        if self.budget_id.is_none() {
            self.budget_id = Some(op.budget_id);
        }
        let seq = self.ops.len() as u64 + 1;
        self.seen.insert(op.op_id, seq);
        self.ops.push(SequencedOp { seq, op });
        Ok(seq)
    }

    /// The ops with sequence greater than `since`, in canonical order
    /// (ADR 0007: deltas since the client's last-seen sequence).
    pub fn delta_since(&self, since: u64) -> impl Iterator<Item = &SequencedOp> {
        self.ops.iter().skip_while(move |s| s.seq <= since)
    }

    /// The highest assigned sequence — the high-water mark clients compare
    /// their cursor against.
    pub fn tip(&self) -> u64 {
        self.ops.len() as u64
    }

    /// The budget this log is scoped to, once the first op fixes it.
    pub fn budget_id(&self) -> Option<BudgetId> {
        self.budget_id
    }
}

/// How a delta disposed of its ops (ADR 0017).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DeltaSummary {
    /// Ops that wrote a field (or set it for the first time).
    pub applied: u64,
    /// Ops whose `op_id` was already applied — idempotent replays.
    pub duplicates: u64,
    /// Ops whose stamp had already lost a field — ignored.
    pub stale: u64,
    /// The session's `last_seen` after the delta.
    pub last_seen: u64,
}

/// One device's client side: materialized state, the device's HLC, and the
/// `last_seen` cursor (ADR 0017). The transport-free "sync session" the
/// future transport drives.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SyncSession {
    state: BudgetState,
    clock: Hlc,
    last_seen: u64,
}

impl SyncSession {
    pub fn new() -> Self {
        Self {
            state: BudgetState::new(),
            clock: Hlc::now(),
            last_seen: 0,
        }
    }

    /// Apply a delta of remote ops in delivered order (ADR 0017). Every op
    /// goes through the slice-1 idempotent LWW apply, the clock merges
    /// every successfully processed op, and `last_seen` advances to the
    /// maximum processed sequence — never regressing on re-delivery.
    ///
    /// The first failing op aborts the delta with its [`ApplyError`]: ops
    /// processed before it stay applied, the cursor stops at the failure,
    /// and retrying the same delta reproduces the error — the engine never
    /// advances past an op it could not apply.
    pub fn apply_delta<'a, I>(&mut self, delta: I) -> Result<DeltaSummary, ApplyError>
    where
        I: IntoIterator<Item = &'a SequencedOp>,
    {
        let mut summary = DeltaSummary {
            last_seen: self.last_seen,
            ..DeltaSummary::default()
        };
        for sequenced in delta {
            match self.state.apply(sequenced.op.clone())? {
                Applied::Applied => summary.applied += 1,
                Applied::Duplicate => summary.duplicates += 1,
                Applied::Stale => summary.stale += 1,
            }
            self.clock.merge(sequenced.op.hlc);
            self.last_seen = self.last_seen.max(sequenced.seq);
            summary.last_seen = self.last_seen;
        }
        Ok(summary)
    }

    /// The materialized state — converges across devices by ADR 0017's
    /// theorem.
    pub fn state(&self) -> &BudgetState {
        &self.state
    }

    /// The device clock: dominates every received op stamp, so post-delta
    /// local ticks outrank all of them.
    pub fn clock(&self) -> Hlc {
        self.clock
    }

    /// The last canonical sequence this session has processed (0 = nothing).
    pub fn last_seen(&self) -> u64 {
        self.last_seen
    }
}

impl Default for SyncSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AccountField, BudgetField, CategoryField, CategoryGroupField, EntityKind, Field,
        MonthCategoryField, PayeeField, TransactionField, Value,
    };
    use crate::ids::{DeviceId, EntityId, UserId};
    use crate::money::Milliunits;
    use crate::testkit::{Rng, v7};
    use uuid::Uuid;

    /// Synthetic stamps far above any real wall clock keep sessions'
    /// clock behavior deterministic (same trick as the hlc tests).
    const HLC_BASE: u64 = 1 << 60;
    /// v7-friendly ms for deterministic ids.
    const ID_MS: u64 = 1 << 40;
    const BUDGET_RAND: u64 = 1;

    fn budget() -> crate::ids::BudgetId {
        crate::ids::BudgetId::new(v7(1, BUDGET_RAND)).unwrap()
    }

    /// One deterministic op. `op_rand` disambiguates the op id; `(ms,
    /// logical)` is the stamp.
    fn op(op_rand: u64, ms: u64, logical: u32, field: Field, value: Value) -> Op {
        Op {
            op_id: OpId::new(v7(ID_MS, op_rand)).unwrap(),
            budget_id: budget(),
            device_id: DeviceId::new(Uuid::nil()).unwrap(),
            user_id: UserId::new(Uuid::nil()).unwrap(),
            entity_kind: EntityKind::Transaction,
            entity_id: EntityId::new(v7(ID_MS, 50)).unwrap(),
            field,
            value,
            hlc: Hlc {
                physical_ms: ms,
                logical,
            },
        }
    }

    fn sequenced(seq: u64, op: Op) -> SequencedOp {
        SequencedOp { seq, op }
    }

    fn amount(milli: i64) -> (Field, Value) {
        (
            Field::Transaction(TransactionField::Amount),
            Value::Milliunits(Milliunits::from_milli(milli)),
        )
    }

    #[test]
    fn append_assigns_dense_canonical_sequences() {
        let mut log = OpLog::new();
        let (field, value) = amount(1);
        assert_eq!(log.append(op(1, 10, 0, field, value.clone())), Ok(1));
        assert_eq!(log.append(op(2, 20, 0, field, value)), Ok(2));
        assert_eq!(log.tip(), 2);
        assert_eq!(log.budget_id(), Some(budget()));
        let seqs: Vec<u64> = log.delta_since(0).map(|s| s.seq).collect();
        assert_eq!(seqs, [1, 2], "append order is canonical order");
        assert!(log.delta_since(2).next().is_none());
        assert_eq!(log.delta_since(1).next().map(|s| s.seq), Some(2));
    }

    #[test]
    fn duplicate_append_returns_the_original_sequence() {
        let mut log = OpLog::new();
        let (field, value) = amount(7);
        let first = op(1, 10, 0, field, value);
        let first_id = first.op_id;
        assert_eq!(log.append(first.clone()), Ok(1));
        assert_eq!(log.append(first), Ok(1), "a retry is a no-op");
        assert_eq!(log.tip(), 1);
        // Same op_id, different content: corruption, loud (ADR 0017).
        let mut conflict = op(2, 20, 0, amount(0).0, amount(9).1);
        conflict.op_id = first_id;
        conflict.hlc = Hlc {
            physical_ms: 99,
            logical: 9,
        };
        assert_eq!(
            log.append(conflict),
            Err(LogError::OpIdConflict { op_id: first_id })
        );
        assert_eq!(log.tip(), 1, "a rejected append stores nothing");
    }

    #[test]
    fn foreign_budget_append_is_rejected() {
        let mut log = OpLog::new();
        let (field, value) = amount(1);
        assert!(log.append(op(1, 10, 0, field, value)).is_ok());
        let mut foreign = op(2, 20, 0, amount(0).0, amount(2).1);
        foreign.budget_id = crate::ids::BudgetId::new(v7(9, 9)).unwrap();
        assert!(matches!(
            log.append(foreign),
            Err(LogError::BudgetMismatch { .. })
        ));
        assert_eq!(log.tip(), 1);
    }

    #[test]
    fn duplicate_and_reordered_delivery_is_idempotent() {
        let (field, _) = amount(0);
        let ops = [
            op(1, 10, 0, field, amount(111).1),
            op(2, 20, 0, field, amount(222).1),
            op(3, 15, 0, Field::Transaction(TransactionField::Memo), {
                Value::Text("m".into())
            }),
            op(4, 30, 0, Field::Deleted, Value::Bool(true)),
        ];
        let mut rng = Rng::new(42);
        let mut reference: Option<BudgetState> = None;
        for _ in 0..8 {
            let mut delivery: Vec<SequencedOp> = ops
                .iter()
                .enumerate()
                .map(|(i, o)| sequenced(i as u64 + 1, o.clone()))
                .collect();
            // Shuffle, then inject duplicates at random positions.
            shuffle(&mut rng, &mut delivery);
            for _ in 0..delivery.len() / 2 {
                let at = rng.below(delivery.len() as u64 + 1) as usize;
                let copy = delivery[rng.below(delivery.len() as u64) as usize].clone();
                delivery.insert(at, copy);
            }
            let mut session = SyncSession::new();
            let summary = session.apply_delta(&delivery).unwrap();
            assert_eq!(summary.last_seen, 4, "the cursor is the high-water mark");
            assert_eq!(
                summary.applied + summary.duplicates + summary.stale,
                delivery.len() as u64
            );
            // Re-delivering the whole delta changes nothing but the counts.
            let again = session.apply_delta(&delivery).unwrap();
            assert_eq!(again.duplicates, delivery.len() as u64);
            assert_eq!(again.applied, 0);
            assert_eq!(again.stale, 0);
            // Per-field LWW winners are delivery-order independent.
            let txn = match session
                .state()
                .entity(&EntityId::new(v7(ID_MS, 50)).unwrap())
            {
                Some(crate::domain::Entity::Transaction(t)) => t.clone(),
                other => panic!("expected transaction, got {other:?}"),
            };
            assert_eq!(txn.amount, Some(Milliunits::from_milli(222)));
            assert_eq!(txn.memo.as_deref(), Some("m"));
            assert!(txn.deleted);
            // ...and every shuffle reached the same state.
            match &reference {
                None => reference = Some(session.state().clone()),
                Some(reference) => assert_eq!(session.state(), reference),
            }
        }
    }

    #[test]
    fn stale_arrivals_lose_but_the_cursor_moves() {
        let mut session = SyncSession::new();
        let (field, _) = amount(0);
        let newer = sequenced(1, op(2, 20, 0, field, amount(222).1));
        let older = sequenced(2, op(1, 10, 0, field, amount(111).1));
        assert_eq!(session.apply_delta([&newer]).unwrap().applied, 1);
        let summary = session.apply_delta([&older]).unwrap();
        assert_eq!(summary.stale, 1, "reordered older op loses the field");
        assert_eq!(summary.last_seen, 2, "the cursor still advances");
        let entity = session
            .state()
            .entity(&EntityId::new(v7(ID_MS, 50)).unwrap())
            .cloned()
            .unwrap();
        match entity {
            crate::domain::Entity::Transaction(t) => {
                assert_eq!(t.amount, Some(Milliunits::from_milli(222)))
            }
            other => panic!("expected transaction, got {other:?}"),
        }
    }

    #[test]
    fn skewed_remote_stamps_are_absorbed_by_the_clock() {
        // A device an hour ahead writes, then the local device receives.
        // LWW ranks by HLC, not arrival; and the session clock now
        // dominates the remote stamp, so the next local tick outranks it.
        let mut session = SyncSession::new();
        let ahead_ms = HLC_BASE + 3_600_000;
        let (field, value) = amount(9);
        let remote = sequenced(1, op(1, ahead_ms, 0, field, value));
        session.apply_delta([&remote]).unwrap();
        let mut clock = session.clock();
        assert!(clock > remote.op.hlc, "receive merges the remote clock");
        clock.tick();
        assert!(
            clock > remote.op.hlc,
            "a local tick after receiving outranks the skewed remote"
        );
    }

    #[test]
    fn corrupt_op_stops_the_delta_and_stays_loud() {
        let mut session = SyncSession::new();
        let (field, value) = amount(1);
        let good = sequenced(1, op(1, 10, 0, field, value));
        let lie = sequenced(
            2,
            op(
                2,
                20,
                0,
                Field::Account(AccountField::Name),
                Value::Text("x".into()),
            ),
        );
        let tail = sequenced(3, op(3, 30, 0, Field::Deleted, Value::Bool(true)));
        // Seed the entity so the delta's second op is a kind lie against it.
        session.apply_delta([&good.clone()]).unwrap();

        let err = session.apply_delta([&good, &lie.clone(), &tail.clone()]);
        assert!(matches!(err, Err(ApplyError::KindMismatch { .. })));
        assert_eq!(
            session.last_seen(),
            1,
            "the cursor stops before the failure"
        );
        assert_eq!(session.state().entities().count(), 1);

        // Retrying reproduces the error; nothing advances past it.
        let err = session.apply_delta([&lie, &tail]);
        assert!(matches!(err, Err(ApplyError::KindMismatch { .. })));
        assert_eq!(session.last_seen(), 1);
    }

    // ------------------------------------------------------------------
    // Convergence proofs (ADR 0017): N devices, shuffled/interleaved and
    // duplicated delivery, per-device clock skew, equal-HLC ties,
    // tombstone races, dangling references — all xorshift-deterministic
    // per the ADR 0016 convention.
    // ------------------------------------------------------------------

    const DEVICES: u64 = 5;
    const OPS_PER_DEVICE: usize = 80;
    const SEEDS: u64 = 25;
    /// Fixed per-device offsets in ms: two devices share a clock (forcing
    /// equal-HLC ties broken by op_id), one runs a year ahead, one a day
    /// behind the base.
    const SKEW: [u64; DEVICES as usize] = [0, 0, 3_600_000, 31_536_000_000, 86_399_999];

    /// Entity pool across every kind: (kind, id rand) — multiple entities
    /// per kind so ops race across both fields and entities.
    const POOL: [(EntityKind, u64); 12] = [
        (EntityKind::Budget, 1),
        (EntityKind::Account, 2),
        (EntityKind::Account, 30),
        (EntityKind::CategoryGroup, 3),
        (EntityKind::Category, 4),
        (EntityKind::Category, 21),
        (EntityKind::Category, 22),
        (EntityKind::Payee, 5),
        (EntityKind::Transaction, 6),
        (EntityKind::Transaction, 50),
        (EntityKind::MonthCategory, 7),
        (EntityKind::MonthCategory, 60),
    ];

    const TEXTS: [&str; 5] = ["", "GCash", "groceries ₱", "Meralco", "uña"];

    fn fields_for(kind: EntityKind) -> &'static [Field] {
        match kind {
            EntityKind::Budget => &[Field::Deleted, Field::Budget(BudgetField::Name)],
            EntityKind::Account => &[
                Field::Deleted,
                Field::Account(AccountField::Name),
                Field::Account(AccountField::Kind),
            ],
            EntityKind::CategoryGroup => &[
                Field::Deleted,
                Field::CategoryGroup(CategoryGroupField::Name),
            ],
            EntityKind::Category => &[
                Field::Deleted,
                Field::Category(CategoryField::Name),
                Field::Category(CategoryField::GroupId),
                Field::Category(CategoryField::Note),
            ],
            EntityKind::Payee => &[Field::Deleted, Field::Payee(PayeeField::Name)],
            EntityKind::Transaction => &[
                Field::Deleted,
                Field::Transaction(TransactionField::AccountId),
                Field::Transaction(TransactionField::Date),
                Field::Transaction(TransactionField::Amount),
                Field::Transaction(TransactionField::PayeeId),
                Field::Transaction(TransactionField::CategoryId),
                Field::Transaction(TransactionField::Memo),
                Field::Transaction(TransactionField::Cleared),
            ],
            EntityKind::MonthCategory => &[
                Field::Deleted,
                Field::MonthCategory(MonthCategoryField::Month),
                Field::MonthCategory(MonthCategoryField::CategoryId),
                Field::MonthCategory(MonthCategoryField::Budgeted),
            ],
        }
    }

    /// An id value: a pool entity of the referenced kind, or a dangling id
    /// (resolution's missing-reference path, ADR 0016).
    fn reference_value(rng: &mut Rng, kind: EntityKind) -> Value {
        let candidates: Vec<u64> = POOL
            .iter()
            .filter(|(k, _)| *k == kind)
            .map(|(_, r)| *r)
            .chain([9999])
            .collect();
        Value::Id(
            EntityId::new(v7(
                ID_MS,
                candidates[rng.below(candidates.len() as u64) as usize],
            ))
            .unwrap(),
        )
    }

    fn random_value(rng: &mut Rng, field: Field) -> Value {
        use crate::date::{Date, Month};
        match field {
            Field::Deleted => Value::Bool(rng.below(2) == 0),
            Field::Budget(BudgetField::Name)
            | Field::Account(AccountField::Name)
            | Field::CategoryGroup(CategoryGroupField::Name)
            | Field::Category(CategoryField::Name)
            | Field::Category(CategoryField::Note)
            | Field::Payee(PayeeField::Name)
            | Field::Transaction(TransactionField::Memo) => {
                Value::Text(TEXTS[rng.below(TEXTS.len() as u64) as usize].into())
            }
            Field::Account(AccountField::Kind) => Value::AccountKind(match rng.below(11) {
                0 => crate::domain::AccountKind::Checking,
                1 => crate::domain::AccountKind::Savings,
                2 => crate::domain::AccountKind::CreditCard,
                3 => crate::domain::AccountKind::Cash,
                4 => crate::domain::AccountKind::LineOfCredit,
                5 => crate::domain::AccountKind::Investment,
                6 => crate::domain::AccountKind::Mortgage,
                7 => crate::domain::AccountKind::OtherAsset,
                8 => crate::domain::AccountKind::OtherLiability,
                9 => crate::domain::AccountKind::Other,
                _ => crate::domain::AccountKind::Checking,
            }),
            Field::Category(CategoryField::GroupId) => {
                reference_value(rng, EntityKind::CategoryGroup)
            }
            Field::Transaction(TransactionField::AccountId) => {
                reference_value(rng, EntityKind::Account)
            }
            Field::Transaction(TransactionField::PayeeId) => {
                reference_value(rng, EntityKind::Payee)
            }
            Field::Transaction(TransactionField::CategoryId) => {
                reference_value(rng, EntityKind::Category)
            }
            Field::Transaction(TransactionField::Date) => Value::Date(
                Date::new(
                    2020 + rng.below(11) as u16,
                    1 + rng.below(12) as u8,
                    1 + rng.below(28) as u8,
                )
                .unwrap(),
            ),
            Field::Transaction(TransactionField::Amount)
            | Field::MonthCategory(MonthCategoryField::Budgeted) => {
                Value::Milliunits(Milliunits::from_milli(rng.next_i64() / 8))
            }
            Field::Transaction(TransactionField::Cleared) => Value::Cleared(match rng.below(3) {
                0 => crate::domain::Cleared::Uncleared,
                1 => crate::domain::Cleared::Cleared,
                _ => crate::domain::Cleared::Reconciled,
            }),
            Field::MonthCategory(MonthCategoryField::Month) => Value::Month(
                Month::new(2024 + rng.below(4) as u16, 1 + rng.below(12) as u8).unwrap(),
            ),
            Field::MonthCategory(MonthCategoryField::CategoryId) => {
                reference_value(rng, EntityKind::Category)
            }
        }
    }

    /// Deterministic op stream: `DEVICES × OPS_PER_DEVICE` ops, per-device
    /// clock offsets, occasional same-ms logical bumps.
    fn generate_ops(seed: u64) -> Vec<Op> {
        let mut rng = Rng::new(seed | 1);
        let mut ops = Vec::new();
        let mut global: u64 = 0;
        for device in 0..DEVICES {
            for event in 0..OPS_PER_DEVICE as u64 {
                global += 1;
                let (kind, entity_rand) = POOL[rng.below(POOL.len() as u64) as usize];
                let fields = fields_for(kind);
                let field = fields[rng.below(fields.len() as u64) as usize];
                let value = random_value(&mut rng, field);
                let ms = HLC_BASE + SKEW[device as usize] + event;
                let logical = if rng.below(8) == 0 {
                    rng.below(3) as u32
                } else {
                    0
                };
                ops.push(Op {
                    op_id: OpId::new(v7(ID_MS, global)).unwrap(),
                    budget_id: budget(),
                    device_id: DeviceId::new(v7(ID_MS + device, 100 + device)).unwrap(),
                    user_id: UserId::new(v7(ID_MS + device % 2, 200 + device % 2)).unwrap(),
                    entity_kind: kind,
                    entity_id: EntityId::new(v7(ID_MS, entity_rand)).unwrap(),
                    field,
                    value,
                    hlc: Hlc {
                        physical_ms: ms,
                        logical,
                    },
                });
            }
        }
        ops
    }

    fn shuffle<T>(rng: &mut Rng, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = rng.below((i + 1) as u64) as usize;
            slice.swap(i, j);
        }
    }

    /// Scenario (a): the rendezvous loop — devices push their ops to the
    /// log in a shuffled interleave and pull random-sized deltas, sometimes
    /// re-pulling overlaps (at-least-once delivery), until everyone has
    /// everything.
    #[test]
    fn n_devices_converge_through_the_rendezvous_loop() {
        for seed in 1..=SEEDS {
            let ops = generate_ops(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let mut rng = Rng::new(seed.wrapping_mul(0x5851_F42D_4C95_7F2D));
            let mut log = OpLog::new();
            let mut queues: Vec<std::collections::VecDeque<Op>> = (0..DEVICES)
                .map(|d| {
                    ops[d as usize * OPS_PER_DEVICE..(d as usize + 1) * OPS_PER_DEVICE]
                        .iter()
                        .cloned()
                        .collect()
                })
                .collect();
            let mut sessions: Vec<SyncSession> = (0..DEVICES).map(|_| SyncSession::new()).collect();

            while queues.iter().any(|q| !q.is_empty()) {
                let d = rng.below(DEVICES) as usize;
                for _ in 0..1 + rng.below(4) {
                    if let Some(op) = queues[d].pop_front() {
                        log.append(op).expect("generated ops are well-formed");
                    }
                }
                for session in &mut sessions {
                    if rng.below(3) == 0 {
                        // Mostly pull only new ops; sometimes re-pull an
                        // overlap — at-least-once delivery.
                        let since = if rng.below(4) == 0 {
                            session.last_seen().saturating_sub(rng.below(5))
                        } else {
                            session.last_seen()
                        };
                        session
                            .apply_delta(log.delta_since(since))
                            .expect("generated ops are well-formed");
                    }
                }
            }
            for session in &mut sessions {
                // First full drain brings the session to the tip (some ops
                // may never have been pulled); a second full re-delivery
                // must then be pure duplicates — at-least-once idempotence.
                let drained = session.apply_delta(log.delta_since(0)).unwrap();
                assert_eq!(drained.last_seen, log.tip());
                let summary = session.apply_delta(log.delta_since(0)).unwrap();
                assert_eq!(summary.last_seen, log.tip());
                assert_eq!(summary.applied, 0, "everything was already applied");
                assert_eq!(summary.stale, 0);
                assert_eq!(summary.duplicates, log.tip());
            }

            let reference = sessions[0].state().clone();
            for (i, session) in sessions.iter().enumerate() {
                assert_eq!(
                    session.state(),
                    &reference,
                    "device {i} diverged (seed {seed})"
                );
            }
            // The reference itself equals a fresh canonical-order session.
            let mut canonical = SyncSession::new();
            canonical
                .apply_delta(log.delta_since(0))
                .expect("generated ops are well-formed");
            assert_eq!(canonical.state(), &reference, "seed {seed}");
            assert_eq!(log.tip(), (DEVICES as usize * OPS_PER_DEVICE) as u64);
        }
    }

    /// Scenario (b): no log at all — each device receives the full op set
    /// as an independent shuffle with injected duplicates, in random batch
    /// sizes; all must equal the generation-order reference.
    #[test]
    fn n_devices_converge_from_shuffled_duplicated_delivery() {
        for seed in 1..=SEEDS {
            let ops = generate_ops(seed.wrapping_mul(0xBF58_476D_1CE4_E5B9));
            let mut reference = BudgetState::new();
            for op in &ops {
                reference
                    .apply(op.clone())
                    .expect("generated ops are well-formed");
            }

            let mut rng = Rng::new(seed.wrapping_mul(0x94D0_49BB_1331_11EB));
            for device in 0..DEVICES {
                let mut delivery: Vec<SequencedOp> = ops
                    .iter()
                    .enumerate()
                    .map(|(i, op)| sequenced(i as u64 + 1, op.clone()))
                    .collect();
                shuffle(&mut rng, &mut delivery);
                let duplicates = delivery.len() / 8;
                for _ in 0..duplicates {
                    let at = rng.below(delivery.len() as u64 + 1) as usize;
                    let copy = delivery[rng.below(delivery.len() as u64) as usize].clone();
                    delivery.insert(at, copy);
                }
                let mut session = SyncSession::new();
                let mut rest = delivery.as_slice();
                while !rest.is_empty() {
                    let take = (1 + rng.below(7) as usize).min(rest.len());
                    let (batch, tail) = rest.split_at(take);
                    session
                        .apply_delta(batch)
                        .expect("generated ops are well-formed");
                    rest = tail;
                }
                assert_eq!(
                    session.state(),
                    &reference,
                    "device {device} diverged (seed {seed})"
                );
                assert_eq!(session.last_seen(), ops.len() as u64);
            }
        }
    }
}
