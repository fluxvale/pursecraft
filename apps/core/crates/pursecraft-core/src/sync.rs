//! The oplog sync engine (ADRs 0007, 0017): the transport-free rendezvous
//! model and the client session that applies remote deltas.
//!
//! [`OpLog`] is the in-memory shape of the future server: it assigns
//! canonical per-budget sequences and inspects only server-visible
//! metadata. [`SyncSession`] is the client: idempotent delta application
//! onto [`ScopeState`], an HLC that absorbs every received op, and a
//! monotonic `last_seen` cursor.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use crate::hlc::Hlc;
use crate::ids::{OpId, ScopeId};
use crate::ops::{Applied, ApplyError, Op, ScopeState};

/// An op stamped with its canonical per-log sequence (ADR 0007).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SequencedOp {
    pub seq: u64,
    pub op: Op,
}

/// A rejected append — a scoping violation is loud, never merged
/// ([ADRs 0008, 0020]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LogError {
    /// The op is scoped to a log other than this one's ([ADR 0008],
    /// [ADR 0021]).
    ScopeMismatch {
        op_scope: ScopeId,
        log_scope: ScopeId,
    },
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScopeMismatch {
                op_scope,
                log_scope,
            } => write!(
                f,
                "op scope {op_scope:?} does not belong to op log {log_scope:?}"
            ),
        }
    }
}

impl std::error::Error for LogError {}

/// The append-only, per-scope canonical op log — the rendezvous model of
/// [ADR 0007] as an in-memory type the future server drives; a log is
/// scoped to one org or one budget (ADR 0021). Sequences are 1-based and
/// append order is the canonical order in a fresh log. The log touches
/// only server-visible metadata: dedupe is by `op_id` alone (content is
/// opaque under [ADR 0009] — an encrypted retry must dedupe like an
/// identical one), and the loud same-id-different-content check lives in
/// [`ScopeState::apply`], where plaintext always lives (ADR 0017).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpLog {
    scope: Option<ScopeId>,
    ops: Vec<SequencedOp>,
    seen: HashMap<OpId, u64>,
    /// The sequence the next append assigns — 1 for a fresh log. A durable
    /// store resumes it above its commit high-water so a repair never
    /// reuses a sequence (ADR 0018).
    next_seq: u64,
}

impl Default for OpLog {
    fn default() -> Self {
        Self {
            scope: None,
            ops: Vec::new(),
            seen: HashMap::new(),
            next_seq: 1,
        }
    }
}

impl OpLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// A log whose next append assigns `seq` — how a durable store resumes
    /// its sequence space after a repair (ADR 0018).
    pub fn resuming_at(seq: u64) -> Self {
        Self {
            next_seq: seq,
            ..Self::default()
        }
    }

    /// Append an op; returns its canonical sequence. Scope checking is
    /// first (the scope is metadata — exactly what a real server sees),
    /// then dedupe by `op_id`: re-appending an op whose id is already
    /// stored returns the original sequence — safe retries ([ADR 0007]) —
    /// regardless of payload bytes. Errors leave the log untouched.
    pub fn append(&mut self, op: Op) -> Result<u64, LogError> {
        let seq = self.next_seq;
        let (assigned, stored) = self.append_inner(seq, op)?;
        if stored {
            self.next_seq = seq + 1;
        }
        Ok(assigned)
    }

    /// Append `op` under an explicit sequence — the boot path of a durable
    /// store, whose records carry the sequences they were assigned
    /// (ADR 0018). Sequences are advisory cursors, never identity
    /// (ADR 0017): gaps are legal and stall watermarks by design. Scoping
    /// and `op_id` dedupe follow [`OpLog::append`] exactly.
    pub(crate) fn append_sequenced(&mut self, seq: u64, op: Op) -> Result<u64, LogError> {
        self.append_inner(seq, op).map(|(assigned, _)| assigned)
    }

    /// The shared append: scope check, dedupe, then store under `seq`.
    /// Returns the op's sequence and whether it was newly stored.
    fn append_inner(&mut self, seq: u64, op: Op) -> Result<(u64, bool), LogError> {
        if let Some(log_scope) = self.scope
            && log_scope != op.scope
        {
            return Err(LogError::ScopeMismatch {
                op_scope: op.scope,
                log_scope,
            });
        }
        if let Some(&seen) = self.seen.get(&op.op_id) {
            return Ok((seen, false));
        }
        if self.scope.is_none() {
            self.scope = Some(op.scope);
        }
        self.seen.insert(op.op_id, seq);
        self.ops.push(SequencedOp { seq, op });
        Ok((seq, true))
    }

    /// The ops with sequence greater than `since`, in canonical order
    /// (ADR 0007: deltas since the client's last-seen sequence).
    pub fn delta_since(&self, since: u64) -> impl Iterator<Item = &SequencedOp> {
        self.ops.iter().skip_while(move |s| s.seq <= since)
    }

    /// The highest sequence in the log — the high-water mark clients
    /// compare their cursor against. (Sequences strictly increase, so
    /// the last record holds the maximum.)
    pub fn tip(&self) -> u64 {
        self.ops.last().map(|s| s.seq).unwrap_or(0)
    }

    /// The scope this log is fixed to, once the first op fixes it
    /// (ADR 0021).
    pub fn scope_id(&self) -> Option<ScopeId> {
        self.scope
    }

    /// The canonical sequence already assigned to `op_id`, if the log holds
    /// it — the dedupe lookup a durable store fronts with its own commit
    /// (ADR 0018).
    pub fn seq_of(&self, op_id: &OpId) -> Option<u64> {
        self.seen.get(op_id).copied()
    }

    /// The sequence the next [`OpLog::append`] assigns (ADR 0018).
    pub fn next_seq(&self) -> u64 {
        self.next_seq
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
/// future transport drives — one per log scope (ADR 0021).
#[derive(Clone, Debug)]
pub struct SyncSession {
    state: ScopeState,
    clock: Hlc,
    /// The contiguous resume watermark: every sequence up to and including
    /// it has been processed. `delta_since(last_seen)` can never skip an
    /// unprocessed op, whatever the arrival order (ADR 0007).
    last_seen: u64,
    /// Sequences processed ahead of the watermark, held until their gap
    /// fills so the watermark can advance over them.
    pending: BTreeSet<u64>,
}

impl SyncSession {
    pub fn new() -> Self {
        Self {
            state: ScopeState::new(),
            clock: Hlc::now(),
            last_seen: 0,
            pending: BTreeSet::new(),
        }
    }

    /// Apply a delta of remote ops in any order (ADR 0017). Every op goes
    /// through the slice-1 idempotent LWW apply, the clock merges every
    /// successfully processed op, and the cursor advances only across
    /// gap-free prefixes — reordered ops apply immediately but are held
    /// pending until the sequences below them arrive, so a later
    /// `delta_since(last_seen)` still re-serves anything the session has
    /// not seen. Sequence values are taken as advisory: absurd values can
    /// stall a watermark but never wedge it past unapplied ops.
    ///
    /// The first failing op aborts the delta with its [`ApplyError`]: ops
    /// processed before it stay applied, the cursor stops at the failure,
    /// and retrying the same delta reproduces the error — the engine never
    /// advances past an op it could not apply.
    pub fn apply_delta<'a, I>(&mut self, delta: I) -> Result<DeltaSummary, ApplyError>
    where
        I: IntoIterator<Item = &'a SequencedOp>,
    {
        // Seed the cursor from the session so an empty delta reports the
        // current watermark, not zero.
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
            let seq = sequenced.seq;
            if seq == self.last_seen.saturating_add(1) {
                self.last_seen = seq;
                while self.pending.remove(&self.last_seen.saturating_add(1)) {
                    self.last_seen = self.last_seen.saturating_add(1);
                }
            } else if seq > self.last_seen {
                self.pending.insert(seq);
            }
            summary.last_seen = self.last_seen;
        }
        Ok(summary)
    }

    /// The materialized state — converges across devices by ADR 0017's
    /// theorem, per scope (ADR 0021).
    pub fn state(&self) -> &ScopeState {
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

    /// How many sequences are processed but stranded behind a gap: 0 means
    /// the watermark is fully caught up; a value that persists while
    /// `last_seen` stalls says a sequence below the pending window never
    /// arrived — the designed stall the compaction slice's snapshot
    /// bootstrap answers (ADR 0007, ADR 0017).
    pub fn pending_len(&self) -> usize {
        self.pending.len()
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
    use crate::domain::{AccountField, Field, TransactionField, Value};
    use crate::ids::EntityId;
    use crate::money::Milliunits;
    use crate::testkit::conv::{
        DEVICES, HLC_BASE, ID_MS, OPS_PER_DEVICE, amount, budget, expected_tie_value, generate_ops,
        materialized, op, scopes, sequenced, shuffle,
    };
    use crate::testkit::{Rng, v7};

    #[test]
    fn append_assigns_dense_canonical_sequences() {
        let mut log = OpLog::new();
        let (field, value) = amount(1);
        assert_eq!(log.append(op(1, 10, 0, field, value.clone())), Ok(1));
        assert_eq!(log.append(op(2, 20, 0, field, value)), Ok(2));
        assert_eq!(log.tip(), 2);
        assert_eq!(log.scope_id(), Some(ScopeId::Budget(budget())));
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
        assert_eq!(log.append(first.clone()), Ok(1));
        assert_eq!(log.append(first), Ok(1), "a retry is a no-op");
        assert_eq!(log.tip(), 1);
        // The log dedupes by op_id alone — under E2EE a re-encrypted
        // retry carries different payload bytes and must still dedupe
        // (ADR 0017). The loud same-id-different-content check is the
        // client's, exercised below.
        let mut conflict = op(2, 20, 0, amount(0).0, amount(9).1);
        conflict.op_id = OpId::new(v7(ID_MS, 1)).unwrap();
        assert_eq!(log.append(conflict.clone()), Ok(1));
        assert_eq!(log.tip(), 1);
        // Applying the colliding op is loud corruption, not divergence.
        let mut session = SyncSession::new();
        session
            .apply_delta(log.delta_since(0))
            .expect("the stored op is well-formed");
        assert!(matches!(
            session.apply_delta(&[SequencedOp {
                seq: 2,
                op: conflict
            }]),
            Err(ApplyError::OpIdConflict { .. })
        ));
    }

    #[test]
    fn reordered_delivery_does_not_wedge_the_cursor() {
        // Reordered arrival applies immediately but must not move the
        // resume watermark past unprocessed sequences: after seeing only
        // seq 3, a pull since the cursor still serves 1 and 2.
        let mut log = OpLog::new();
        let mut session = SyncSession::new();
        let mut ms = 10;
        let mut push = |i: u64, log: &mut OpLog| {
            ms += 1;
            log.append(op(i, ms, 0, Field::Transaction(TransactionField::Memo), {
                Value::Text(format!("m{i}"))
            }))
            .unwrap()
        };
        assert_eq!(push(1, &mut log), 1);
        assert_eq!(push(2, &mut log), 2);
        assert_eq!(push(3, &mut log), 3);

        // Seq 3 arrives alone (reordered).
        let newest = log.delta_since(2).next().cloned().unwrap();
        let first = session.apply_delta([&newest]).unwrap();
        assert_eq!(first.applied, 1);
        assert_eq!(session.last_seen(), 0, "a gap pins the watermark");
        assert_eq!(session.pending_len(), 1, "the stranded op is visible");

        // Catching up from the cursor re-serves everything: 3 is a
        // duplicate; 1 and 2 are stale — their stamps lost to the newer
        // write already applied — but the watermark still crosses them.
        let catch_up: Vec<SequencedOp> = log.delta_since(session.last_seen()).cloned().collect();
        assert_eq!(catch_up.len(), 3);
        let summary = session.apply_delta(&catch_up).unwrap();
        assert_eq!(summary.applied, 0);
        assert_eq!(summary.stale, 2, "the older memos lose the field");
        assert_eq!(summary.duplicates, 1);
        assert_eq!(session.last_seen(), 3);
        assert_eq!(session.pending_len(), 0, "the gap filled");
        let txn = match session
            .state()
            .entity(&EntityId::new(v7(ID_MS, 50)).unwrap())
        {
            Some(crate::domain::Entity::Transaction(t)) => t.clone(),
            other => panic!("expected transaction, got {other:?}"),
        };
        assert_eq!(txn.memo.as_deref(), Some("m3"));
    }

    #[test]
    fn foreign_scope_append_is_rejected() {
        let mut log = OpLog::new();
        let (field, value) = amount(1);
        let first = op(1, 10, 0, field, value);
        assert_eq!(log.append(first.clone()), Ok(1));
        let mut foreign = op(2, 20, 0, amount(0).0, amount(2).1);
        foreign.scope = ScopeId::Budget(crate::ids::BudgetId::new(v7(9, 9)).unwrap());
        assert!(matches!(
            log.append(foreign.clone()),
            Err(LogError::ScopeMismatch { .. })
        ));
        assert_eq!(log.tip(), 1);
        // Scoping is checked before dedupe: even an op REUSING a seen
        // op_id is rejected when scoped to the wrong log — the scope
        // is metadata, the one thing a real server always sees (ADRs
        // 0008, 0020).
        foreign.op_id = first.op_id;
        assert!(matches!(
            log.append(foreign),
            Err(LogError::ScopeMismatch { .. })
        ));
    }

    #[test]
    fn an_empty_delta_reports_the_current_cursor() {
        let mut session = SyncSession::new();
        let (field, value) = amount(1);
        let delivered = sequenced(1, op(1, 10, 0, field, value));
        session.apply_delta([&delivered]).unwrap();
        let summary = session.apply_delta(Vec::<&SequencedOp>::new()).unwrap();
        assert_eq!(
            summary.last_seen, 1,
            "an idle poll must not reset the cursor"
        );
        assert_eq!(summary.applied + summary.duplicates + summary.stale, 0);
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
        let mut reference: Option<ScopeState> = None;
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
    // per the ADR 0016 convention. The op stream generator and assertions
    // live in `testkit::conv`, shared with the store suite (ADR 0018), and
    // run over both log scopes (ADR 0021): the same theorem for org logs
    // and budget logs.
    // ------------------------------------------------------------------

    const SEEDS: u64 = 25;

    /// Scenario (a): the rendezvous loop — devices push their ops to the
    /// log in a shuffled interleave and pull random-sized deltas, sometimes
    /// re-pulling overlaps (at-least-once delivery), until everyone has
    /// everything. Both scopes (ADR 0021).
    #[test]
    fn n_devices_converge_through_the_rendezvous_loop() {
        for scope in scopes() {
            for seed in 1..=SEEDS {
                let ops = generate_ops(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), scope);
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
                let mut sessions: Vec<SyncSession> =
                    (0..DEVICES).map(|_| SyncSession::new()).collect();

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

                // The forced equal-HLC tie at the winning stamp: every
                // replica's materialized value must be the op_id tie-break's
                // pick — asserted directly, not just via state equality.
                let (tie_entity, tie_field, tie_value) = expected_tie_value(&ops);
                let mut replicas = sessions.iter().map(|s| s.state());
                let first_tie = materialized(
                    replicas.next().expect("at least one session"),
                    tie_entity,
                    tie_field,
                );
                assert_eq!(first_tie, Some(tie_value), "seed {seed}");
                for state in replicas {
                    assert_eq!(
                        materialized(state, tie_entity, tie_field),
                        first_tie,
                        "seed {seed}"
                    );
                }
                assert_eq!(
                    materialized(canonical.state(), tie_entity, tie_field),
                    first_tie,
                    "seed {seed}"
                );
            }
        }
    }

    /// Scenario (b): no log at all — each device receives the full op set
    /// as an independent shuffle with injected duplicates, in random batch
    /// sizes; all must equal the generation-order reference. Both scopes
    /// (ADR 0021).
    #[test]
    fn n_devices_converge_from_shuffled_duplicated_delivery() {
        for scope in scopes() {
            for seed in 1..=SEEDS {
                let ops = generate_ops(seed.wrapping_mul(0xBF58_476D_1CE4_E5B9), scope);
                let (tie_entity, tie_field, tie_value) = expected_tie_value(&ops);
                let mut reference = ScopeState::new();
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
                    assert_eq!(
                        materialized(session.state(), tie_entity, tie_field),
                        Some(tie_value.clone()),
                        "device {device} tie-break (seed {seed})"
                    );
                }
                assert_eq!(
                    materialized(&reference, tie_entity, tie_field),
                    Some(tie_value),
                    "reference tie-break (seed {seed})"
                );
            }
        }
    }
}
