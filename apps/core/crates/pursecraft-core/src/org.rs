//! Organization-level semantics (ADR 0021): projections within one org
//! state, the personal-org provisioning op-set, and the cross-state
//! personal-org invariant.
//!
//! Org entities live in org-scoped logs and converge through the ordinary
//! engine; everything here is a pure projection over [`ScopeState`]s, so
//! it converges with them and never mutates stored state (ADR 0016's
//! discipline). Budget-content resolution stays in [`crate::resolve`].

use crate::domain::{
    Budget, Entity, EntityKind, Field, MembershipField, MembershipRole, OrgField, Organization,
    Value,
};
use crate::hlc::Hlc;
use crate::ids::{DeviceId, EntityId, OpId, OrgId, ScopeId, UserId};
use crate::ops::{Op, ScopeState};

/// The organization entity of `state`'s own org. An org log holds exactly
/// one organization entity — its own, enforced at apply time (ADR 0021) —
/// so this lookup cannot find a stranger's.
pub fn organization(state: &ScopeState) -> Option<&Organization> {
    let org = state.scope_id()?.org()?;
    match state.entity(&EntityId::from_raw(org.as_uuid())) {
        Some(Entity::Organization(organization)) => Some(organization),
        _ => None,
    }
}

/// Whether the org of `state` survives: org deletion hides everything it
/// owns, data stays (ADR 0021's cascade-hide).
pub fn org_alive(state: &ScopeState) -> bool {
    organization(state).is_some_and(|organization| !organization.deleted)
}

/// Whether a budget of this org is visible: it belongs to THIS org (the
/// entity's stored scope is checked against the state's — a caller
/// composing budgets across orgs cannot smuggle a foreign org's budget
/// past this projection), the budget survives, and the org survives
/// (ADR 0021). An org's budget list is the visible ones — offline, from
/// the org log alone.
pub fn budget_visible(state: &ScopeState, budget: &Budget) -> bool {
    state.scope_id() == Some(budget.scope) && !budget.deleted && org_alive(state)
}

/// The org's visible budgets (ADR 0021), in stable `BudgetId` order —
/// entity iteration order is a HashMap's and must never leak into
/// anything a caller can observe.
pub fn visible_budgets(state: &ScopeState) -> Vec<&Budget> {
    let mut budgets: Vec<&Budget> = state
        .entities()
        .filter_map(|entity| match entity {
            Entity::Budget(budget) if budget_visible(state, budget) => Some(budget),
            _ => None,
        })
        .collect();
    budgets.sort_by_key(|budget| budget.id);
    budgets
}

/// The user's role in this org: the earliest-created surviving membership
/// naming them — minimum UUIDv7, ADR 0016's fallback convention. Only
/// role-bearing memberships compete: a torn, role-less write shadows
/// nothing (it contributes no role until one lands on it). A user appears
/// at most once per org in well-formed data; racing twins resolve
/// deterministically on every device (ADR 0021).
pub fn membership_role(state: &ScopeState, user: UserId) -> Option<MembershipRole> {
    state
        .entities()
        .filter_map(|entity| match entity {
            Entity::Membership(membership)
                if !membership.deleted && membership.user_id == Some(user) =>
            {
                membership.role.map(|role| (membership.id, role))
            }
            _ => None,
        })
        .min_by_key(|(id, _)| *id)
        .map(|(_, role)| role)
}

/// A user's access to one budget of this org: their membership role, iff
/// the budget belongs to this org and both survive (ADR 0021). Different
/// orgs give different roles through different memberships; roles are
/// data, and enforcing them is the auth slice's job.
pub fn budget_access(state: &ScopeState, user: UserId, budget: &Budget) -> Option<MembershipRole> {
    budget_visible(state, budget)
        .then(|| membership_role(state, user))
        .flatten()
}

/// The ids a personal-org provisioning writes (ADR 0021): the org, the
/// owner-membership entity, and the user the org is personal for. The
/// caller mints all three (capture is a later slice, ADR 0016).
#[derive(Clone, Copy, Debug)]
pub struct PersonalOrgIds {
    pub user: UserId,
    pub org: OrgId,
    pub membership: EntityId,
}

/// The creation stamp every provisioning op carries (ADR 0021): the org
/// id's own UUIDv7 millisecond, logical zero. Anchoring here is the merge
/// guard — any device that has ever seen this org received a stamp this
/// dominates (HLC receive, ADR 0007), so every edit such a device later
/// writes outranks provisioning at merge, whatever the provisioning
/// device's clock knew. A stale or empty device therefore cannot clobber
/// a user edit or re-escalate a role, structurally; provisioning can only
/// land fields no device ever wrote. (A never-synced writer with a clock
/// behind the org's mint is outside the protocol — the ADR 0017 skew
/// posture.)
fn org_creation_stamp(org: OrgId) -> Hlc {
    // RFC 9562: a UUIDv7's top 48 bits are its unix-milliseconds field —
    // exactly what the id's minter encoded. (0 only if the bits carry
    // nothing, which a validated v7 id never does; it is the fail-safe
    // bottom of the stamp order anyway.)
    let ms = (org.as_uuid().as_u128() >> 80) as u64;
    Hlc {
        physical_ms: ms,
        logical: 0,
    }
}

/// The personal-org provisioning op-set (ADR 0021): the organization —
/// named, marked personal for `user` — plus the creator's owner
/// membership. Two barriers make retrying safe, because the retrying
/// device may be empty or stale (that is why retries exist):
///
/// 1. **Read-then-mint (capture's contract):** the caller probes the
///    current org-log state — sync first — and this function emits an op
///    only where that state holds no value for its field, completing a
///    partially-applied attempt and emitting nothing for a satisfied one.
/// 2. **Anchored stamps (the core's structural guard):** every emitted op
///    carries the org id's own mint millisecond (see the private
///    `org_creation_stamp`) — not the provisioning device's clock, so on
///    merge these ops lose to every field any legitimate editor ever
///    wrote. A contract-violating stale retry still cannot revert a
///    rename or re-escalate a demotion.
///
/// `mint_op_id` supplies op ids for whatever is missing. `state` is
/// probed only when fixed to this org — otherwise every op is emitted,
/// and a genuinely foreign state rejects them loudly at apply.
pub fn provision_personal_org(
    state: &ScopeState,
    ids: PersonalOrgIds,
    name: &str,
    device_id: DeviceId,
    mut mint_op_id: impl FnMut() -> OpId,
) -> Vec<Op> {
    let PersonalOrgIds {
        user,
        org,
        membership,
    } = ids;
    let scope = ScopeId::Org(org);
    let org_entity = EntityId::from_raw(org.as_uuid());
    let hlc = org_creation_stamp(org);
    let probing = state.scope_id() == Some(scope);
    let present = |id: EntityId, field: Field| match (state.entity(&id), field) {
        (Some(Entity::Organization(o)), Field::Organization(OrgField::Name)) => o.name.is_some(),
        (Some(Entity::Organization(o)), Field::Organization(OrgField::PersonalFor)) => {
            o.personal_for.is_some()
        }
        (Some(Entity::Membership(m)), Field::Membership(MembershipField::UserId)) => {
            m.user_id.is_some()
        }
        (Some(Entity::Membership(m)), Field::Membership(MembershipField::Role)) => m.role.is_some(),
        _ => false,
    };
    let writes = [
        (
            EntityKind::Organization,
            org_entity,
            Field::Organization(OrgField::Name),
            Value::Text(name.to_owned()),
        ),
        (
            EntityKind::Organization,
            org_entity,
            Field::Organization(OrgField::PersonalFor),
            Value::User(user),
        ),
        (
            EntityKind::Membership,
            membership,
            Field::Membership(MembershipField::UserId),
            Value::User(user),
        ),
        (
            EntityKind::Membership,
            membership,
            Field::Membership(MembershipField::Role),
            Value::Role(MembershipRole::Owner),
        ),
    ];
    writes
        .into_iter()
        .filter(|&(_, id, field, _)| !(probing && present(id, field)))
        .map(|(entity_kind, entity_id, field, value)| Op {
            op_id: mint_op_id(),
            scope,
            device_id,
            user_id: user,
            entity_kind,
            entity_id,
            field,
            value,
            hlc,
        })
        .collect()
}

/// The live orgs claiming to be `user`'s personal org, across every org
/// state the caller holds (ADR 0021) — deduplicated, because passing the
/// same state twice is a legal call, not a violation. The provisioning
/// invariant holds iff the result has exactly one element: a user's state
/// always includes a personal org, and provisioning never duplicates one.
/// Budget-scoped states contribute nothing — they hold no organization
/// entity.
pub fn live_personal_orgs<'a, I>(states: I, user: UserId) -> Vec<OrgId>
where
    I: IntoIterator<Item = &'a ScopeState>,
{
    let mut orgs: Vec<OrgId> = states
        .into_iter()
        .filter_map(|state| {
            let organization = organization(state)?;
            (!organization.deleted && organization.personal_for == Some(user))
                .then_some(organization.id)
        })
        .collect();
    orgs.sort();
    orgs.dedup();
    orgs
}

/// The personal-org invariant's second clause (ADR 0021): the creator's
/// OWNER membership survives — their resolved role in their own org is
/// Owner, exactly what [`membership_role`] (and therefore
/// [`budget_access`]) resolves, so the checker can never disagree with
/// access. Removal, a role-less twin, a squatted membership id, or a
/// demotion — anything that leaves the creator without Owner — is a
/// visible violation; the log stays faithful. Roles among OTHER members
/// are data.
pub fn owner_membership_intact(state: &ScopeState, user: UserId) -> bool {
    membership_role(state, user) == Some(MembershipRole::Owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::MembershipRole as Role;
    use crate::ids::BudgetId;
    use crate::ops::Applied;
    use crate::testkit::conv::shuffle;
    use crate::testkit::{Rng, v7};
    use uuid::Uuid;

    const MS: u64 = 1 << 40;

    /// Org-scoped test harness: fixes one org as its scope, then applies
    /// writes at increasing HLCs — resolve.rs's Fixture, org-shaped.
    struct OrgFx {
        state: ScopeState,
        org_rand: u64,
        ms: u64,
        ops: u64,
    }

    impl OrgFx {
        fn new(org_rand: u64) -> Self {
            let mut fx = Self {
                state: ScopeState::new(),
                org_rand,
                ms: 0,
                ops: 0,
            };
            fx.write(
                EntityKind::Organization,
                org_rand,
                Field::Organization(OrgField::Name),
                Value::Text("org".into()),
            );
            fx
        }

        fn scope(&self) -> ScopeId {
            ScopeId::Org(OrgId::new(v7(MS, self.org_rand)).unwrap())
        }

        fn write(
            &mut self,
            kind: EntityKind,
            entity_rand: u64,
            field: Field,
            value: Value,
        ) -> &mut Self {
            self.ms += 1;
            self.ops += 1;
            let op = Op {
                op_id: OpId::new(v7(MS + self.ops, self.ops)).unwrap(),
                scope: self.scope(),
                device_id: DeviceId::new(Uuid::nil()).unwrap(),
                user_id: UserId::new(Uuid::nil()).unwrap(),
                entity_kind: kind,
                entity_id: EntityId::new(v7(MS, entity_rand)).unwrap(),
                field,
                value,
                hlc: Hlc {
                    physical_ms: self.ms,
                    logical: 0,
                },
            };
            assert_eq!(self.state.apply(op), Ok(Applied::Applied));
            self
        }

        fn member(&mut self, member_rand: u64, user: UserId, role: Role) -> &mut Self {
            self.write(
                EntityKind::Membership,
                member_rand,
                Field::Membership(MembershipField::UserId),
                Value::User(user),
            )
            .write(
                EntityKind::Membership,
                member_rand,
                Field::Membership(MembershipField::Role),
                Value::Role(role),
            )
        }

        fn budget(&mut self, budget_rand: u64, name: &str) -> &mut Self {
            self.write(
                EntityKind::Budget,
                budget_rand,
                Field::Budget(crate::domain::BudgetField::Name),
                Value::Text(name.into()),
            )
        }

        fn delete_org(&mut self) -> &mut Self {
            self.write(
                EntityKind::Organization,
                self.org_rand,
                Field::Deleted,
                Value::Bool(true),
            )
        }

        fn budget_entity(&self, budget_rand: u64) -> Budget {
            match self
                .state
                .entity(&EntityId::new(v7(MS, budget_rand)).unwrap())
            {
                Some(Entity::Budget(b)) => b.clone(),
                other => panic!("expected budget, got {other:?}"),
            }
        }
    }

    fn user(rand: u64) -> UserId {
        UserId::new(v7(MS, rand)).unwrap()
    }

    fn hlc_at(ms: u64) -> Hlc {
        Hlc {
            physical_ms: ms,
            logical: 0,
        }
    }

    /// A pen for manual org-scope writes outside any harness: holds the
    /// target state, scope, and actor, and mints unique op ids.
    struct OrgPen<'a> {
        state: &'a mut ScopeState,
        scope: ScopeId,
        actor: UserId,
        n: u64,
    }

    impl OrgPen<'_> {
        fn write(&mut self, ms: u64, kind: EntityKind, id: EntityId, field: Field, value: Value) {
            self.n += 1;
            self.state
                .apply(Op {
                    op_id: OpId::new(v7(MS + 500 + self.n, 500 + self.n)).unwrap(),
                    scope: self.scope,
                    device_id: DeviceId::new(Uuid::nil()).unwrap(),
                    user_id: self.actor,
                    entity_kind: kind,
                    entity_id: id,
                    field,
                    value,
                    hlc: hlc_at(ms),
                })
                .expect("manual write is well-formed");
        }
    }

    /// Provisioning invariant (ADR 0021): provisioning yields exactly one
    /// live personal org with the creator as owner — and NEVER clobbers
    /// user edits, whatever stamps a retry carries. The hostile case: the
    /// user renames their org and demotes themselves, then a crash-retry
    /// re-provisions with fresh op ids AND a fresh (later) stamp — the
    /// retry must emit nothing, so no edit reverts and no demotion
    /// re-escalates.
    #[test]
    fn personal_org_provisioning_never_clobbers_user_edits() {
        let terence = user(500);
        let org = OrgId::new(v7(MS, 41)).unwrap();
        let membership = EntityId::new(v7(MS, 42)).unwrap();
        let device = DeviceId::new(Uuid::nil()).unwrap();
        let scope = ScopeId::Org(org);
        let org_entity = EntityId::from_raw(org.as_uuid());

        // A virgin state provisions in full: four ops.
        let mut counter = 0u64;
        let ops = provision_personal_org(
            &ScopeState::new(),
            PersonalOrgIds {
                user: terence,
                org,
                membership,
            },
            "Terence's org",
            device,
            || {
                counter += 1;
                OpId::new(v7(MS + counter, counter)).unwrap()
            },
        );
        assert_eq!(ops.len(), 4);
        let mut state = ScopeState::new();
        for op in &ops {
            assert_eq!(state.apply(op.clone()), Ok(Applied::Applied));
        }
        // The invariant: exactly one live personal org, creator is owner,
        // the owner membership is intact.
        assert_eq!(live_personal_orgs([&state], terence), vec![org]);
        assert_eq!(membership_role(&state, terence), Some(Role::Owner));
        assert!(owner_membership_intact(&state, terence));
        assert_eq!(
            organization(&state).unwrap().name.as_deref(),
            Some("Terence's org")
        );

        // THE REPRO: the user renames the org and demotes themselves at
        // T+50.
        let mut pen = OrgPen {
            state: &mut state,
            scope,
            actor: terence,
            n: 0,
        };
        pen.write(
            MS + 50,
            EntityKind::Organization,
            org_entity,
            Field::Organization(OrgField::Name),
            Value::Text("Home".into()),
        );
        pen.write(
            MS + 50,
            EntityKind::Membership,
            membership,
            Field::Membership(MembershipField::Role),
            Value::Role(Role::Viewer),
        );
        assert_eq!(organization(&state).unwrap().name.as_deref(), Some("Home"));
        assert_eq!(membership_role(&state, terence), Some(Role::Viewer));

        // The crash-retry: fresh op ids, fresh stamp T+60 — every field is
        // present, so the probe emits NOTHING; applying it changes
        // nothing. No silent privilege re-escalation, no lost edit.
        let mut counter2 = 100u64;
        let retry = provision_personal_org(
            &state,
            PersonalOrgIds {
                user: terence,
                org,
                membership,
            },
            "Terence's org",
            device,
            || {
                counter2 += 1;
                OpId::new(v7(MS + counter2, counter2)).unwrap()
            },
        );
        assert!(
            retry.is_empty(),
            "a satisfied provisioning emits nothing, got {retry:?}"
        );
        for op in &retry {
            state.apply(op.clone()).unwrap();
        }
        assert_eq!(organization(&state).unwrap().name.as_deref(), Some("Home"));
        assert_eq!(membership_role(&state, terence), Some(Role::Viewer));
        assert_eq!(live_personal_orgs([&state], terence), vec![org]);
        // The self-demotion is itself a flagged state under the owner
        // clause (the creator lost Owner in their own org) — that is the
        // checker REPORTING policy, which is exactly what must NOT be
        // silently "repaired" by a retry.
        assert!(!owner_membership_intact(&state, terence));

        // The same-stamp, same-op-id replay of the ORIGINAL set is still
        // the engine's duplicate no-op (ADR 0007) — the probe and the
        // dedupe agree.
        for op in &ops {
            assert_eq!(state.apply(op.clone()), Ok(Applied::Duplicate));
        }
        assert_eq!(organization(&state).unwrap().name.as_deref(), Some("Home"));

        // A partially-applied first attempt is completed, without touching
        // fields a user already wrote: partner's org lands only its two
        // org-entity ops, partner renames it, and the retry must supply
        // exactly the two membership ops — never reverting the rename.
        let partner = user(501);
        let org2 = OrgId::new(v7(MS, 44)).unwrap();
        let membership2 = EntityId::new(v7(MS, 45)).unwrap();
        let mut counter3 = 200u64;
        let first = provision_personal_org(
            &ScopeState::new(),
            PersonalOrgIds {
                user: partner,
                org: org2,
                membership: membership2,
            },
            "Second",
            device,
            || {
                counter3 += 1;
                OpId::new(v7(MS + counter3, counter3)).unwrap()
            },
        );
        let mut partial = ScopeState::new();
        for op in &first[..2] {
            partial.apply(op.clone()).unwrap();
        }
        OrgPen {
            state: &mut partial,
            scope: ScopeId::Org(org2),
            actor: partner,
            n: 0,
        }
        .write(
            MS + 50,
            EntityKind::Organization,
            EntityId::from_raw(org2.as_uuid()),
            Field::Organization(OrgField::Name),
            Value::Text("Renamed".into()),
        );
        let mut counter4 = 300u64;
        let completion = provision_personal_org(
            &partial,
            PersonalOrgIds {
                user: partner,
                org: org2,
                membership: membership2,
            },
            "Second",
            device,
            || {
                counter4 += 1;
                OpId::new(v7(MS + counter4, counter4)).unwrap()
            },
        );
        assert_eq!(completion.len(), 2, "only the membership ops are missing");
        for op in &completion {
            partial.apply(op.clone()).unwrap();
        }
        assert_eq!(
            organization(&partial).unwrap().name.as_deref(),
            Some("Renamed"),
            "the retry must not revert the user's rename"
        );
        assert_eq!(organization(&partial).unwrap().personal_for, Some(partner));
        assert_eq!(membership_role(&partial, partner), Some(Role::Owner));
        assert_eq!(live_personal_orgs([&partial], partner), vec![org2]);

        // A second org claiming to be Terence's personal org is a visible
        // invariant violation — the checker reports it; it never merges.
        let mut imposter = OrgFx::new(43);
        imposter.write(
            EntityKind::Organization,
            43,
            Field::Organization(OrgField::PersonalFor),
            Value::User(terence),
        );
        let claimed = live_personal_orgs([&state, &imposter.state], terence);
        assert_eq!(claimed.len(), 2, "the checker sees both claimants");

        // Passing the same state twice is a legal call, not a violation.
        assert_eq!(
            live_personal_orgs([&state, &state, &imposter.state], terence).len(),
            2,
            "input duplication must not manufacture claimants"
        );

        // A deleted personal org is equally visible: the invariant demands
        // exactly one LIVE org, so a hostile or buggy tombstone leaves the
        // user org-less and the checker says so (ADR 0021 — the log stays
        // faithful; the policy is enforced at capture).
        let mut deleted = imposter;
        deleted.write(
            EntityKind::Organization,
            43,
            Field::Deleted,
            Value::Bool(true),
        );
        assert_eq!(
            live_personal_orgs([&state, &deleted.state], terence),
            vec![org],
            "the dead claimant drops out; the real one remains"
        );
        let mut mutinied = state;
        mutinied
            .apply(Op {
                op_id: OpId::new(v7(MS + 900, 900)).unwrap(),
                scope: ScopeId::Org(org),
                device_id: DeviceId::new(Uuid::nil()).unwrap(),
                user_id: terence,
                entity_kind: EntityKind::Organization,
                entity_id: EntityId::from_raw(org.as_uuid()),
                field: Field::Deleted,
                value: Value::Bool(true),
                hlc: hlc_at(MS + 2),
            })
            .unwrap();
        assert_eq!(
            live_personal_orgs([&mutinied], terence),
            Vec::<OrgId>::new(),
            "no live personal org — the violation is the checker's output"
        );
    }

    /// The stale/empty-device path (ADR 0021): a device that never saw
    /// the org provisions with a fresh clock — read-then-mint cannot help
    /// it (its state is empty), so the ANCHORED STAMPS must: its ops lose
    /// on merge to every field the up-to-date world already wrote. The
    /// repro from review: device A provisions, the user renames and
    /// self-demotes; device B, empty, re-provisions; merging B into A
    /// must not revert the rename or re-escalate the role — in either
    /// merge order.
    #[test]
    fn stale_device_provisioning_cannot_clobber_on_merge() {
        let terence = user(500);
        let org = OrgId::new(v7(MS, 41)).unwrap();
        let membership = EntityId::new(v7(MS, 42)).unwrap();
        let device_a = DeviceId::new(Uuid::nil()).unwrap();
        let device_b = DeviceId::new(Uuid::max()).unwrap();
        let scope = ScopeId::Org(org);
        let org_entity = EntityId::from_raw(org.as_uuid());

        // Device A: virgin provisioning, then the user's own edits at
        // T+50 (rename + self-demotion).
        let mut counter = 0u64;
        let a_ops = provision_personal_org(
            &ScopeState::new(),
            PersonalOrgIds {
                user: terence,
                org,
                membership,
            },
            "Terence's org",
            device_a,
            || {
                counter += 1;
                OpId::new(v7(MS + counter, counter)).unwrap()
            },
        );
        // Provisioning ops are stamped at the org's mint time (MS), not
        // the minter's clock — the anchored-stamp guard itself.
        assert!(
            a_ops.iter().all(|op| op.hlc.physical_ms == MS),
            "provisioning stamps anchor at the org id's UUIDv7 ms"
        );
        let mut edits = vec![];
        for (kind, id, field, value) in [
            (
                EntityKind::Organization,
                org_entity,
                Field::Organization(OrgField::Name),
                Value::Text("Home".into()),
            ),
            (
                EntityKind::Membership,
                membership,
                Field::Membership(MembershipField::Role),
                Value::Role(Role::Viewer),
            ),
        ] {
            let n = edits.len() as u64;
            edits.push(Op {
                op_id: OpId::new(v7(MS + 50 + n, 50 + n)).unwrap(),
                scope,
                device_id: device_a,
                user_id: terence,
                entity_kind: kind,
                entity_id: id,
                field,
                value,
                hlc: hlc_at(MS + 50),
            });
        }

        // Device B: NEVER saw any of it — its state is empty, so the
        // probe passes everything through, and its fresh clock (T+60)
        // would win a blind LWW race. The anchored stamps must not.
        let mut counter_b = 100u64;
        let b_ops = provision_personal_org(
            &ScopeState::new(),
            PersonalOrgIds {
                user: terence,
                org,
                membership,
            },
            "Terence's org",
            device_b,
            || {
                counter_b += 1;
                OpId::new(v7(MS + counter_b, counter_b)).unwrap()
            },
        );
        assert_eq!(b_ops.len(), 4, "an empty state provisions in full");
        assert!(b_ops.iter().all(|op| op.hlc.physical_ms == MS));

        // Merge B into A, and A into B — both orders, same outcome: the
        // user's edits survive, the demotion is not re-escalated.
        for order in [
            (true, "B's stale provisioning applied onto A's state"),
            (false, "A's ops applied onto B's provisioning-first state"),
        ] {
            let (b_onto_a, label) = order;
            let mut merged = ScopeState::new();
            let first: Vec<Op> = if b_onto_a {
                b_ops.clone()
            } else {
                a_ops.clone().into_iter().chain(edits.clone()).collect()
            };
            let second: Vec<Op> = if b_onto_a {
                a_ops.clone().into_iter().chain(edits.clone()).collect()
            } else {
                b_ops.clone()
            };
            for op in first.iter().chain(&second) {
                merged.apply(op.clone()).expect("well-formed ops");
            }
            assert_eq!(
                organization(&merged).unwrap().name.as_deref(),
                Some("Home"),
                "the rename survives the merge ({label})"
            );
            assert_eq!(
                membership_role(&merged, terence),
                Some(Role::Viewer),
                "no privilege re-escalation through the merge ({label})"
            );
            assert_eq!(live_personal_orgs([&merged], terence), vec![org]);
        }
    }

    /// The invariant's second clause (ADR 0021): the checker verifies the
    /// CREATOR'S OWNER membership — the resolved role, so it can never
    /// disagree with access. Repro A: removal plus a role-less twin
    /// naming the creator must flag (the checker must not be satisfied by
    /// any live membership). Repro B: an attacker squats the membership
    /// id provisioning will use — the creator ends up role-less while
    /// the attacker is Owner, and the checker must flag that too.
    #[test]
    fn removed_owner_membership_is_flagged() {
        let terence = user(500);
        let org = OrgId::new(v7(MS, 46)).unwrap();
        let membership = EntityId::new(v7(MS, 47)).unwrap();
        let device = DeviceId::new(Uuid::nil()).unwrap();
        let mut counter = 0u64;
        let ops = provision_personal_org(
            &ScopeState::new(),
            PersonalOrgIds {
                user: terence,
                org,
                membership,
            },
            "Home",
            device,
            || {
                counter += 1;
                OpId::new(v7(MS + counter, counter)).unwrap()
            },
        );
        let mut state = ScopeState::new();
        for op in ops {
            state.apply(op).unwrap();
        }
        assert_eq!(live_personal_orgs([&state], terence), vec![org]);
        assert!(owner_membership_intact(&state, terence));
        assert_eq!(membership_role(&state, terence), Some(Role::Owner));

        // Repro A: the owner membership is tombstoned and a role-less
        // twin naming the creator takes its place — "any live membership"
        // would be satisfied; the CREATOR'S OWNER membership is not.
        OrgPen {
            state: &mut state,
            scope: ScopeId::Org(org),
            actor: terence,
            n: 0,
        }
        .write(
            MS + 10,
            EntityKind::Membership,
            membership,
            Field::Deleted,
            Value::Bool(true),
        );
        let mut twin = state.clone();
        OrgPen {
            state: &mut twin,
            scope: ScopeId::Org(org),
            actor: terence,
            n: 10,
        }
        .write(
            MS + 11,
            EntityKind::Membership,
            EntityId::new(v7(MS, 45)).unwrap(), // lower id than `membership`: the earliest survivor if it counted
            Field::Membership(MembershipField::UserId),
            Value::User(terence),
        );
        assert!(
            !owner_membership_intact(&twin, terence),
            "repro A: the role-less twin must not satisfy the clause"
        );
        assert_eq!(membership_role(&twin, terence), None);
        assert_eq!(
            live_personal_orgs([&twin], terence),
            vec![org],
            "the org clause still holds — the two clauses are independent"
        );

        // Repro B: an attacker pre-writes the membership id provisioning
        // will use, naming themselves Owner. The probe skips the occupied
        // fields, the creator ends up role-less, and the checker flags
        // the creator's loss (policing the attacker is the auth slice's).
        let victim_org = OrgId::new(v7(MS, 56)).unwrap();
        let victim_membership = EntityId::new(v7(MS, 57)).unwrap();
        let attacker = user(502);
        let mut squatted = ScopeState::new();
        {
            let mut pen = OrgPen {
                state: &mut squatted,
                scope: ScopeId::Org(victim_org),
                actor: attacker,
                n: 0,
            };
            pen.write(
                MS + 1,
                EntityKind::Organization,
                EntityId::from_raw(victim_org.as_uuid()),
                Field::Organization(OrgField::Name),
                Value::Text("Stolen".into()),
            );
            pen.write(
                MS + 2,
                EntityKind::Membership,
                victim_membership,
                Field::Membership(MembershipField::UserId),
                Value::User(attacker),
            );
            pen.write(
                MS + 3,
                EntityKind::Membership,
                victim_membership,
                Field::Membership(MembershipField::Role),
                Value::Role(Role::Owner),
            );
        }
        let mut counter2 = 200u64;
        let squatter_ops = provision_personal_org(
            &squatted,
            PersonalOrgIds {
                user: terence,
                org: victim_org,
                membership: victim_membership,
            },
            "Terence's org",
            device,
            || {
                counter2 += 1;
                OpId::new(v7(MS + counter2, counter2)).unwrap()
            },
        );
        assert_eq!(
            squatter_ops.len(),
            1,
            "the probe skips the squatted fields: only personal_for is missing"
        );
        for op in &squatter_ops {
            squatted.apply(op.clone()).unwrap();
        }
        assert_eq!(
            membership_role(&squatted, terence),
            None,
            "repro B: the creator is role-less in their own org"
        );
        assert_eq!(membership_role(&squatted, attacker), Some(Role::Owner));
        assert!(
            !owner_membership_intact(&squatted, terence),
            "repro B: the creator's loss is flagged"
        );
        assert_eq!(
            live_personal_orgs([&squatted], terence),
            vec![victim_org],
            "the org clause holds — personal_for is the creator's"
        );
    }

    /// Role semantics as data (ADR 0021): one user, two orgs, different
    /// roles — the requirement, resolved from memberships alone.
    #[test]
    fn roles_differ_across_orgs() {
        let terence = user(500);
        let mut household = OrgFx::new(50); // Terence owns this one
        household.member(52, terence, Role::Owner);
        household.budget(53, "Household");
        let mut work = OrgFx::new(61); // he only views this one
        work.member(62, terence, Role::Viewer);
        work.budget(63, "Team budget");

        assert_eq!(
            budget_access(&household.state, terence, &household.budget_entity(53)),
            Some(Role::Owner)
        );
        assert_eq!(
            budget_access(&work.state, terence, &work.budget_entity(63)),
            Some(Role::Viewer)
        );
        // A stranger has no role anywhere, whoever else is a member.
        assert_eq!(membership_role(&household.state, user(999)), None);

        // A torn, role-less membership with a LOWER id than the complete
        // one shadows nothing: only role-bearing memberships compete, so
        // the earliest complete one wins (ADR 0021).
        household.write(
            EntityKind::Membership,
            51, // lower id than 52 — a racing twin that never got its role
            Field::Membership(MembershipField::UserId),
            Value::User(terence),
        );
        assert_eq!(
            membership_role(&household.state, terence),
            Some(Role::Owner),
            "a role-less twin must not blank the user's role"
        );
        household.write(
            EntityKind::Membership,
            51,
            Field::Membership(MembershipField::Role),
            Value::Role(Role::Viewer),
        );
        // Now the twin is complete and earliest — it wins, deterministically.
        assert_eq!(
            membership_role(&household.state, terence),
            Some(Role::Viewer)
        );
    }

    /// The budget list is in stable `BudgetId` order, and a budget whose
    /// stored scope is another org's is never visible or accessible
    /// through this org's projections (ADR 0021) — cross-org composition
    /// cannot smuggle a foreign budget past them.
    #[test]
    fn budget_list_order_is_stable_and_foreign_scope_budgets_resolve_nothing() {
        let terence = user(500);
        let mut a = OrgFx::new(81);
        a.member(82, terence, Role::Owner);
        // Created in descending id order; the list must come back ascending.
        a.budget(86, "third");
        a.budget(84, "first");
        a.budget(85, "second");
        let listed: Vec<BudgetId> = visible_budgets(&a.state)
            .iter()
            .map(|budget| BudgetId::from_raw(budget.id.as_uuid()))
            .collect();
        assert_eq!(
            listed,
            [
                BudgetId::new(v7(MS, 84)).unwrap(),
                BudgetId::new(v7(MS, 85)).unwrap(),
                BudgetId::new(v7(MS, 86)).unwrap(),
            ],
            "stable ascending BudgetId order, whatever the HashMap gave"
        );

        // A foreign org's budget entity value — same everything, wrong
        // scope. Not visible, no access, though Terence owns org A and A
        // is alive: the stored scope is checked against the state's.
        let mut b = OrgFx::new(91);
        b.member(92, terence, Role::Viewer);
        b.budget(93, "B budget");
        let foreign = b.budget_entity(93);
        assert_eq!(foreign.scope, ScopeId::Org(OrgId::new(v7(MS, 91)).unwrap()));
        assert!(!budget_visible(&a.state, &foreign));
        assert_eq!(budget_access(&a.state, terence, &foreign), None);
        // The own-org budget still resolves.
        assert!(budget_visible(&a.state, &a.budget_entity(84)));
        assert_eq!(
            budget_access(&a.state, terence, &a.budget_entity(84)),
            Some(Role::Owner)
        );
    }

    /// Cross-org isolation (ADR 0021, the P1 class): an op or entity from
    /// one org never influences another's resolution.
    #[test]
    fn cross_org_ops_never_influence_another_orgs_resolution() {
        let terence = user(500);
        let mut a = OrgFx::new(71);
        a.member(72, terence, Role::Editor);
        a.budget(73, "A budget");
        let mut b = OrgFx::new(81);
        b.member(82, terence, Role::Viewer);
        b.budget(83, "B budget");
        let a_before = a.state.clone();

        // B's ops are foreign to A's state and log — loudly.
        let b_op = Op {
            op_id: OpId::new(v7(MS + 900, 900)).unwrap(),
            scope: b.scope(),
            device_id: DeviceId::new(Uuid::nil()).unwrap(),
            user_id: terence,
            entity_kind: EntityKind::Budget,
            entity_id: EntityId::new(v7(MS, 83)).unwrap(),
            field: Field::Budget(crate::domain::BudgetField::Name),
            value: Value::Text("hijack".into()),
            hlc: Hlc {
                physical_ms: u64::MAX / 2,
                logical: 0,
            },
        };
        assert!(matches!(
            a.state.apply(b_op.clone()),
            Err(crate::ops::ApplyError::ScopeMismatch { .. })
        ));
        let mut log = crate::sync::OpLog::new();
        log.append(b_op).expect("B's log accepts B's op");
        // A's resolution is untouched: same budgets, same role.
        assert_eq!(a.state, a_before);
        assert_eq!(
            budget_access(&a.state, terence, &a.budget_entity(73)),
            Some(Role::Editor)
        );
        let a_budgets: Vec<&str> = visible_budgets(&a.state)
            .iter()
            .filter_map(|budget| budget.name.as_deref())
            .collect();
        assert_eq!(a_budgets, ["A budget"], "B's budget never lists in A");

        // The same user's memberships resolve independently per org.
        assert_eq!(membership_role(&a.state, terence), Some(Role::Editor));
        assert_eq!(membership_role(&b.state, terence), Some(Role::Viewer));

        // And the invariant checker reads across both without mixing them.
        assert_eq!(
            live_personal_orgs([&a.state, &b.state], terence),
            Vec::new()
        );
    }

    /// Referential behavior (ADR 0021): org deletion hides its budgets
    /// (cascade-hide, data stays), budget deletion hides one budget,
    /// membership removal drops that user's access only.
    #[test]
    fn org_deletion_cascades_and_membership_removal_is_scoped() {
        let terence = user(500);
        let partner = user(501);
        let mut fx = OrgFx::new(91);
        fx.member(92, terence, Role::Owner);
        fx.member(93, partner, Role::Editor);
        fx.budget(94, "Home");

        assert!(budget_visible(&fx.state, &fx.budget_entity(94)));
        assert_eq!(
            budget_access(&fx.state, partner, &fx.budget_entity(94)),
            Some(Role::Editor)
        );

        // Membership removal: partner loses access; Terence keeps his.
        fx.write(
            EntityKind::Membership,
            93,
            Field::Deleted,
            Value::Bool(true),
        );
        assert_eq!(
            budget_access(&fx.state, partner, &fx.budget_entity(94)),
            None
        );
        assert_eq!(
            budget_access(&fx.state, terence, &fx.budget_entity(94)),
            Some(Role::Owner)
        );

        // Budget deletion hides one budget, org alive. (Resolution takes
        // the entity by value — always read it fresh from the state.)
        fx.write(EntityKind::Budget, 94, Field::Deleted, Value::Bool(true));
        assert!(!budget_visible(&fx.state, &fx.budget_entity(94)));
        assert_eq!(visible_budgets(&fx.state).len(), 0);

        // Resurrection works — deletes are just fields (ADR 0016).
        fx.write(EntityKind::Budget, 94, Field::Deleted, Value::Bool(false));
        assert!(budget_visible(&fx.state, &fx.budget_entity(94)));

        // Org deletion cascades over every budget and membership — the
        // data stays, projections skip it.
        fx.delete_org();
        assert!(!org_alive(&fx.state));
        assert!(!budget_visible(&fx.state, &fx.budget_entity(94)));
        assert_eq!(visible_budgets(&fx.state).len(), 0);
        assert_eq!(
            budget_access(&fx.state, terence, &fx.budget_entity(94)),
            None
        );
    }

    /// Determinism (ADR 0021): concurrent membership and org edits resolve
    /// identically under every delivery order — the same theorem the
    /// convergence loops prove, asserted on the org projections.
    #[test]
    fn concurrent_membership_and_org_edits_resolve_deterministically() {
        let terence = user(500);
        let partner = user(501);
        let org_rand = 95u64;
        let scope = ScopeId::Org(OrgId::new(v7(MS, org_rand)).unwrap());
        let base_ms = 10u64;

        // The racing op set: partner's role fought over (Editor vs Viewer
        // at different stamps), a membership tombstone and resurrection,
        // an org tombstone and resurrection, budgets around it.
        let mut ops: Vec<Op> = Vec::new();
        let mut push =
            |i: u64, kind: EntityKind, entity_rand: u64, field: Field, value: Value, ms: u64| {
                ops.push(Op {
                    op_id: OpId::new(v7(MS + i, i)).unwrap(),
                    scope,
                    device_id: DeviceId::new(Uuid::nil()).unwrap(),
                    user_id: terence,
                    entity_kind: kind,
                    entity_id: EntityId::new(v7(MS, entity_rand)).unwrap(),
                    field,
                    value,
                    hlc: Hlc {
                        physical_ms: base_ms + ms,
                        logical: 0,
                    },
                });
            };
        push(
            1,
            EntityKind::Organization,
            org_rand,
            Field::Organization(OrgField::Name),
            Value::Text("Household".into()),
            1,
        );
        push(
            2,
            EntityKind::Organization,
            org_rand,
            Field::Organization(OrgField::PersonalFor),
            Value::User(terence),
            2,
        );
        push(
            3,
            EntityKind::Membership,
            96,
            Field::Membership(MembershipField::UserId),
            Value::User(terence),
            3,
        );
        push(
            4,
            EntityKind::Membership,
            96,
            Field::Membership(MembershipField::Role),
            Value::Role(Role::Owner),
            4,
        );
        push(
            5,
            EntityKind::Membership,
            97,
            Field::Membership(MembershipField::UserId),
            Value::User(partner),
            5,
        );
        push(
            6,
            EntityKind::Membership,
            97,
            Field::Membership(MembershipField::Role),
            Value::Role(Role::Editor),
            6,
        );
        push(
            7,
            EntityKind::Membership,
            97,
            Field::Membership(MembershipField::Role),
            Value::Role(Role::Viewer),
            7,
        ); // the race: later stamp wins
        push(
            8,
            EntityKind::Membership,
            97,
            Field::Deleted,
            Value::Bool(true),
            8,
        ); // removed…
        push(
            9,
            EntityKind::Membership,
            97,
            Field::Deleted,
            Value::Bool(false),
            9,
        ); // …re-added
        push(
            10,
            EntityKind::Budget,
            98,
            Field::Budget(crate::domain::BudgetField::Name),
            Value::Text("Home".into()),
            10,
        );
        push(
            11,
            EntityKind::Organization,
            org_rand,
            Field::Deleted,
            Value::Bool(false),
            11,
        );

        let mut rng = Rng::new(36);
        let mut reference: Option<(MembershipRole, usize, bool)> = None;
        for _ in 0..16 {
            let mut delivery = ops.clone();
            shuffle(&mut rng, &mut delivery);
            let mut state = ScopeState::new();
            for op in delivery {
                state.apply(op).expect("racing ops are well-formed");
            }
            let outcome = (
                membership_role(&state, partner).expect("re-added membership survives"),
                visible_budgets(&state).len(),
                org_alive(&state),
            );
            match reference {
                None => reference = Some(outcome),
                Some(expected) => assert_eq!(
                    outcome, expected,
                    "resolution must not depend on delivery order"
                ),
            }
        }
        let (role, budgets, alive) = reference.expect("at least one shuffle");
        assert_eq!(role, Role::Viewer, "the later stamp won the role race");
        assert_eq!(budgets, 1);
        assert!(alive, "the org resurrection won");
    }
}
