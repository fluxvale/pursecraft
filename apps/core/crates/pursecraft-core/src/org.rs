//! Organization-level semantics (ADR 0020): projections within one org
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
/// one organization entity — its own, enforced at apply time (ADR 0020) —
/// so this lookup cannot find a stranger's.
pub fn organization(state: &ScopeState) -> Option<&Organization> {
    let org = state.scope_id()?.org()?;
    match state.entity(&EntityId::from_raw(org.as_uuid())) {
        Some(Entity::Organization(organization)) => Some(organization),
        _ => None,
    }
}

/// Whether the org of `state` survives: org deletion hides everything it
/// owns, data stays (ADR 0020's cascade-hide).
pub fn org_alive(state: &ScopeState) -> bool {
    organization(state).is_some_and(|organization| !organization.deleted)
}

/// Whether a budget of this org is visible: the budget and the org both
/// survive (ADR 0020). An org's budget list is the visible ones — offline,
/// from the org log alone.
pub fn budget_visible(state: &ScopeState, budget: &Budget) -> bool {
    !budget.deleted && org_alive(state)
}

/// The org's visible budgets (ADR 0020).
pub fn visible_budgets(state: &ScopeState) -> impl Iterator<Item = &Budget> {
    state.entities().filter_map(|entity| match entity {
        Entity::Budget(budget) if budget_visible(state, budget) => Some(budget),
        _ => None,
    })
}

/// The user's role in this org: the earliest-created surviving membership
/// naming them — minimum UUIDv7, ADR 0016's fallback convention. A user
/// appears at most once per org in well-formed data; racing twins resolve
/// deterministically on every device (ADR 0020).
pub fn membership_role(state: &ScopeState, user: UserId) -> Option<MembershipRole> {
    state
        .entities()
        .filter_map(|entity| match entity {
            Entity::Membership(membership)
                if !membership.deleted && membership.user_id == Some(user) =>
            {
                Some(membership)
            }
            _ => None,
        })
        .min_by_key(|membership| membership.id)
        .and_then(|membership| membership.role)
}

/// A user's access to one budget of this org: their membership role, iff
/// the budget and the org both survive (ADR 0020). Different orgs give
/// different roles through different memberships; roles are data, and
/// enforcing them is the auth slice's job.
pub fn budget_access(state: &ScopeState, user: UserId, budget: &Budget) -> Option<MembershipRole> {
    budget_visible(state, budget)
        .then(|| membership_role(state, user))
        .flatten()
}

/// The personal-org provisioning op-set (ADR 0020): the organization —
/// named, marked personal for `user` — plus the creator's owner membership.
/// The FluxVale pattern as oplog data: a retried set dedupes on `op_id`,
/// and a re-provision reusing the entity ids rewrites identical values —
/// outcome-idempotent either way. The caller owns all id minting (capture
/// is a later slice, ADR 0016); `mint_op_id` supplies the four op ids.
pub fn provision_personal_org(
    user: UserId,
    org: OrgId,
    membership: EntityId,
    name: &str,
    device_id: DeviceId,
    hlc: Hlc,
    mut mint_op_id: impl FnMut() -> OpId,
) -> Vec<Op> {
    let scope = ScopeId::Org(org);
    let org_entity = EntityId::from_raw(org.as_uuid());
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
/// state the caller holds (ADR 0020). The provisioning invariant holds iff
/// the result has exactly one element: a user's state always includes a
/// personal org, and provisioning never duplicates one. Budget-scoped
/// states contribute nothing — they hold no organization entity.
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
    orgs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::MembershipRole as Role;
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

    /// Provisioning invariant (ADR 0020): provisioning yields exactly one
    /// live personal org with the creator as owner, idempotently.
    #[test]
    fn personal_org_provisioning_is_idempotent_data() {
        let terence = user(500);
        let org = OrgId::new(v7(MS, 41)).unwrap();
        let membership = EntityId::new(v7(MS, 42)).unwrap();
        let device = DeviceId::new(Uuid::nil()).unwrap();
        let hlc = Hlc {
            physical_ms: MS + 1,
            logical: 0,
        };
        let mut counter = 0u64;
        let ops = provision_personal_org(
            terence,
            org,
            membership,
            "Terence's org",
            device,
            hlc,
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
        // The invariant: exactly one live personal org, creator is owner.
        assert_eq!(live_personal_orgs([&state], terence), vec![org]);
        assert_eq!(membership_role(&state, terence), Some(Role::Owner));
        assert_eq!(
            organization(&state).unwrap().name.as_deref(),
            Some("Terence's org")
        );

        // A retried set dedupes wholesale (op_id idempotence, ADR 0007).
        for op in &ops {
            assert_eq!(state.apply(op.clone()), Ok(Applied::Duplicate));
        }
        assert_eq!(live_personal_orgs([&state], terence), vec![org]);

        // A re-provision reusing the entity ids rewrites identical values
        // under the same stamp — outcome-idempotent (ADR 0020), whatever
        // the delivery interleaving. The stamps may name the new op ids as
        // the tie-break winners; the *outcome* must be indistinguishable.
        let mut counter2 = 100u64;
        let reprovision = provision_personal_org(
            terence,
            org,
            membership,
            "Terence's org",
            device,
            hlc,
            || {
                counter2 += 1;
                OpId::new(v7(MS + counter2, counter2)).unwrap()
            },
        );
        let mut re_state = ScopeState::new();
        for op in reprovision.iter().chain(&ops) {
            re_state.apply(op.clone()).unwrap();
        }
        assert_eq!(
            live_personal_orgs([&re_state], terence),
            vec![org],
            "still exactly one personal org"
        );
        assert_eq!(membership_role(&re_state, terence), Some(Role::Owner));
        assert_eq!(
            organization(&re_state).unwrap().name.as_deref(),
            Some("Terence's org")
        );
        assert_eq!(organization(&re_state).unwrap().personal_for, Some(terence));

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

        // A deleted personal org is equally visible: the invariant
        // demands exactly one LIVE org, so a hostile or buggy tombstone
        // leaves the user org-less and the checker says so (ADR 0020 —
        // the log stays faithful; the policy is enforced at capture).
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
                hlc: Hlc {
                    physical_ms: MS + 2,
                    logical: 0,
                },
            })
            .unwrap();
        assert_eq!(
            live_personal_orgs([&mutinied], terence),
            Vec::<OrgId>::new(),
            "no live personal org — the violation is the checker's output"
        );
    }

    /// Role semantics as data (ADR 0020): one user, two orgs, different
    /// roles — the requirement, resolved from memberships alone.
    #[test]
    fn roles_differ_across_orgs() {
        let terence = user(500);
        let mut household = OrgFx::new(51); // Terence owns this one
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
    }

    /// Cross-org isolation (ADR 0020, the P1 class): an op or entity from
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

    /// Referential behavior (ADR 0020): org deletion hides its budgets
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
        assert_eq!(visible_budgets(&fx.state).count(), 0);

        // Resurrection works — deletes are just fields (ADR 0016).
        fx.write(EntityKind::Budget, 94, Field::Deleted, Value::Bool(false));
        assert!(budget_visible(&fx.state, &fx.budget_entity(94)));

        // Org deletion cascades over every budget and membership — the
        // data stays, projections skip it.
        fx.delete_org();
        assert!(!org_alive(&fx.state));
        assert!(!budget_visible(&fx.state, &fx.budget_entity(94)));
        assert_eq!(visible_budgets(&fx.state).count(), 0);
        assert_eq!(
            budget_access(&fx.state, terence, &fx.budget_entity(94)),
            None
        );
    }

    /// Determinism (ADR 0020): concurrent membership and org edits resolve
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
                visible_budgets(&state).count(),
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
