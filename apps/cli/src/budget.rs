//! Allocation and the balances view (ADR 0027): `assign` writes the
//! month × category cell read-then-mint, `budget` renders the core's
//! projection — assigned, activity, available per category, plus
//! to-be-budgeted. All derived, never stored.

use std::fmt;
use std::path::Path;

use pursecraft_core::budget::CategoryRow;
use pursecraft_core::date::{Date, Month};
use pursecraft_core::domain::{Entity, EntityKind, Field, MonthCategoryField, Value};
use pursecraft_core::ids::{CategoryId, EntityId, ScopeId};
use pursecraft_core::money::Milliunits;
use pursecraft_core::ops::ApplyError;
use pursecraft_core::store::{LocalStore, StoreError};

use crate::capture::{Minter, boot};
use crate::category::{CategoryError, ensure_inbox, find_category, grouped, inbox_line, inbox_of};
use crate::home::{IdentityError, budget_log, load_identity};
use crate::idmint::mint_uuid;
use crate::session::Session;
use crate::sink;

/// A failed assign or budget show.
#[derive(Debug)]
pub enum BudgetError {
    Identity(IdentityError),
    Store(StoreError),
    Apply(ApplyError),
    Category(CategoryError),
    /// The pending-sync count failed (ADR 0011's badge must not lie).
    Sync(crate::sync::SyncError),
    /// `--month` is not a strict `YYYY-MM`.
    Month {
        input: String,
    },
    /// The amount carries a sign — assignment is a bare magnitude
    /// (ADR 0027: "no sign").
    Signed {
        input: String,
    },
    /// The amount is not a strict Milliunits magnitude.
    Invalid {
        input: String,
    },
    /// `assign` targeted the Inbox — a review surface, not an envelope
    /// (ADR 0027).
    AssignsInbox,
}

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Apply(e) => write!(f, "stored op rejected by the engine: {e}"),
            Self::Category(e) => write!(f, "{e}"),
            Self::Sync(e) => write!(f, "{e}"),
            Self::Month { input } => {
                write!(
                    f,
                    "invalid month {input:?} (expected YYYY-MM, e.g. 2026-10)"
                )
            }
            Self::Signed { input } => write!(
                f,
                "amount {input:?} carries a sign — assign holds a bare magnitude; write 500, \
                 not +500 or -500 (pass a smaller amount to reduce, never a minus)"
            ),
            Self::Invalid { input } => write!(
                f,
                "invalid amount {input:?} (expected e.g. 500 or 1250.50: digits, an optional \
                 fraction of at most 3 digits, no separators or symbols)"
            ),
            Self::AssignsInbox => write!(
                f,
                "the Inbox is the review queue, not an envelope — categorize first: \
                 pursecraft categorize"
            ),
        }
    }
}

impl std::error::Error for BudgetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(e) => Some(e),
            Self::Store(e) => Some(e),
            Self::Apply(e) => Some(e),
            Self::Category(e) => Some(e),
            Self::Sync(e) => Some(e),
            _ => None,
        }
    }
}

impl From<IdentityError> for BudgetError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}

impl From<StoreError> for BudgetError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<ApplyError> for BudgetError {
    fn from(e: ApplyError) -> Self {
        Self::Apply(e)
    }
}

impl From<CategoryError> for BudgetError {
    fn from(e: CategoryError) -> Self {
        Self::Category(e)
    }
}

impl From<crate::sync::SyncError> for BudgetError {
    fn from(e: crate::sync::SyncError) -> Self {
        Self::Sync(e)
    }
}

impl From<crate::category::EnsureError> for BudgetError {
    fn from(e: crate::category::EnsureError) -> Self {
        match e {
            crate::category::EnsureError::Store(e) => Self::Store(e),
            crate::category::EnsureError::Apply(e) => Self::Apply(e),
        }
    }
}

impl From<std::io::Error> for BudgetError {
    fn from(e: std::io::Error) -> Self {
        Self::Store(e.into())
    }
}

/// The month an assign or view targets: `--month`/positional strict
/// `YYYY-MM`, else today's calendar month (ADR 0027 — the local civil
/// today, never a UTC month).
fn resolve_month(raw: Option<&str>, today: Date) -> Result<Month, BudgetError> {
    match raw.map(str::trim) {
        Some(input) => input.parse().map_err(|_| BudgetError::Month {
            input: input.to_owned(),
        }),
        None => Month::new(today.year(), today.month()).ok_or_else(|| BudgetError::Month {
            input: today.to_string(),
        }),
    }
}

/// Parse an assignment magnitude: the core's exact Milliunits grammar,
/// bare digits — no sign in either direction (ADR 0027).
fn parse_magnitude(input: &str) -> Result<Milliunits, BudgetError> {
    let trimmed = input.trim();
    if trimmed.starts_with('-') || trimmed.starts_with('+') {
        return Err(BudgetError::Signed {
            input: trimmed.to_owned(),
        });
    }
    trimmed.parse().map_err(|_| BudgetError::Invalid {
        input: trimmed.to_owned(),
    })
}

/// `pursecraft assign <category> <amount> [--month YYYY-MM]` (ADR 0027):
/// the month × category cell's `budgeted`, read-then-mint — the earliest
/// cell for the pair gets the write (this is the household race LWW
/// exists for), a cell is minted only when none exists, and a torn cell
/// (entity landed, `budgeted` not) is completed, never twinned.
pub fn assign(
    home: &Path,
    session: &Session,
    raw_category: &str,
    raw_amount: &str,
    raw_month: Option<&str>,
    today: Date,
) -> Result<String, BudgetError> {
    let amount = parse_magnitude(raw_amount)?;
    let month = resolve_month(raw_month, today)?;
    let Some(identity) = load_identity(home)? else {
        return Err(CategoryError::NotBootstrapped.into());
    };
    let mut minter = Minter::new(session, &identity);

    let path = budget_log(home, identity.budget_id);
    std::fs::create_dir_all(path.parent().expect("store parent"))?;
    let mut store = LocalStore::open(&path)?;
    let mut out = String::new();
    if ensure_inbox(&mut minter, &mut store, &identity)? {
        out.push_str(&inbox_line());
    }
    let boot_session = boot(&store)?;
    minter.absorb(boot_session.clock());
    let state = boot_session.state();

    let wanted = raw_category.trim();
    let category = find_category(state, wanted).ok_or_else(|| CategoryError::Unknown {
        wanted: wanted.to_owned(),
        known: crate::category::known_names(state),
    })?;
    let category_typed = CategoryId::new(category.as_uuid()).expect("stored v7");
    if inbox_of(state) == Some(category_typed) {
        return Err(BudgetError::AssignsInbox);
    }
    let name = state
        .entity(&category)
        .and_then(|entity| match entity {
            Entity::Category(c) => c.name.clone(),
            _ => None,
        })
        .unwrap_or_else(|| "?".to_owned());

    // Every live cell for (month, category), earliest id first: the
    // earliest gets the write (this is the household race LWW exists
    // for); any twin (two devices minting offline) is zeroed so the
    // next assign corrects the total, exactly as ADR 0027 promises.
    let mut cells: Vec<(EntityId, Option<Milliunits>)> = Vec::new();
    for entity in state.entities() {
        let Entity::MonthCategory(cell) = entity else {
            continue;
        };
        if cell.deleted || cell.month != Some(month) || cell.category_id != Some(category_typed) {
            continue;
        }
        cells.push((
            EntityId::new(cell.id.as_uuid()).expect("stored v7"),
            cell.budgeted,
        ));
    }
    cells.sort_by_key(|(id, _)| *id);

    let scope = ScopeId::Budget(identity.budget_id);
    let mut ops = Vec::new();
    match cells.first() {
        Some((cell, was)) => {
            ops.push(minter.op_now(
                scope,
                EntityKind::MonthCategory,
                *cell,
                Field::MonthCategory(MonthCategoryField::Budgeted),
                Value::Milliunits(amount),
            ));
            let stale = cells.len() - 1;
            for (twin, _) in &cells[1..] {
                ops.push(minter.op_now(
                    scope,
                    EntityKind::MonthCategory,
                    *twin,
                    Field::MonthCategory(MonthCategoryField::Budgeted),
                    Value::Milliunits(Milliunits::ZERO),
                ));
            }
            let folded = if stale > 0 {
                format!(
                    " (folded {stale} stale duplicate cell{})",
                    if stale == 1 { "" } else { "s" }
                )
            } else {
                String::new()
            };
            match was.filter(|was| *was != amount) {
                Some(was) => out.push_str(&format!(
                    "assigned {amount} to {name} for {month}, was {was}{folded}\n"
                )),
                None => out.push_str(&format!(
                    "assigned {amount} to {name} for {month}{folded}\n"
                )),
            }
        }
        None => {
            let cell = EntityId::new(mint_uuid()).expect("minted v7");
            for (field, value) in [
                (
                    Field::MonthCategory(MonthCategoryField::Month),
                    Value::Month(month),
                ),
                (
                    Field::MonthCategory(MonthCategoryField::CategoryId),
                    Value::Id(category),
                ),
                (
                    Field::MonthCategory(MonthCategoryField::Budgeted),
                    Value::Milliunits(amount),
                ),
            ] {
                ops.push(minter.op_now(scope, EntityKind::MonthCategory, cell, field, value));
            }
            out.push_str(&format!("assigned {amount} to {name} for {month}\n"));
        }
    }
    for op in ops {
        sink::sink(&mut store, op)?;
    }
    Ok(out)
}

/// `pursecraft budget [show] [YYYY-MM]` (ADR 0027): the can-I-buy-this
/// view — the core projection rendered, grouped like `category list`,
/// the Inbox row shown only when the bucket is non-empty that month.
/// Read-only; an absent world shows the getting-started hint.
pub fn show(
    home: &Path,
    session: &Session,
    raw_month: Option<&str>,
    today: Date,
) -> Result<String, BudgetError> {
    let month = resolve_month(raw_month, today)?;
    let Some(identity) = load_identity(home)? else {
        return Ok("no budget yet\n\ntry: pursecraft add coffee -4.50\n".to_owned());
    };
    let path = budget_log(home, identity.budget_id);
    if !path.exists() {
        return Ok("no budget yet\n\ntry: pursecraft add coffee -4.50\n".to_owned());
    }
    let store = LocalStore::open(&path)?;
    let replay = boot(&store)?;
    let state = replay.state();
    let projected = pursecraft_core::budget::project(state, month, inbox_of(state));

    let mut out = format!("{month}\n");
    let amounts_of = |id: EntityId| -> Option<&CategoryRow> {
        projected
            .rows
            .iter()
            .find(|row| row.category == CategoryId::new(id.as_uuid()).expect("stored v7"))
    };
    let mut any_rows = false;
    for (group, members) in grouped(state) {
        let lines: Vec<String> = members
            .iter()
            .filter_map(|(id, name)| amounts_of(*id).map(|row| (name, row)))
            .map(|(name, row)| row_line(name, row.assigned, row.activity, row.available))
            .collect();
        if lines.is_empty() {
            continue;
        }
        any_rows = true;
        match group {
            Some(group) => out.push_str(&format!("\n{group}\n")),
            None => out.push_str("\n(ungrouped)\n"),
        }
        out.push_str(&lines.join(""));
    }
    if !any_rows {
        out.push_str("\nno categories yet — try: pursecraft category new Food\n");
    }
    if projected.inbox.count > 0 || projected.inbox.assigned != Milliunits::ZERO {
        // The nag renders on bucket membership (ADR 0027: "non-empty
        // that month"), not on activity — an income-only bucket still
        // awaits review, its amounts sitting in inflow.
        let label = if projected.inbox.count > 0 {
            format!("Inbox ({} to review)", projected.inbox.count)
        } else {
            "Inbox".to_owned()
        };
        out.push_str(&format!(
            "\n{}\n",
            row_line(
                &label,
                projected.inbox.assigned,
                projected.inbox.activity,
                projected.inbox.available,
            )
        ));
    }
    out.push_str(&format!("\nto be budgeted {}\n", projected.to_be_budgeted));
    Ok(crate::list::with_pending_sync(
        out,
        crate::sync::pending_count(home, session, &identity)?,
    ))
}

/// One envelope row: `  name  assigned  activity  available` (ADR 0027's
/// three columns; the equation holds cell-by-cell in the projection).
/// Amounts stringify first — Milliunits' Display ignores formatter
/// width, so padding a String is what makes the columns align.
fn row_line(
    name: &str,
    assigned: Milliunits,
    activity: Milliunits,
    available: Milliunits,
) -> String {
    format!(
        "  {name:<22} {:>12} {:>12} {:>12}\n",
        assigned.to_string(),
        activity.to_string(),
        available.to_string()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::home::Identity;
    use crate::testsupport::TempDir;
    use pursecraft_core::ids::DeviceId;
    use pursecraft_core::ops::{Op, ScopeState};
    use pursecraft_core::sync::SyncSession;

    fn today() -> Date {
        Date::new(2026, 10, 25).unwrap()
    }

    fn session() -> crate::session::Session {
        crate::session::Session {
            version: 1,
            server: "http://127.0.0.1:9".into(),
            device_id: DeviceId::new(mint_uuid()).unwrap(),
            token: "test-only".into(),
        }
    }

    fn capture(home: &Path, payee: &str, amount: &str, category: Option<&str>) {
        crate::capture::add(
            home,
            &session(),
            &crate::capture::RawAdd {
                payee,
                amount,
                date: None,
                account: None,
                category,
            },
            today(),
        )
        .unwrap();
    }

    fn boot_state(home: &Path) -> (Identity, LocalStore, ScopeState) {
        let identity = load_identity(home).unwrap().expect("world");
        let store = LocalStore::open(&budget_log(home, identity.budget_id)).unwrap();
        let mut replay = SyncSession::new();
        replay.apply_delta(store.delta_since(0)).unwrap();
        (identity, store, replay.state().clone())
    }

    /// Magnitude parsing: signless, negative-teaching, exact.
    #[test]
    fn assignment_amounts_are_magnitudes() {
        assert_eq!(parse_magnitude("500").unwrap(), Milliunits::from_major(500));
        assert_eq!(
            parse_magnitude(" 1250.50 ").unwrap(),
            Milliunits::from_milli(1_250_500)
        );
        assert_eq!(parse_magnitude("0").unwrap(), Milliunits::ZERO);
        for signed in ["-500", "+500"] {
            let err = parse_magnitude(signed).unwrap_err();
            assert!(
                err.to_string().contains("bare magnitude"),
                "{signed}: {err}"
            );
        }
        let err = parse_magnitude("1,000").unwrap_err();
        assert!(err.to_string().contains("invalid amount"), "{err}");
    }

    /// THE allocation round trip (issue #29): assign mints the cell;
    /// replay yields exactly (month, category, budgeted); re-assign
    /// re-targets the SAME cell (LWW, no twin); a torn cell is completed.
    #[test]
    fn allocation_round_trips_and_retargets_one_cell() {
        let tmp = TempDir::new("assign-roundtrip");
        let home = tmp.path();
        capture(home, "coffee", "-4.50", None);
        crate::category::new_category(home, &session(), "Food", None).unwrap();

        let first = assign(home, &session(), "Food", "500", None, today()).unwrap();
        assert!(
            first.contains("assigned 500.000 to Food for 2026-10"),
            "{first}"
        );

        let (_, store, state) = boot_state(home);
        let cells: Vec<_> = state
            .entities()
            .filter_map(|e| match e {
                Entity::MonthCategory(c) => Some(c.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(cells.len(), 1, "exactly one cell");
        assert_eq!(cells[0].month, Some(Month::new(2026, 10).unwrap()));
        assert_eq!(cells[0].budgeted, Some(Milliunits::from_major(500)));
        let food = find_category(&state, "Food").unwrap();
        assert_eq!(
            cells[0].category_id,
            Some(CategoryId::new(food.as_uuid()).unwrap())
        );
        let cell_id = cells[0].id;
        let tip = store.tip();
        drop(store);

        // Re-assign targets the same cell: three ops never re-land, only
        // the budgeted write.
        let re = assign(home, &session(), "Food", "300.25", None, today()).unwrap();
        assert!(
            re.contains("assigned 300.250 to Food for 2026-10, was 500.000"),
            "{re}"
        );
        let (_, store, state) = boot_state(home);
        let fresh: Vec<Op> = store.delta_since(tip).map(|s| s.op.clone()).collect();
        assert_eq!(fresh.len(), 1, "one budgeted write, no twin cell");
        assert_eq!(
            fresh[0].entity_id.as_uuid(),
            cell_id.as_uuid(),
            "the same cell entity"
        );
        let still: Vec<_> = state
            .entities()
            .filter_map(|e| match e {
                Entity::MonthCategory(c) => Some(c.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(still.len(), 1);
        assert_eq!(still[0].budgeted, Some(Milliunits::from_milli(300_250)));

        // A different month mints its own cell; the inbox is refused.
        assign(home, &session(), "Food", "100", Some("2026-11"), today()).unwrap();
        let (_, _, state) = boot_state(home);
        assert_eq!(
            state
                .entities()
                .filter(|e| matches!(e, Entity::MonthCategory(_)))
                .count(),
            2
        );
        let err = assign(home, &session(), "Inbox", "100", None, today()).unwrap_err();
        assert!(
            err.to_string().contains("review queue"),
            "assign refuses the inbox\n{err}"
        );
    }

    /// Twin cells fold (hostile-review P2-2, ADR 0027's correction
    /// promise): a later assign targets the earliest cell AND zeroes the
    /// twin — the total becomes exactly the new amount, never floored by
    /// a stale duplicate.
    #[test]
    fn twin_cells_are_folded_by_the_next_assign() {
        let tmp = TempDir::new("twin-fold");
        let home = tmp.path();
        capture(home, "coffee", "-4.50", None);
        crate::category::new_category(home, &session(), "Food", None).unwrap();
        // Seed the twin state: two devices each minted a cell offline.
        let (identity, mut store, state) = boot_state(home);
        let food = find_category(&state, "Food").unwrap();
        let month = Month::new(2026, 10).unwrap();
        let mut minter = Minter::new(&session(), &identity);
        minter.absorb(boot(&store).unwrap().clock());
        for budgeted in [500, 700] {
            let cell = EntityId::new(mint_uuid()).unwrap();
            for (field, value) in [
                (
                    Field::MonthCategory(MonthCategoryField::Month),
                    Value::Month(month),
                ),
                (
                    Field::MonthCategory(MonthCategoryField::CategoryId),
                    Value::Id(food),
                ),
                (
                    Field::MonthCategory(MonthCategoryField::Budgeted),
                    Value::Milliunits(Milliunits::from_major(budgeted)),
                ),
            ] {
                sink::sink(
                    &mut store,
                    minter.op_now(
                        ScopeId::Budget(identity.budget_id),
                        EntityKind::MonthCategory,
                        cell,
                        field,
                        value,
                    ),
                )
                .unwrap();
            }
        }
        drop(store);

        // The over-stated view before correction…
        let view = show(home, &session(), None, today()).unwrap();
        assert!(view.contains("1200.000"), "twins sum: {view}");

        // …and the assign that folds them.
        let assigned = assign(home, &session(), "Food", "800", None, today()).unwrap();
        assert!(
            assigned.contains("folded 1 stale duplicate cell"),
            "{assigned}"
        );
        let view = show(home, &session(), None, today()).unwrap();
        let line = view.lines().find(|l| l.contains("Food")).unwrap();
        assert!(
            line.contains("800.000") && !view.contains("1200.000"),
            "the total is the new amount exactly\n{view}"
        );
        let (_, _, state) = boot_state(home);
        let totals: Vec<i64> = state
            .entities()
            .filter_map(|e| match e {
                Entity::MonthCategory(c) => c.budgeted.map(|b| b.milli()),
                _ => None,
            })
            .collect();
        assert!(totals.contains(&800_000) && totals.contains(&0));
    }

    /// A torn cell (month+category landed, budgeted not) is completed by
    /// the next assign — never twinned (crash window, ADR 0027).
    #[test]
    fn a_torn_cell_is_completed_not_twinned() {
        let tmp = TempDir::new("torn-cell");
        let home = tmp.path();
        capture(home, "coffee", "-4.50", None);
        crate::category::new_category(home, &session(), "Food", None).unwrap();
        let (identity, mut store, state) = boot_state(home);
        let food = find_category(&state, "Food").unwrap();
        let month = Month::new(2026, 10).unwrap();
        let mut minter = Minter::new(&session(), &identity);
        minter.absorb(boot(&store).unwrap().clock());
        let cell = EntityId::new(mint_uuid()).unwrap();
        // Seed the torn pair: month and category, no budgeted.
        for (field, value) in [
            (
                Field::MonthCategory(MonthCategoryField::Month),
                Value::Month(month),
            ),
            (
                Field::MonthCategory(MonthCategoryField::CategoryId),
                Value::Id(food),
            ),
        ] {
            sink::sink(
                &mut store,
                minter.op_now(
                    ScopeId::Budget(identity.budget_id),
                    EntityKind::MonthCategory,
                    cell,
                    field,
                    value,
                ),
            )
            .unwrap();
        }
        drop(store);

        assign(home, &session(), "Food", "50", None, today()).unwrap();
        let (_, _, state) = boot_state(home);
        let cells: Vec<_> = state
            .entities()
            .filter_map(|e| match e {
                Entity::MonthCategory(c) => Some(c.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(cells.len(), 1, "the torn cell was completed");
        assert_eq!(
            cells[0].id.as_uuid(),
            cell.as_uuid(),
            "the SAME entity — no twin"
        );
        assert_eq!(cells[0].budgeted, Some(Milliunits::from_major(50)));
    }

    /// THE balances view + the equation, end to end (issue #29): budget
    /// renders assigned/activity/available per category and to-be-
    /// budgeted, with the inbox nag and income inflow visible.
    #[test]
    fn budget_renders_the_equation_end_to_end() {
        let tmp = TempDir::new("budget-view");
        let home = tmp.path();
        capture(home, "salary", "+5000", None);
        capture(home, "groceries", "-120.50", None);
        crate::category::new_category(home, &session(), "Food", None).unwrap();
        assign(home, &session(), "Food", "400", None, today()).unwrap();

        // File groceries into Food; a second spend stays in the inbox.
        let review = crate::categorize::review(home, &session()).unwrap();
        let short = review
            .lines()
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        crate::categorize::file(home, &session(), &short, "Food").unwrap();
        capture(home, "mystery", "-30", None);

        let view = show(home, &session(), None, today()).unwrap();
        assert!(view.contains("2026-10"), "{view}");
        let food_line = view
            .lines()
            .find(|l| l.contains("Food"))
            .unwrap_or_else(|| panic!("no Food row\n{view}"));
        assert_eq!(
            food_line.trim(),
            format!(
                "{:<22} {:>12} {:>12} {:>12}",
                "Food", "400.000", "-120.500", "279.500"
            ),
            "{view}"
        );
        assert!(
            view.contains("Inbox (2 to review)"),
            "the nag row renders on bucket membership — negatives show as \
             activity, and the count names what waits (salary + mystery)\n{view}"
        );
        assert!(
            view.contains("to be budgeted 4600.000"),
            "5000 income − 400 assigned\n{view}"
        );

        // A month with nothing shows zero envelopes, nothing to budget.
        let empty = show(home, &session(), Some("2027-01"), today()).unwrap();
        assert!(empty.contains("2027-01"), "{empty}");
        assert!(empty.contains("to be budgeted 0.000"), "{empty}");
        assert!(
            !empty.contains("to review"),
            "an empty bucket hides the nag\n{empty}"
        );

        // Bad months and unknown categories teach.
        let err = show(home, &session(), Some("2026-13"), today()).unwrap_err();
        assert!(err.to_string().contains("invalid month"), "{err}");
        let err = assign(home, &session(), "Nope", "100", None, today()).unwrap_err();
        assert!(err.to_string().contains("unknown category"), "{err}");
        let err = assign(home, &session(), "Food", "100", Some("oct-26"), today()).unwrap_err();
        assert!(err.to_string().contains("invalid month"), "{err}");
    }

    /// Year rollover (hostile-review class): a January today defaults to
    /// 2027-01 — the month always comes from a validated date, never
    /// from arithmetic.
    #[test]
    fn the_default_month_rolls_the_year_with_today() {
        assert_eq!(
            resolve_month(None, Date::new(2026, 12, 31).unwrap()).unwrap(),
            Month::new(2026, 12).unwrap()
        );
        assert_eq!(
            resolve_month(None, Date::new(2027, 1, 1).unwrap()).unwrap(),
            Month::new(2027, 1).unwrap()
        );
        assert_eq!(
            resolve_month(Some("2026-12"), Date::new(2027, 1, 1).unwrap()).unwrap(),
            Month::new(2026, 12).unwrap()
        );
    }
}
