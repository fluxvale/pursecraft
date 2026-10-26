//! The category surface (ADR 0026): `category new/list`, category and
//! group name resolution, and the Inbox ensure — every budget-writing
//! command's read-then-mint step for the review queue.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use pursecraft_core::domain::{
    CategoryField, CategoryGroupField, Entity, EntityKind, Field, Value,
};
use pursecraft_core::ids::{CategoryId, EntityId, ScopeId};
use pursecraft_core::ops::{ApplyError, ScopeState};
use pursecraft_core::resolve::category_group;
use pursecraft_core::store::{LocalStore, StoreError};
use pursecraft_core::sync::SyncSession;

use crate::capture::Minter;
use crate::home::{Identity, IdentityError, budget_log, load_identity};
use crate::idmint::mint_uuid;
use crate::session::Session;
use crate::sink;

/// The review queue's name (ADR 0026): the earliest live category named
/// this IS the inbox — bootstrap mints it, a user-created one is adopted.
pub const INBOX_NAME: &str = "Inbox";

/// A failed category command.
#[derive(Debug)]
pub enum CategoryError {
    Identity(IdentityError),
    Store(StoreError),
    Apply(ApplyError),
    /// The pending-sync count failed (ADR 0011's badge must not lie).
    Sync(crate::sync::SyncError),
    /// No world exists — bootstrap is capture's (ADR 0023).
    NotBootstrapped,
    /// `category new` with an empty name (argv rejects this; the public
    /// API defends it too).
    EmptyName,
    /// A live category of this exact name exists (ADR 0026: name-keyed
    /// resolution must stay unambiguous); `known` lists what does.
    Duplicate {
        name: String,
        known: Vec<String>,
    },
    /// No live category of this exact name; `known` lists what does —
    /// the resolution error for `--category`, `assign`, and
    /// `categorize` (exact names, never find-or-create).
    Unknown {
        wanted: String,
        known: Vec<String>,
    },
}

impl fmt::Display for CategoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Apply(e) => write!(f, "stored op rejected by the engine: {e}"),
            Self::Sync(e) => write!(f, "{e}"),
            Self::NotBootstrapped => write!(
                f,
                "nothing to file into yet — capture a transaction first: pursecraft add coffee -4.50"
            ),
            Self::EmptyName => write!(f, "category name must not be empty"),
            Self::Duplicate { name, known } => write!(
                f,
                "category {name:?} already exists (known: {}; use a distinct name — \
                 categories are matched by exact name)",
                join_known(known)
            ),
            Self::Unknown { wanted, known } => write!(
                f,
                "unknown category {wanted:?} (known: {}; create one: pursecraft category new {wanted:?})",
                join_known(known)
            ),
        }
    }
}

impl std::error::Error for CategoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(e) => Some(e),
            Self::Store(e) => Some(e),
            Self::Apply(e) => Some(e),
            Self::Sync(e) => Some(e),
            _ => None,
        }
    }
}

impl From<IdentityError> for CategoryError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}

impl From<StoreError> for CategoryError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<ApplyError> for CategoryError {
    fn from(e: ApplyError) -> Self {
        Self::Apply(e)
    }
}

impl From<crate::sync::SyncError> for CategoryError {
    fn from(e: crate::sync::SyncError) -> Self {
        Self::Sync(e)
    }
}

impl From<EnsureError> for CategoryError {
    fn from(e: EnsureError) -> Self {
        match e {
            EnsureError::Store(e) => Self::Store(e),
            EnsureError::Apply(e) => Self::Apply(e),
        }
    }
}

impl From<std::io::Error> for CategoryError {
    fn from(e: std::io::Error) -> Self {
        Self::Store(e.into())
    }
}

/// The `known:` list rendering shared by every name-resolution error.
pub(crate) fn join_known(known: &[String]) -> String {
    if known.is_empty() {
        "none exist yet".to_owned()
    } else {
        known.join(", ")
    }
}

/// A failed ensure step (the Inbox bootstrap): store or engine trouble —
/// the only failures [`ensure_inbox`] can produce.
#[derive(Debug)]
pub(crate) enum EnsureError {
    Store(StoreError),
    Apply(ApplyError),
}

impl fmt::Display for EnsureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Apply(e) => write!(f, "stored op rejected by the engine: {e}"),
        }
    }
}

impl std::error::Error for EnsureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(e) => Some(e),
            Self::Apply(e) => Some(e),
        }
    }
}

impl From<StoreError> for EnsureError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<ApplyError> for EnsureError {
    fn from(e: ApplyError) -> Self {
        Self::Apply(e)
    }
}

/// The state's live, named categories as `(id, name)` pairs, earliest id
/// first (ADR 0016's deterministic convention) — the one enumeration
/// every category surface reads.
pub(crate) fn live_categories(state: &ScopeState) -> Vec<(EntityId, String)> {
    let mut categories: Vec<(EntityId, String)> = state
        .entities()
        .filter_map(|entity| match entity {
            Entity::Category(c) if !c.deleted && c.name.is_some() => Some((
                EntityId::new(c.id.as_uuid()).expect("stored v7"),
                c.name.clone().unwrap_or_default(),
            )),
            _ => None,
        })
        .collect();
    categories.sort();
    categories
}

/// The live category names, earliest-first (error listings and views).
pub(crate) fn known_names(state: &ScopeState) -> Vec<String> {
    live_categories(state)
        .into_iter()
        .map(|(_, name)| name)
        .collect()
}

/// Find the earliest-created live category named exactly `name` (ADR
/// 0026's name-keyed resolution — the payee precedent).
pub(crate) fn find_category(state: &ScopeState, name: &str) -> Option<EntityId> {
    state
        .entities()
        .filter_map(|entity| match entity {
            Entity::Category(c) if !c.deleted && c.name.as_deref() == Some(name) => {
                Some(EntityId::new(c.id.as_uuid()).expect("stored v7"))
            }
            _ => None,
        })
        .min()
}

/// The inbox category (ADR 0026): the earliest live category named
/// [`INBOX_NAME`], as the typed id the core projection takes.
pub(crate) fn inbox_of(state: &ScopeState) -> Option<CategoryId> {
    find_category(state, INBOX_NAME).map(|id| CategoryId::new(id.as_uuid()).expect("stored v7"))
}

/// Ensure the Inbox category exists (ADR 0026): every budget-writing
/// command's first budget-log step — find-by-name, else mint one entity
/// with an anchored name op (the account ensure pattern: a stale retry
/// loses contested fields, a torn one self-heals). Returns whether this
/// call minted it.
pub(crate) fn ensure_inbox(
    minter: &mut Minter,
    store: &mut LocalStore,
    identity: &Identity,
) -> Result<bool, EnsureError> {
    let session = crate::capture::boot(store)?;
    if find_category(session.state(), INBOX_NAME).is_some() {
        return Ok(false);
    }
    let id = EntityId::new(mint_uuid()).expect("minted v7");
    sink::sink(
        store,
        minter.op_at(
            crate::capture::anchored_at(id),
            ScopeId::Budget(identity.budget_id),
            EntityKind::Category,
            id,
            Field::Category(CategoryField::Name),
            Value::Text(INBOX_NAME.to_owned()),
        ),
    )?;
    Ok(true)
}

/// The line every command that mints the Inbox prints (ADR 0026's
/// teaching, once per world).
pub(crate) fn inbox_line() -> String {
    format!(
        "created the {INBOX_NAME:?} category — uncategorized captures land there (review: pursecraft categorize)\n"
    )
}

/// `pursecraft category new <name> [--group <name>]` (ADR 0026): an
/// explicit mint — duplicate live names are refused (name-keyed
/// resolution must stay unambiguous), the optional group is
/// find-or-create (a label, not money).
pub fn new_category(
    home: &Path,
    session: &Session,
    name: &str,
    group: Option<&str>,
) -> Result<String, CategoryError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CategoryError::EmptyName);
    }
    let Some(identity) = load_identity(home)? else {
        return Err(CategoryError::NotBootstrapped);
    };
    let mut minter = Minter::new(session, &identity);

    let path = budget_log(home, identity.budget_id);
    std::fs::create_dir_all(path.parent().expect("store parent"))?;
    let mut store = LocalStore::open(&path)?;
    let mut out = String::new();
    if ensure_inbox(&mut minter, &mut store, &identity)? {
        out.push_str(&inbox_line());
    }
    let boot = crate::capture::boot(&store)?;
    minter.absorb(boot.clock());
    let state = boot.state();
    if find_category(state, name).is_some() {
        return Err(CategoryError::Duplicate {
            name: name.to_owned(),
            known: known_names(state),
        });
    }
    let scope = ScopeId::Budget(identity.budget_id);
    let id = EntityId::new(mint_uuid()).expect("minted v7");

    // Groups are find-or-create labels (ADR 0026): find the earliest
    // live group of this exact name, else mint one — a typo'd group is
    // cosmetic, never money.
    let mut ops = Vec::new();
    let group_name = group.map(|group| {
        let existing = state
            .entities()
            .filter_map(|entity| match entity {
                Entity::CategoryGroup(g) if !g.deleted && g.name.as_deref() == Some(group) => {
                    Some(EntityId::new(g.id.as_uuid()).expect("stored v7"))
                }
                _ => None,
            })
            .min();
        match existing {
            Some(group_id) => group_id,
            None => {
                let group_id = EntityId::new(mint_uuid()).expect("minted v7");
                ops.push(minter.op_now(
                    scope,
                    EntityKind::CategoryGroup,
                    group_id,
                    Field::CategoryGroup(CategoryGroupField::Name),
                    Value::Text(group.to_owned()),
                ));
                group_id
            }
        }
    });
    if let Some(group_id) = group_name {
        ops.push(minter.op_now(
            scope,
            EntityKind::Category,
            id,
            Field::Category(CategoryField::GroupId),
            Value::Id(group_id),
        ));
    }
    ops.push(minter.op_now(
        scope,
        EntityKind::Category,
        id,
        Field::Category(CategoryField::Name),
        Value::Text(name.to_owned()),
    ));
    for op in ops {
        sink::sink(&mut store, op)?;
    }
    match group.map(str::to_owned) {
        Some(group) => out.push_str(&format!("created category {name:?} in group {group:?}\n")),
        None => out.push_str(&format!("created category {name:?}\n")),
    }
    Ok(out)
}

/// `pursecraft category list` (ADR 0026): live categories grouped, the
/// Inbox marked. Read-only — no world shows the getting-started hint.
pub fn list(home: &Path, session: &Session) -> Result<String, CategoryError> {
    let Some(identity) = load_identity(home)? else {
        return Ok("no categories yet\n\ntry: pursecraft add coffee -4.50\n".to_owned());
    };
    let path = budget_log(home, identity.budget_id);
    if !path.exists() {
        return Ok("no categories yet\n\ntry: pursecraft add coffee -4.50\n".to_owned());
    }
    let store = LocalStore::open(&path)?;
    let mut replay = SyncSession::new();
    replay.apply_delta(store.delta_since(0))?;
    let state = replay.state();
    let inbox = inbox_of(state);

    let mut out = String::new();
    for (group, members) in grouped(state) {
        match group {
            Some(group) => out.push_str(&format!("{group}\n")),
            None => out.push_str("(ungrouped)\n"),
        }
        for (id, name) in members {
            let inbox_mark = if Some(CategoryId::new(id.as_uuid()).expect("stored v7")) == inbox {
                " (inbox)"
            } else {
                ""
            };
            out.push_str(&format!("  {name}{inbox_mark}\n"));
        }
    }
    if out.is_empty() {
        return Ok("no categories yet\n\ntry: pursecraft category new Food\n".to_owned());
    }
    Ok(crate::list::with_pending_sync(
        out,
        crate::sync::pending_count(home, session, &identity)?,
    ))
}

/// One display block: an optional group header and its member
/// categories `(id, name)` — the shared shape of `category list`'s and
/// `budget`'s grouped rows.
pub(crate) type CategoryBlock = (Option<String>, Vec<(EntityId, String)>);

/// Live named categories in display order (shared by `category list`
/// and `budget`'s grouped rows, ADR 0026): groups by name ascending,
/// the ungrouped block last; within a block, name ascending then id.
pub(crate) fn grouped(state: &ScopeState) -> Vec<CategoryBlock> {
    // (group id, group name) for every live named group.
    let mut groups: Vec<(EntityId, String)> = state
        .entities()
        .filter_map(|entity| match entity {
            Entity::CategoryGroup(g) if !g.deleted && g.name.is_some() => Some((
                EntityId::new(g.id.as_uuid()).expect("stored v7"),
                g.name.clone().unwrap_or_default(),
            )),
            _ => None,
        })
        .collect();
    groups.sort();

    let mut grouped: BTreeMap<String, Vec<(String, EntityId)>> = BTreeMap::new();
    let mut ungrouped: Vec<(String, EntityId)> = Vec::new();
    for (id, name) in live_categories(state) {
        let group = match state.entity(&id) {
            Some(Entity::Category(c)) => category_group(state, c),
            _ => None,
        };
        match group {
            Some(group) => {
                let header = groups
                    .iter()
                    .find(|(gid, _)| *gid == EntityId::new(group.as_uuid()).expect("stored v7"))
                    .map(|(_, name)| name.clone())
                    .unwrap_or_else(|| "?".to_owned()); // live but torn name
                grouped.entry(header).or_default().push((name, id));
            }
            None => ungrouped.push((name, id)),
        }
    }

    let mut blocks: Vec<CategoryBlock> = grouped
        .into_iter()
        .map(|(header, mut members)| {
            members.sort();
            (
                Some(header),
                members.into_iter().map(|(name, id)| (id, name)).collect(),
            )
        })
        .collect();
    if !ungrouped.is_empty() {
        ungrouped.sort();
        blocks.push((
            None,
            ungrouped.into_iter().map(|(name, id)| (id, name)).collect(),
        ));
    }
    blocks
}
