// SPDX-License-Identifier: Apache-2.0
//! Native automatic-upgrade mechanics. No historical domain interpretation.
use super::{cell, quote, Own, Snapshot, Table};
use busbar_contract::persistence::archive::digest;
use rusqlite::{params, Connection, OpenFlags};
use std::path::{Path, PathBuf};

const CONTROL: &str = "__busbar_upgrade";
const TARGETS: &[&str] = &[CONTROL, "meta", "records", "receipts"];
const CONTROL_DDL: &str = "CREATE TABLE __busbar_upgrade(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,operation BLOB NOT NULL,route BLOB NOT NULL,target_format INTEGER NOT NULL,upgrade BLOB NOT NULL,source BLOB NOT NULL,target BLOB NOT NULL,atomic_domain BLOB NOT NULL,clock_authority BLOB NOT NULL,source_physical INTEGER NOT NULL,original_catalogue BLOB NOT NULL,guarded_catalogue BLOB NOT NULL,frozen_digest BLOB NOT NULL,phase INTEGER NOT NULL,activation BLOB,completion BLOB)";
const CATALOGUE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Busy,
    Unsupported,
    MissingCapability,
    Changed,
    Corrupt,
    Bounds,
    Unavailable,
    Pending,
    Refused,
}
fn sql<T>(value: rusqlite::Result<T>) -> Result<T, Error> {
    value.map_err(|e| match e.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            Error::Busy
        }
        _ => Error::Unavailable,
    })
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Object {
    kind: String,
    name: String,
    table: String,
    root: i64,
    sql: Option<String>,
}
fn catalogue(c: &Connection) -> Result<Vec<Object>, Error> {
    let mut query=sql(c.prepare("SELECT type,name,tbl_name,rootpage,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name LIMIT 257"))?;
    let mut rows = sql(query.query([]))?;
    let mut out = Vec::new();
    let mut used = 0usize;
    while let Some(row) = sql(rows.next())? {
        let item = Object {
            kind: sql(row.get(0))?,
            name: sql(row.get(1))?,
            table: sql(row.get(2))?,
            root: sql(row.get(3))?,
            sql: sql(row.get(4))?,
        };
        used = used
            .checked_add(
                item.kind.len()
                    + item.name.len()
                    + item.table.len()
                    + item.sql.as_ref().map_or(0, String::len),
            )
            .ok_or(Error::Bounds)?;
        if used > CATALOGUE_BYTES || out.len() == 256 {
            return Err(Error::Bounds);
        }
        out.push(item);
    }
    Ok(out)
}
fn encode(catalogue: &[Object]) -> Result<Vec<u8>, Error> {
    let value=catalogue.iter().map(|o|serde_json::json!({"kind":o.kind,"name":o.name,"table":o.table,"root":o.root,"sql":o.sql})).collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&value).map_err(|_| Error::Corrupt)?;
    if bytes.len() > CATALOGUE_BYTES {
        return Err(Error::Bounds);
    }
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> Result<Vec<Object>, Error> {
    let values: Vec<serde_json::Value> =
        serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
    values
        .into_iter()
        .map(|v| {
            let fields = v.as_object().ok_or(Error::Corrupt)?;
            if fields.len() != 5 {
                return Err(Error::Corrupt);
            }
            let text = |key| {
                v.get(key)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .ok_or(Error::Corrupt)
            };
            let sql = match v.get("sql") {
                Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(s)) => Some(s.clone()),
                _ => return Err(Error::Corrupt),
            };
            Ok(Object {
                kind: text("kind")?,
                name: text("name")?,
                table: text("table")?,
                root: v
                    .get("root")
                    .and_then(serde_json::Value::as_i64)
                    .ok_or(Error::Corrupt)?,
                sql,
            })
        })
        .collect()
}
fn known(catalogue: &[Object], physical: i64) -> Result<(), Error> {
    let bytes = match physical {
        6 => include_bytes!("../tests/fixtures/physical-6-catalogue.json").as_slice(),
        7..=9 => include_bytes!("../tests/fixtures/physical-9-catalogue.json").as_slice(),
        _ => return Err(Error::Unsupported),
    };
    let profile: Vec<serde_json::Value> =
        serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
    if profile.len() != catalogue.len()
        || profile.iter().zip(catalogue).any(|(a, b)| {
            a["kind"].as_str() != Some(&b.kind)
                || a["name"].as_str() != Some(&b.name)
                || a["table"].as_str() != Some(&b.table)
                || a["sql"].as_str() != b.sql.as_deref()
        })
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}
fn revision_barrier_ddl() -> Result<String, Error> {
    let profile: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../tests/fixtures/physical-6-catalogue.json"))
            .map_err(|_| Error::Corrupt)?;
    profile
        .into_iter()
        .find(|v| v["kind"] == "table" && v["name"] == "store_revision")
        .and_then(|v| v["sql"].as_str().map(str::to_owned))
        .ok_or(Error::Corrupt)
}
pub(crate) fn uninitialized(c: &Connection) -> Result<bool, Error> {
    if !catalogue(c)?.is_empty() {
        return Ok(false);
    }
    let version: i64 = sql(c.query_row("PRAGMA user_version", [], |r| r.get(0)))?;
    let application: i64 = sql(c.query_row("PRAGMA application_id", [], |r| r.get(0)))?;
    Ok(version == 0 && application == 0)
}
pub(crate) fn current_schema(c: &Connection) -> Result<bool, Error> {
    let catalog = catalogue(c)?;
    let mut statements = crate::v4::DDL
        .split(';')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_owned())
        .collect::<Vec<_>>();
    let fresh = catalog.len() == 7;
    if fresh {
        statements.push(revision_barrier_ddl()?);
        for verb in ["INSERT", "UPDATE", "DELETE"] {
            statements.push(guard_sql("store_revision", verb));
        }
    }
    if catalog.len() != statements.len()
        || catalog
            .iter()
            .any(|o| !o.sql.as_ref().is_some_and(|sql| statements.contains(sql)))
    {
        return Ok(false);
    }
    let count: i64 = sql(c.query_row("SELECT count(*) FROM meta", [], |r| r.get(0)))?;
    if count != if fresh { 5 } else { 4 } {
        return Ok(false);
    }
    for key in ["dataset", "atomic_domain", "clock_authority"] {
        let value: Vec<u8> = c
            .query_row(
                "SELECT value FROM meta WHERE key=?1 AND typeof(value)='blob' AND length(value)=16",
                [key],
                |r| r.get(0),
            )
            .map_err(|_| Error::Corrupt)?;
        if value == [0; 16] {
            return Err(Error::Corrupt);
        }
    }
    let format:Vec<u8>=c.query_row("SELECT value FROM meta WHERE key='physical_format' AND typeof(value)='blob' AND length(value)=4",[],|r|r.get(0)).map_err(|_|Error::Corrupt)?;
    if format != 1u32.to_le_bytes() {
        return Err(Error::Unsupported);
    }
    if fresh {
        let tag: Vec<u8> = sql(c.query_row(
            "SELECT value FROM meta WHERE key='empty_origin'",
            [],
            |r| r.get(0),
        ))?;
        let source_rows: i64 =
            sql(c.query_row("SELECT count(*) FROM store_revision", [], |r| r.get(0)))?;
        if tag != [1] || source_rows != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}
pub(crate) fn install_empty_origin(c: &Connection) -> Result<(), Error> {
    let count: i64 = sql(c.query_row(
        "SELECT count(*) FROM meta WHERE key='empty_origin'",
        [],
        |r| r.get(0),
    ))?;
    if count == 1 {
        return if current_schema(c)? {
            Ok(())
        } else {
            Err(Error::Changed)
        };
    }
    sql(c.execute_batch(&revision_barrier_ddl()?))?;
    for verb in ["INSERT", "UPDATE", "DELETE"] {
        sql(c.execute_batch(&guard_sql("store_revision", verb)))?;
    }
    sql(c.execute("INSERT INTO meta VALUES('empty_origin',?1)", [&[1u8][..]]))?;
    Ok(())
}
pub(crate) fn whole_empty(c: &Connection) -> Result<bool, Error> {
    if !current_schema(c)? {
        return Ok(false);
    }
    let (records, receipts): (bool, bool) = sql(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM records),EXISTS(SELECT 1 FROM receipts)",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ))?;
    Ok(!records && !receipts)
}
fn guard_sql(table: &str, verb: &str) -> String {
    format!(
        "CREATE TRIGGER {} BEFORE {verb} ON {} BEGIN SELECT RAISE(ABORT,'Busbar legacy source is frozen'); END",
        quote(&format!(
            "__busbar_freeze_{}_{table}",
            verb.to_ascii_lowercase()
        )),
        quote(table)
    )
}
fn random() -> Result<[u8; 16], Error> {
    loop {
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| Error::Unavailable)?;
        if id != [0; 16] {
            return Ok(id);
        }
    }
}
fn descriptor(catalogue: &[Object], physical: i64, path: &Path) -> Result<[u8; 32], Error> {
    let mut bytes = b"SQLite preopen source/1\0".to_vec();
    bytes.extend_from_slice(&physical.to_le_bytes());
    bytes.extend_from_slice(&encode(catalogue)?);
    bytes.extend_from_slice(path.as_os_str().as_encoded_bytes());
    bytes.extend_from_slice(&file_identity(
        &std::fs::File::open(path).map_err(|_| Error::Unavailable)?,
    )?);
    Ok(digest(&bytes))
}
fn source_digest(c: &Connection, tables: &[Table], frame_bytes: usize) -> Result<[u8; 32], Error> {
    let mut hash = digest(b"SQLite guarded original rows/1\0");
    for table in tables {
        let mut pk = table
            .columns
            .iter()
            .enumerate()
            .filter(|(_, c)| c.primary_key_ordinal != 0)
            .collect::<Vec<_>>();
        pk.sort_by_key(|(_, c)| c.primary_key_ordinal);
        let query = format!(
            "SELECT {} FROM {} ORDER BY {}",
            table
                .columns
                .iter()
                .map(|c| quote(&c.name))
                .collect::<Vec<_>>()
                .join(","),
            quote(&table.name),
            pk.iter()
                .map(|(_, c)| format!("{} COLLATE BINARY", quote(&c.name)))
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut statement = sql(c.prepare(&query))?;
        let mut rows = sql(statement.query([]))?;
        let mut table_hash = b"SQLite guarded table/1\0".to_vec();
        table_hash.extend_from_slice(&hash);
        table_hash.extend_from_slice(table.name.as_bytes());
        hash = digest(&table_hash);
        while let Some(row) = sql(rows.next())? {
            let cells = (0..table.columns.len())
                .map(|i| row.get_ref(i).map(cell))
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|_| Error::Corrupt)?;
            let encoded =
                busbar_contract::persistence::legacy_row::encode::<Own>(&cells, frame_bytes)
                    .map_err(|_| Error::Bounds)?;
            let mut frame = b"SQLite guarded row/1\0".to_vec();
            frame.extend_from_slice(&hash);
            frame.extend_from_slice(&(encoded.expose_own(&Own::here()).len() as u64).to_le_bytes());
            frame.extend_from_slice(&digest(encoded.expose_own(&Own::here())));
            hash = digest(&frame);
        }
    }
    Ok(hash)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Upgrade {
    pub operation: [u8; 16],
    pub route: [u8; 32],
    pub target_format: u32,
    pub upgrade: [u8; 16],
    pub source: [u8; 16],
    pub target: [u8; 16],
    pub atomic_domain: [u8; 16],
    pub clock_authority: [u8; 16],
    pub source_physical: i64,
    pub frozen_digest: [u8; 32],
    pub phase: u32,
}
struct Durable {
    upgrade: Upgrade,
    original: Vec<Object>,
    guarded: Vec<Object>,
    activation: Option<Vec<u8>>,
    completion: Option<Vec<u8>>,
}
fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Corrupt)
}
fn load(c: &Connection) -> Result<Durable, Error> {
    let lengths:(i64,i64,Option<i64>,Option<i64>)=sql(c.query_row("SELECT length(original_catalogue),length(guarded_catalogue),length(activation),length(completion) FROM __busbar_upgrade WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))))?;
    if lengths.0 < 0
        || lengths.1 < 0
        || lengths.0 as u64 > CATALOGUE_BYTES as u64
        || lengths.1 as u64 > CATALOGUE_BYTES as u64
        || lengths.2.is_some_and(|n| n != 32)
        || lengths.3.is_some_and(|n| n != 32)
    {
        return Err(Error::Bounds);
    }
    let count: i64 = sql(c.query_row("SELECT count(*) FROM __busbar_upgrade", [], |r| r.get(0)))?;
    if count != 1 {
        return Err(Error::Corrupt);
    }
    let mut q=sql(c.prepare("SELECT version,operation,route,target_format,upgrade,source,target,atomic_domain,clock_authority,source_physical,original_catalogue,guarded_catalogue,frozen_digest,phase,activation,completion FROM __busbar_upgrade WHERE id=1"))?;
    let mut rows = sql(q.query([]))?;
    let r = sql(rows.next())?.ok_or(Error::Corrupt)?;
    if sql(r.get::<_, i64>(0))? != 1 {
        return Err(Error::Unsupported);
    }
    let original: Vec<u8> = sql(r.get(10))?;
    let guarded: Vec<u8> = sql(r.get(11))?;
    if original.len() > CATALOGUE_BYTES || guarded.len() > CATALOGUE_BYTES {
        return Err(Error::Bounds);
    }
    let upgrade = Upgrade {
        operation: fixed(sql(r.get(1))?)?,
        route: fixed(sql(r.get(2))?)?,
        target_format: sql(r.get(3))?,
        upgrade: fixed(sql(r.get(4))?)?,
        source: fixed(sql(r.get(5))?)?,
        target: fixed(sql(r.get(6))?)?,
        atomic_domain: fixed(sql(r.get(7))?)?,
        clock_authority: fixed(sql(r.get(8))?)?,
        source_physical: sql(r.get(9))?,
        frozen_digest: fixed(sql(r.get(12))?)?,
        phase: sql(r.get(13))?,
    };
    if upgrade.operation == [0; 16]
        || upgrade.route == [0; 32]
        || upgrade.target_format != 1
        || upgrade.frozen_digest == [0; 32]
        || upgrade.upgrade == [0; 16]
        || upgrade.source == [0; 16]
        || upgrade.target == [0; 16]
        || upgrade.atomic_domain == [0; 16]
        || upgrade.clock_authority == [0; 16]
        || upgrade.phase > 2
    {
        return Err(Error::Corrupt);
    }
    Ok(Durable {
        upgrade,
        original: decode(&original)?,
        guarded: decode(&guarded)?,
        activation: sql(r.get(14))?,
        completion: sql(r.get(15))?,
    })
}
fn validate_durable(c: &Connection, d: &Durable) -> Result<(), Error> {
    known(&d.original, d.upgrade.source_physical)?;
    let mut expected = d.original.clone();
    let mut statements = vec![CONTROL_DDL.to_owned()];
    statements.extend(
        crate::v4::DDL
            .split(';')
            .filter(|v| !v.trim().is_empty())
            .map(|s| s.trim().to_owned()),
    );
    for object in d.original.iter().filter(|o| o.kind == "table") {
        for verb in ["INSERT", "UPDATE", "DELETE"] {
            statements.push(guard_sql(&object.name, verb));
        }
    }
    for item in d
        .guarded
        .iter()
        .filter(|o| !d.original.iter().any(|old| old.name == o.name))
    {
        if !item
            .sql
            .as_ref()
            .is_some_and(|sql| statements.iter().any(|allowed| allowed == sql))
        {
            return Err(Error::Changed);
        }
        expected.push(item.clone());
    }
    expected.sort_by(|a, b| (&a.kind, &a.name).cmp(&(&b.kind, &b.name)));
    if expected != d.guarded
        || d.guarded.len() != d.original.len() + statements.len()
        || catalogue(c)? != d.guarded
    {
        return Err(Error::Changed);
    }
    let physical: i64 = sql(c.query_row("PRAGMA user_version", [], |r| r.get(0)))?;
    if physical != d.upgrade.source_physical {
        return Err(Error::Changed);
    }
    for (key, expected) in [
        ("dataset", d.upgrade.target.as_slice()),
        ("atomic_domain", d.upgrade.atomic_domain.as_slice()),
        ("clock_authority", d.upgrade.clock_authority.as_slice()),
        ("physical_format", 1u32.to_le_bytes().as_slice()),
    ] {
        let value: Vec<u8> =
            sql(c.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0)))?;
        if value != expected {
            return Err(Error::Changed);
        }
    }
    Ok(())
}
fn file_identity(file: &std::fs::File) -> Result<Vec<u8>, Error> {
    let metadata = file.metadata().map_err(|_| Error::Unavailable)?;
    if !metadata.is_file() {
        return Err(Error::Refused);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(Error::Refused);
        }
        let mut out = metadata.dev().to_le_bytes().to_vec();
        out.extend_from_slice(&metadata.ino().to_le_bytes());
        Ok(out)
    }
    #[cfg(windows)]
    {
        let info = winapi_util::file::information(file).map_err(|_| Error::Unavailable)?;
        if info.number_of_links() != 1 {
            return Err(Error::Refused);
        }
        let mut out = info.volume_serial_number().to_le_bytes().to_vec();
        out.extend_from_slice(&info.file_index().to_le_bytes());
        Ok(out)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        Err(Error::Unsupported)
    }
}
struct Coordination {
    file: std::fs::File,
    path: PathBuf,
    source: PathBuf,
    identity: Vec<u8>,
    source_identity: Vec<u8>,
}
impl Coordination {
    fn acquire(source: &Path) -> Result<Self, Error> {
        if source.canonicalize().map_err(|_| Error::Unavailable)? != source {
            return Err(Error::Refused);
        }
        let source_file = std::fs::File::open(source).map_err(|_| Error::Unavailable)?;
        let source_identity = file_identity(&source_file)?;
        let mut name = source.as_os_str().to_os_string();
        name.push(".busbar-upgrade-lock");
        let path = PathBuf::from(name);
        if std::fs::symlink_metadata(&path)
            .is_ok_and(|m| !m.is_file() || m.file_type().is_symlink())
        {
            return Err(Error::Refused);
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(|_| Error::Unavailable)?;
        if file.metadata().map_err(|_| Error::Unavailable)?.len() != 0 {
            return Err(Error::Refused);
        }
        let identity = file_identity(&file)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(Error::Busy),
            Err(std::fs::TryLockError::Error(_)) => return Err(Error::Unavailable),
        }
        let lock = Self {
            file,
            path,
            source: source.to_owned(),
            identity,
            source_identity,
        };
        lock.check()?;
        Ok(lock)
    }
    fn check(&self) -> Result<(), Error> {
        if std::fs::symlink_metadata(&self.path)
            .map_err(|_| Error::Changed)?
            .file_type()
            .is_symlink()
        {
            return Err(Error::Changed);
        }
        let path_file = std::fs::File::open(&self.path).map_err(|_| Error::Changed)?;
        let source = std::fs::File::open(&self.source).map_err(|_| Error::Changed)?;
        if file_identity(&self.file).map_err(|_| Error::Changed)? != self.identity
            || file_identity(&path_file).map_err(|_| Error::Changed)? != self.identity
            || file_identity(&source).map_err(|_| Error::Changed)? != self.source_identity
        {
            return Err(Error::Changed);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Inspection {
    Empty,
    Current,
    Legacy { physical: i64, descriptor: [u8; 32] },
    InProgress(Upgrade),
}
fn configured_path(input: &Path) -> Result<(PathBuf, bool, bool), Error> {
    let text = input.to_str().ok_or(Error::Unsupported)?;
    if text == ":memory:" {
        return Ok((input.to_owned(), true, true));
    }
    let (path, writable, create) = if let Some(uri) = text.strip_prefix("file:") {
        let (name, query) = uri.split_once('?').unwrap_or((uri, ""));
        let mut mode = None;
        for parameter in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = parameter.split_once('=').ok_or(Error::Unsupported)?;
            match key {
                "mode" if mode.is_none() => mode = Some(value),
                "cache" if value == "private" => {}
                _ => return Err(Error::Unsupported),
            }
        }
        if mode == Some("memory") || (name == ":memory:" && matches!(mode, None | Some("rwc"))) {
            return Ok((PathBuf::from(":memory:"), true, true));
        }
        if !matches!(mode, None | Some("ro" | "rw" | "rwc")) {
            return Err(Error::Unsupported);
        }
        let name = if let Some(tail) = name.strip_prefix("//localhost/") {
            format!("/{tail}")
        } else {
            if name.starts_with("//") && !name.starts_with("///") {
                return Err(Error::Unsupported);
            }
            name.to_owned()
        };
        let mut decoded = Vec::new();
        let source = name.as_bytes();
        let mut at = 0;
        while at < source.len() {
            if source[at] == b'%' {
                if at + 2 >= source.len() {
                    return Err(Error::Unsupported);
                }
                let hex = |b: u8| match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                };
                let byte = hex(source[at + 1])
                    .zip(hex(source[at + 2]))
                    .map(|(a, b)| (a << 4) | b)
                    .ok_or(Error::Unsupported)?;
                if byte == 0 {
                    return Err(Error::Unsupported);
                }
                decoded.push(byte);
                at += 3;
            } else {
                decoded.push(source[at]);
                at += 1;
            }
        }
        (
            PathBuf::from(String::from_utf8(decoded).map_err(|_| Error::Unsupported)?),
            mode != Some("ro"),
            !matches!(mode, Some("rw" | "ro")),
        )
    } else {
        (input.to_owned(), true, true)
    };
    let path = if path.exists() {
        path.canonicalize().map_err(|_| Error::Unavailable)?
    } else {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        parent
            .canonicalize()
            .map_err(|_| Error::Unavailable)?
            .join(path.file_name().ok_or(Error::Unsupported)?)
    };
    Ok((path, writable, create))
}
pub(crate) struct Session {
    path: PathBuf,
    busy_ms: u64,
    writable: bool,
    frame_bytes: usize,
    pub inspection: Inspection,
    pub snapshot: Option<Snapshot>,
    coordination: Option<Coordination>,
    authority: Option<busbar_contract::Secret<Vec<u8>, Own>>,
}
impl Session {
    pub(crate) fn inspect(path: &Path, busy_ms: u64, frame_bytes: usize) -> Result<Self, Error> {
        if frame_bytes == 0 || frame_bytes > 64 * 1024 * 1024 {
            return Err(Error::Bounds);
        }
        let (path, writable, create) = configured_path(path)?;
        let empty = if path == Path::new(":memory:") {
            true
        } else {
            match std::fs::metadata(&path) {
                Ok(metadata) if !metadata.is_file() => return Err(Error::Unsupported),
                Ok(metadata) => metadata.len() == 0,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => true,
                Err(_) => return Err(Error::Unavailable),
            }
        };
        if empty {
            return Ok(Self {
                path,
                busy_ms,
                writable,
                frame_bytes,
                inspection: Inspection::Empty,
                snapshot: None,
                coordination: None,
                authority: None,
            });
        }
        let c = sql(Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ))?;
        sql(c.execute_batch("PRAGMA query_only=ON; BEGIN DEFERRED"))?;
        let catalog = catalogue(&c)?;
        let inspection = if catalog.is_empty() {
            if !uninitialized(&c)? {
                return Err(Error::Unsupported);
            }
            Inspection::Empty
        } else if catalog.iter().any(|o| o.name == CONTROL) {
            let d = load(&c)?;
            validate_durable(&c, &d)?;
            Inspection::InProgress(d.upgrade)
        } else {
            let version: i64 = sql(c.query_row("PRAGMA user_version", [], |r| r.get(0)))?;
            if known(&catalog, version).is_ok() {
                Inspection::Legacy {
                    physical: version,
                    descriptor: descriptor(&catalog, version, &path)?,
                }
            } else {
                if !current_schema(&c)? {
                    return Err(Error::Unsupported);
                }
                if whole_empty(&c)? {
                    Inspection::Empty
                } else {
                    Inspection::Current
                }
            }
        };
        Ok(Self {
            path,
            busy_ms,
            writable,
            frame_bytes,
            inspection,
            snapshot: None,
            coordination: None,
            authority: None,
        })
    }
    fn control(&self) -> Result<Connection, Error> {
        if !self.writable {
            return Err(Error::MissingCapability);
        }
        let access = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    Error::MissingCapability
                } else {
                    Error::Unavailable
                }
            })?;
        drop(access);
        if let Some(lock) = &self.coordination {
            lock.check()?;
        }
        let c = sql(Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ))?;
        sql(c.busy_timeout(std::time::Duration::from_millis(self.busy_ms)))?;
        sql(c.execute_batch("PRAGMA synchronous=FULL"))?;
        Ok(c)
    }
    pub(crate) fn begin(
        &mut self,
        expected: [u8; 32],
        route: [u8; 32],
        target_format: u32,
        operation: [u8; 16],
    ) -> Result<Upgrade, Error> {
        if operation == [0; 16] || route == [0; 32] || target_format != 1 {
            return Err(Error::Refused);
        }
        if self.coordination.is_none() {
            self.coordination = Some(Coordination::acquire(&self.path)?);
        }
        self.coordination.as_ref().ok_or(Error::Refused)?.check()?;
        if self.authority.is_none() {
            let mut token = zeroize::Zeroizing::new([0; 32]);
            getrandom::fill(&mut *token).map_err(|_| Error::Unavailable)?;
            self.authority = Some(busbar_contract::Secret::held(token.to_vec()));
        }
        let c = self.control()?;
        sql(c.execute_batch("BEGIN IMMEDIATE"))?;
        let cat = catalogue(&c)?;
        let durable = if cat.iter().any(|o| o.name == CONTROL) {
            let d = load(&c)?;
            validate_durable(&c, &d)?;
            if descriptor(&d.original, d.upgrade.source_physical, &self.path)? != expected {
                return Err(Error::Changed);
            }
            if d.upgrade.route != route || d.upgrade.target_format != target_format {
                return Err(Error::Refused);
            }
            d
        } else {
            let version: i64 = sql(c.query_row("PRAGMA user_version", [], |r| r.get(0)))?;
            known(&cat, version)?;
            if descriptor(&cat, version, &self.path)? != expected {
                return Err(Error::Changed);
            }
            // IMMEDIATE drains prior writers before these persistent guards become
            // visible. Failed old prepared/reconnected statements cannot escape them.
            for object in cat.iter().filter(|o| o.kind == "table") {
                for verb in ["INSERT", "UPDATE", "DELETE"] {
                    sql(c.execute_batch(&guard_sql(&object.name, verb)))?;
                }
            }
            sql(c.execute_batch(CONTROL_DDL))?;
            sql(c.execute_batch(crate::v4::DDL))?;
            let upgrade = Upgrade {
                operation,
                route,
                target_format,
                upgrade: random()?,
                source: expected[..16].try_into().map_err(|_| Error::Corrupt)?,
                target: random()?,
                atomic_domain: random()?,
                clock_authority: random()?,
                source_physical: version,
                frozen_digest: [0; 32],
                phase: 0,
            };
            for (key, value) in [
                ("dataset", upgrade.target.as_slice()),
                ("atomic_domain", upgrade.atomic_domain.as_slice()),
                ("clock_authority", upgrade.clock_authority.as_slice()),
                ("physical_format", 1u32.to_le_bytes().as_slice()),
            ] {
                sql(c.execute("INSERT INTO meta VALUES(?1,?2)", params![key, value]))?;
            }
            let reader = Snapshot::open(&self.path).map_err(|_| Error::Unsupported)?;
            let tables = reader.tables().to_vec();
            if reader.source_version() != version {
                return Err(Error::Changed);
            }
            drop(reader);
            let frozen_digest = source_digest(&c, &tables, self.frame_bytes)?;
            let upgrade = Upgrade {
                frozen_digest,
                ..upgrade
            };
            let guarded = catalogue(&c)?;
            sql(c.execute("INSERT INTO __busbar_upgrade VALUES(1,1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,0,NULL,NULL)",params![operation.as_slice(),route.as_slice(),target_format,upgrade.upgrade.as_slice(),upgrade.source.as_slice(),upgrade.target.as_slice(),upgrade.atomic_domain.as_slice(),upgrade.clock_authority.as_slice(),version,encode(&cat)?,encode(&guarded)?,frozen_digest.as_slice()]))?;
            Durable {
                upgrade,
                original: cat,
                guarded,
                activation: None,
                completion: None,
            }
        };
        c.execute_batch("COMMIT").map_err(|_| Error::Pending)?;
        // A retained reader cannot coexist with target commits in rollback mode.
        // Transition only after the old-write guards are durably committed; an
        // interrupted transition rejoins the same guarded upgrade on restart.
        let journal: String = sql(c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)))?;
        if journal != "wal" {
            return Err(Error::Refused);
        }
        self.snapshot = None;
        let snapshot = Snapshot::open_guarded(&self.path, TARGETS).map_err(|_| Error::Changed)?;
        let captured = load(&snapshot.conn)?;
        validate_durable(&snapshot.conn, &captured)?;
        if captured.upgrade != durable.upgrade
            || source_digest(&snapshot.conn, &snapshot.tables, self.frame_bytes)?
                != durable.upgrade.frozen_digest
        {
            return Err(Error::Changed);
        }
        self.inspection = Inspection::InProgress(durable.upgrade.clone());
        self.snapshot = Some(snapshot);
        Ok(durable.upgrade)
    }
    pub(crate) fn check(&self, id: [u8; 16]) -> Result<Upgrade, Error> {
        let c = self.control()?;
        let durable = load(&c)?;
        validate_durable(&c, &durable)?;
        if durable.upgrade.upgrade != id {
            return Err(Error::Refused);
        }
        if let Some(snapshot) = self.snapshot.as_ref() {
            let captured = load(&snapshot.conn)?;
            if captured.upgrade.upgrade != durable.upgrade.upgrade
                || captured.upgrade.source != durable.upgrade.source
                || captured.upgrade.frozen_digest != durable.upgrade.frozen_digest
            {
                return Err(Error::Changed);
            }
        } else if durable.upgrade.phase != 2 {
            return Err(Error::Refused);
        }
        Ok(durable.upgrade)
    }
    pub(crate) fn target(&self, id: [u8; 16]) -> Result<(Connection, Upgrade), Error> {
        let upgrade = self.check(id)?;
        let c = self.control()?;
        let current = load(&c)?;
        validate_durable(&c, &current)?;
        if current.upgrade != upgrade {
            return Err(Error::Changed);
        }
        Ok((c, upgrade))
    }
    /// The caller supplies the contract-owned activation validator; this native
    /// layer never guesses core checkpoint encodings or accepts receipt presence.
    pub(crate) fn finish(
        &mut self,
        id: [u8; 16],
        receipt: &[u8],
        complete: bool,
        validate: impl FnOnce(&Connection, &Upgrade, &[u8]) -> Result<(), Error>,
    ) -> Result<Upgrade, Error> {
        if receipt.is_empty() || receipt.len() > self.frame_bytes {
            return Err(Error::Bounds);
        }
        self.check(id)?;
        let c = self.control()?;
        sql(c.execute_batch("BEGIN IMMEDIATE"))?;
        let durable = load(&c)?;
        validate_durable(&c, &durable)?;
        if durable.upgrade.upgrade != id {
            return Err(Error::Refused);
        }
        let prior = if complete {
            &durable.completion
        } else {
            &durable.activation
        };
        if let Some(previous) = prior {
            if previous != receipt {
                return Err(Error::Refused);
            }
        }
        if complete && durable.upgrade.phase == 0 {
            return Err(Error::Refused);
        }
        validate(&c, &durable.upgrade, receipt)?;
        let phase = if complete {
            2
        } else {
            durable.upgrade.phase.max(1)
        };
        let statement = if complete {
            "UPDATE __busbar_upgrade SET phase=?1,completion=?2 WHERE id=1 AND upgrade=?3"
        } else {
            "UPDATE __busbar_upgrade SET phase=?1,activation=?2 WHERE id=1 AND upgrade=?3"
        };
        sql(c.execute(statement, params![phase, receipt, id.as_slice()]))?;
        c.execute_batch("COMMIT").map_err(|_| Error::Pending)?;
        let upgrade = Upgrade {
            phase,
            ..durable.upgrade
        };
        self.inspection = Inspection::InProgress(upgrade.clone());
        // Original rows remain immutable under durable guards. Release the
        // capture read transaction only after confirmed Complete so serving
        // commits can checkpoint WAL normally instead of retaining it forever.
        if complete {
            self.snapshot = None;
        }
        Ok(upgrade)
    }
}

impl Session {
    pub(crate) fn view(
        &self,
    ) -> Result<
        (
            busbar_contract::persistence::lifecycle::SourceIdentity,
            Vec<busbar_contract::persistence::archive::Table>,
        ),
        Error,
    > {
        self.view_kind(false)
    }
    pub(crate) fn frozen_view(
        &self,
    ) -> Result<
        (
            busbar_contract::persistence::lifecycle::SourceIdentity,
            Vec<busbar_contract::persistence::archive::Table>,
        ),
        Error,
    > {
        self.view_kind(true)
    }
    fn view_kind(
        &self,
        frozen: bool,
    ) -> Result<
        (
            busbar_contract::persistence::lifecycle::SourceIdentity,
            Vec<busbar_contract::persistence::archive::Table>,
        ),
        Error,
    > {
        use busbar_contract::persistence::{lifecycle, DatasetId};
        let c = sql(Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ))?;
        sql(c.execute_batch("BEGIN DEFERRED"))?;
        let (objects, physical, dataset) = match &self.inspection {
            Inspection::Legacy {
                physical,
                descriptor,
            } => (
                catalogue(&c)?,
                *physical,
                DatasetId(descriptor[..16].try_into().map_err(|_| Error::Corrupt)?),
            ),
            Inspection::InProgress(_) => {
                let d = load(&c)?;
                validate_durable(&c, &d)?;
                if d.upgrade.phase == 2 && !frozen {
                    (catalogue(&c)?, 1, DatasetId(d.upgrade.target))
                } else {
                    (
                        d.original,
                        d.upgrade.source_physical,
                        DatasetId(d.upgrade.source),
                    )
                }
            }
            Inspection::Current => {
                let id: Vec<u8> = sql(c.query_row(
                    "SELECT value FROM meta WHERE key='dataset'",
                    [],
                    |r| r.get(0),
                ))?;
                (catalogue(&c)?, 1, DatasetId(fixed(id)?))
            }
            Inspection::Empty => return Err(Error::Refused),
        };
        let mut tables = Vec::new();
        let original = encode(&objects)?;
        let mut layouts = Vec::new();
        for table in objects.iter().filter(|o| {
            o.kind == "table"
                && (if physical == 1 {
                    o.name != CONTROL && TARGETS.contains(&o.name.as_str())
                } else {
                    !TARGETS.contains(&o.name.as_str())
                })
        }) {
            let mut q = sql(c.prepare(&format!("PRAGMA table_xinfo({})", quote(&table.name))))?;
            let columns = sql(q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(5)?,
                ))
            }))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| Error::Corrupt)?;
            let mut primary = columns
                .iter()
                .filter(|column| column.3 > 0)
                .collect::<Vec<_>>();
            primary.sort_by_key(|column| column.3);
            let primary = primary
                .into_iter()
                .map(|column| column.0.clone())
                .collect::<Vec<_>>();
            let layout=serde_json::to_vec(&serde_json::json!({"version":1,"catalogue":serde_json::from_slice::<serde_json::Value>(&original).map_err(|_|Error::Corrupt)?,"columns":columns,"indexes":[{"ordinal":0,"origin":"primary-key","columns":primary}]})).map_err(|_|Error::Corrupt)?;
            if layout.len() > CATALOGUE_BYTES {
                return Err(Error::Bounds);
            }
            layouts.extend_from_slice(&digest(&layout));
            tables.push(busbar_contract::persistence::archive::Table {
                name: table.name.clone(),
                columns: columns.into_iter().map(|(name, _, _, _)| name).collect(),
                native_layout: layout,
            });
        }
        tables.sort_by(|a, b| a.name.cmp(&b.name));
        let current = physical == 1;
        Ok((
            lifecycle::SourceIdentity {
                native_anchor: descriptor(&objects, physical, &self.path)?,
                dataset,
                format: Some(lifecycle::Format {
                    owner: if current {
                        *b"busbar.core.v1\0\0"
                    } else {
                        crate::source_interpretation::SOURCE_OWNER
                    },
                    physical: physical as u32,
                    logical: 1,
                    codec: 1,
                }),
                catalogue_digest: digest(&original),
                layout_digest: digest(&layouts),
            },
            tables,
        ))
    }
    pub(crate) fn admission(&self) -> Result<Option<Vec<u8>>, Error> {
        if !matches!(
            self.inspection,
            Inspection::Current | Inspection::InProgress(Upgrade { phase: 1..=2, .. })
        ) {
            return Ok(None);
        }
        let c = sql(Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ))?;
        use rusqlite::OptionalExtension;
        sql(c
            .query_row(
                "SELECT value FROM records WHERE namespace=?1 AND key=?2",
                params![
                    busbar_contract::persistence::lifecycle::ADMISSION_NAMESPACE.as_slice(),
                    busbar_contract::persistence::lifecycle::ADMISSION_KEY
                ],
                |r| r.get(0),
            )
            .optional())
    }
    pub(crate) fn page<O: busbar_contract::redacted::OwnerSeal>(
        &self,
        request: &busbar_contract::persistence::lifecycle::Request<O>,
        owner: &O,
    ) -> Result<busbar_contract::persistence::lifecycle::SourcePage<O>, Error> {
        let busbar_contract::persistence::lifecycle::Request::SourcePage {
            upgrade,
            snapshot,
            family,
            selector,
            cursor,
            bounds,
        } = request
        else {
            return Err(Error::Refused);
        };
        let id = upgrade.id;
        let snapshot_id = *snapshot;
        let family = *family;
        let bounds = *bounds;
        let cursor = cursor.as_ref();
        use busbar_contract::persistence::lifecycle::{SourcePage, SourceRow, SourceSelector};
        let upgrade = self.check(id)?;
        if snapshot_id != upgrade.frozen_digest[..16] {
            return Err(Error::Changed);
        }
        if bounds.bytes <= 256
            || bounds.bytes > 64 * 1024 * 1024
            || bounds.items == 0
            || bounds.items > 4096
        {
            return Err(Error::Bounds);
        }
        let (table, prefix, exact) = match selector {
            SourceSelector::Interpret { reader, bounds } => {
                return self.interpreted_page(request, owner, *reader, *bounds);
            }
            SourceSelector::Scan { table } => (*table, None, false),
            SourceSelector::Exact { table, key } => (*table, Some(key), true),
            SourceSelector::IndexPrefix {
                table,
                index,
                prefix,
            } => {
                if *index != 0 {
                    return Err(Error::MissingCapability);
                }
                (*table, Some(prefix), false)
            }
        };
        if family != crate::source_interpretation::SOURCE_OWNER {
            return Err(Error::Refused);
        }
        let after = cursor.map(|v| busbar_contract::Secret::held(v.expose_own(owner).clone()));
        let prefix = prefix.map(|v| busbar_contract::Secret::held(v.expose_own(owner).clone()));
        let reopened;
        let source = if let Some(snapshot) = self.snapshot.as_ref() {
            snapshot
        } else {
            if upgrade.phase != 2 {
                return Err(Error::Refused);
            }
            reopened = Snapshot::open_guarded(&self.path, TARGETS).map_err(|_| Error::Changed)?;
            &reopened
        };
        let limits = super::Limits {
            rows: bounds.items as usize,
            bytes: (bounds.bytes as usize - 256) / 3,
        };
        let page = (if prefix.is_none() {
            source.page(table as usize, after.as_ref(), limits)
        } else {
            source.page_matching(
                table as usize,
                after.as_ref(),
                limits,
                prefix.as_ref(),
                exact,
            )
        })
        .map_err(|e| match e {
            super::Error::RowTooLarge => Error::Bounds,
            super::Error::InvalidCursor => Error::Refused,
            _ => Error::Corrupt,
        })?;
        let next = if page.exhausted {
            None
        } else {
            page.rows.last().map(|row| {
                busbar_contract::Secret::held(row.identity.expose_own(&Own::here()).clone())
            })
        };
        let mut coverage = upgrade.frozen_digest.to_vec();
        coverage.extend_from_slice(&family);
        coverage.extend_from_slice(&table.to_le_bytes());
        if let Some(cursor) = cursor {
            coverage.extend_from_slice(&digest(cursor.expose_own(owner)))
        }
        let rows = page
            .rows
            .into_iter()
            .map(|row| {
                coverage.extend_from_slice(&digest(row.identity.expose_own(&Own::here())));
                coverage.extend_from_slice(&digest(row.value.expose_own(&Own::here())));
                SourceRow {
                    table,
                    native_key: busbar_contract::Secret::held(
                        row.identity.expose_own(&Own::here()).clone(),
                    ),
                    value: busbar_contract::Secret::held(
                        row.value.expose_own(&Own::here()).clone(),
                    ),
                }
            })
            .collect();
        Ok(SourcePage {
            snapshot: snapshot_id,
            family,
            rows,
            next,
            source_digest: upgrade.frozen_digest,
            coverage_digest: digest(&coverage),
        })
    }
}

impl Session {
    pub(crate) fn enforcement(&self, id: [u8; 16]) -> Result<[u8; 32], Error> {
        self.check(id)?;
        let c = self.control()?;
        let guards = catalogue(&c)?
            .into_iter()
            .filter(|o| o.kind == "trigger" && o.name.starts_with("__busbar_freeze_"))
            .collect::<Vec<_>>();
        Ok(digest(&encode(&guards)?))
    }
    pub(crate) fn refresh_inspection(&mut self) -> Result<(), Error> {
        if self.authority.is_none() && self.coordination.is_none() {
            let mut fresh = Self::inspect(&self.path, self.busy_ms, self.frame_bytes)?;
            fresh.writable = self.writable;
            *self = fresh;
        }
        Ok(())
    }
    pub(crate) fn database_name(&self) -> &Path {
        &self.path
    }
    pub(crate) fn may_write(&self) -> bool {
        self.writable
    }
    pub(crate) fn authority(&self) -> Result<&[u8], Error> {
        self.authority
            .as_ref()
            .map(|a| a.expose_own(&Own::here()).as_slice())
            .ok_or(Error::Refused)
    }
    pub(crate) fn authenticate(&self, id: [u8; 16], authority: &[u8]) -> Result<Upgrade, Error> {
        if self.authority()? != authority {
            return Err(Error::Refused);
        }
        self.check(id)
    }
    pub(crate) fn selected(&self) -> Result<(Connection, Upgrade), Error> {
        let c = self.control()?;
        let d = load(&c)?;
        validate_durable(&c, &d)?;
        if d.upgrade.phase < 1 {
            return Err(Error::Refused);
        }
        Ok((c, d.upgrade))
    }
    pub(crate) fn ready(
        &self,
    ) -> Result<busbar_contract::persistence::lifecycle::RecoveryReady, Error> {
        let c = self.control()?;
        let d = load(&c)?;
        validate_durable(&c, &d)?;
        if d.upgrade.phase < 1 {
            return Err(Error::Refused);
        }
        let activation_receipt_digest = fixed(d.activation.ok_or(Error::Corrupt)?)?;
        let mut selector = d.upgrade.upgrade.to_vec();
        selector.extend_from_slice(&d.upgrade.target);
        selector.extend_from_slice(&activation_receipt_digest);
        Ok(busbar_contract::persistence::lifecycle::RecoveryReady {
            upgrade: d.upgrade.upgrade,
            target: busbar_contract::persistence::DatasetId(d.upgrade.target),
            activation_receipt_digest,
            selector_digest: digest(&selector),
        })
    }
}

#[cfg(test)]
#[path = "tests/lifecycle_native_tests.rs"]
mod tests;

impl Session {
    fn interpreted_page<O: busbar_contract::redacted::OwnerSeal>(
        &self,
        request: &busbar_contract::persistence::lifecycle::Request<O>,
        owner: &O,
        reader: busbar_contract::persistence::lifecycle::SourceReader,
        interpretation: busbar_contract::persistence::lifecycle::InterpretationBounds,
    ) -> Result<busbar_contract::persistence::lifecycle::SourcePage<O>, Error> {
        use busbar_contract::{persistence::lifecycle as l, Secret};
        let map = |error| match error {
            l::Error::Bounds => Error::Bounds,
            l::Error::UnsupportedFormat => Error::Unsupported,
            l::Error::SourceChanged => Error::Changed,
            _ => Error::Corrupt,
        };
        interpretation.validate().map_err(map)?;
        let l::Request::SourcePage {
            upgrade,
            snapshot,
            family,
            cursor,
            bounds,
            ..
        } = request
        else {
            return Err(Error::Refused);
        };
        if *family != l::INTERPRETED_SOURCE {
            return Err(Error::Refused);
        }
        let retained = self.check(upgrade.id)?;
        let (source, tables) = self.frozen_view()?;
        let physical = source.format.ok_or(Error::Corrupt)?.physical;
        if crate::source_interpretation::descriptor(physical).map_err(map)? != reader {
            return Err(Error::Changed);
        }
        crate::source_interpretation::validate_catalogue(physical, &tables).map_err(map)?;
        let charge = tables.iter().try_fold(
            tables
                .len()
                .checked_mul(std::mem::size_of::<
                    busbar_contract::persistence::archive::Table,
                >())
                .ok_or(Error::Bounds)?,
            |total, table| {
                total
                    .checked_add(table.name.capacity())
                    .and_then(|n| n.checked_add(table.native_layout.capacity()))
                    .and_then(|n| {
                        table.columns.iter().try_fold(n, |n, c| {
                            n.checked_add(c.capacity() + std::mem::size_of::<String>())
                        })
                    })
                    .ok_or(Error::Bounds)
            },
        )?;
        if charge > interpretation.index_bytes as usize {
            return Err(Error::Bounds);
        }
        let (mut table, mut position): (u32, Option<Secret<Vec<u8>, O>>) = if let Some(cursor) =
            cursor
        {
            let bytes = cursor.expose_own(owner);
            if bytes.len() < 41 || bytes[0] != 1 || bytes[1..33] != reader.decoder_digest() {
                return Err(Error::Refused);
            }
            let table = u32::from_le_bytes(bytes[33..37].try_into().map_err(|_| Error::Corrupt)?);
            let length =
                u32::from_le_bytes(bytes[37..41].try_into().map_err(|_| Error::Corrupt)?) as usize;
            if bytes.len() != 41usize.checked_add(length).ok_or(Error::Bounds)? {
                return Err(Error::Refused);
            }
            (
                table,
                (length != 0).then(|| Secret::held(bytes[41..].to_vec())),
            )
        } else {
            (0, None)
        };
        while (table as usize) < tables.len() {
            let raw = self.page(
                &l::Request::SourcePage {
                    upgrade: upgrade.clone(),
                    snapshot: *snapshot,
                    family: crate::source_interpretation::SOURCE_OWNER,
                    selector: l::SourceSelector::Scan { table },
                    cursor: position.take(),
                    bounds: l::Bounds {
                        items: 1,
                        bytes: interpretation.semantic_bytes.min(64 * 1024 * 1024),
                    },
                },
                owner,
            )?;
            let selected = table;
            position = raw.next;
            if position.is_none() {
                table = table.checked_add(1).ok_or(Error::Bounds)?;
            }
            if raw.rows.is_empty() {
                if position.is_some() {
                    return Err(Error::Corrupt);
                }
                continue;
            }
            if raw.rows.len() != 1 {
                return Err(Error::Corrupt);
            }
            let chunk = crate::source_interpretation::interpret(
                physical,
                &tables[selected as usize],
                &raw.rows[0],
                interpretation.semantic_bytes as usize,
                owner,
            )
            .map_err(map)?;
            let value = l::codec::encode_source_chunk_owned(
                &chunk,
                l::Bounds {
                    items: u32::MAX,
                    bytes: bounds.bytes.checked_sub(256).ok_or(Error::Bounds)?,
                },
            )
            .map_err(map)?;
            let next = if table as usize == tables.len() {
                None
            } else {
                let length = position.as_ref().map_or(0, |v| v.expose_own(owner).len());
                let capacity = 41usize.checked_add(length).ok_or(Error::Bounds)?;
                if capacity > bounds.bytes as usize {
                    return Err(Error::Bounds);
                }
                let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
                bytes.push(1);
                bytes.extend_from_slice(&reader.decoder_digest());
                bytes.extend_from_slice(&table.to_le_bytes());
                bytes.extend_from_slice(
                    &u32::try_from(length)
                        .map_err(|_| Error::Bounds)?
                        .to_le_bytes(),
                );
                if let Some(position) = &position {
                    bytes.extend_from_slice(position.expose_own(owner));
                }
                Some(Secret::held(std::mem::take(&mut *bytes)))
            };
            let mut coverage = busbar_contract::persistence::archive::Hasher::new();
            coverage.update(&retained.frozen_digest);
            coverage.update(&reader.decoder_digest());
            coverage.update(&raw.coverage_digest);
            coverage.update(value.expose_own(owner));
            return Ok(l::SourcePage {
                snapshot: *snapshot,
                family: *family,
                rows: vec![l::SourceRow {
                    table: 0,
                    native_key: chunk.group,
                    value,
                }],
                next,
                source_digest: retained.frozen_digest,
                coverage_digest: coverage.finish(),
            });
        }
        if table as usize != tables.len() {
            return Err(Error::Refused);
        }
        let mut coverage = busbar_contract::persistence::archive::Hasher::new();
        coverage.update(&retained.frozen_digest);
        coverage.update(&reader.decoder_digest());
        Ok(l::SourcePage {
            snapshot: *snapshot,
            family: *family,
            rows: vec![],
            next: None,
            source_digest: retained.frozen_digest,
            coverage_digest: coverage.finish(),
        })
    }
}
