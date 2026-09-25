// NOT COMPILED BY THIS CRATE — provenance for tests/fixtures/v6-release-1.0.6.db.
//
// That database file was written by THIS program running as an example of store-sqlite v1.0.6 (the latest RELEASE, schema v6) built against busbar a71b21e9f (1.5.5):
//   cargo run -p busbar-store-sqlite --example gen_fixture -- v6-release-1.0.6.db
// It is kept byte-for-byte as that code left it so the upgrade test opens a database the old code
// really produced, not one this build imagines the old code would have produced.
#[path = "gen_common.rs"]
mod common;
use busbar_api::*;
use busbar_store_sqlite::SqliteStore;
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let s = SqliteStore::open(&path, 5000).unwrap();
    common::common(&s);
    s.add_usage("vk_live", 1_700_000_000, &UsageDelta { requests: 7, billable_requests: 6, models: vec![
        ModelTokensDelta { model: "gpt-x".into(), tokens: TierTokensDelta { input: 100, output: 50, cache_read: 10, cache_write: 5 } },
        ModelTokensDelta { model: "claude-y".into(), tokens: TierTokensDelta { input: 1, output: 2, cache_read: 3, cache_write: 4 } },
    ]}).unwrap();
    s.add_metering(&MeteringDelta { key_id: "vk_live".into(), bucket: 1_699_920_000, model: "gpt-x".into(), provider: "openai".into(),
        tokens_input: 100, tokens_output: 50, tokens_cache_read: 10, tokens_cache_write: 5, requests: 7, billable_requests: 6,
        key_group_at_use: "eng".into(), pricing_version: "v3".into() }).unwrap();
    drop(s);
}
