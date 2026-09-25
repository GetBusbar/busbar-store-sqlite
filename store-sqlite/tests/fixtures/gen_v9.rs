// NOT COMPILED BY THIS CRATE — provenance for tests/fixtures/v9-origin-dev.db.
//
// That database file was written by THIS program running as an example of store-sqlite origin/dev 08b8031 (schema v9, never released) built against busbar eac13fa3f (its .busbar-ref pin):
//   cargo run -p busbar-store-sqlite --example gen_fixture -- v9-origin-dev.db
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
    for (id, state, upd) in [("task_active", "input-required", 1_700_000_100u64), ("task_done", "completed", 1_700_000_200)] {
        s.put_task(&TaskRow { task_id: id.into(), context_id: "ctx1".into(), principal: "vk_live".into(), direction: "inbound".into(),
            state: state.into(), agent_id: "agent1".into(), artifact_cursor: 3, push_callback: "https://cb.example/x".into(),
            created_at: 1_700_000_000, updated_at: upd }).unwrap();
    }
    for seq in 1..=2u64 {
        s.append_task_event(&TaskEventRow { task_id: "task_active".into(), seq, ts: 1_700_000_000 + seq, kind: "task.working".into(),
            context_id: "ctx1".into(), principal: "vk_live".into(), agent_id: "agent1".into(), state: "working".into(),
            request_id: format!("req-{seq}"), prev_hash: if seq == 1 { String::new() } else { "e1".into() }, hash: format!("e{seq}") }).unwrap();
    }
    s.append_mcp_call(&McpCallRecord { principal: "vk_live".into(), seq: 1, ts: 1_700_000_050, server: "srv".into(), tool: "srv_do".into(),
        outcome: "dispatched".into(), reason: String::new(), tool_digest: "sha256:d".into(), pin_generation: 1,
        request_id: "req-c1".into(), prev_hash: String::new(), hash: "c1".into() }).unwrap();
    s.put_mcp_demotion(&McpDemotionRow { server: "srv_bad".into(), reason: "drift".into(), recorded_at: 1_700_000_060 }).unwrap();
    assert!(s.redeem_ask_state("nonce_spent", 4_000_000_000, 1_700_000_000).unwrap());
    drop(s);
}
