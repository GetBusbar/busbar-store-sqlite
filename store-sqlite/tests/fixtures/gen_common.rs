// Provenance: shared helpers for the upgrade fixtures (see gen_v6.rs / gen_v9.rs).
use busbar_api::*;
use busbar_store_sqlite::SqliteStore;

pub fn key(id: &str, pools: Option<Vec<&str>>) -> VirtualKey {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert("team".to_string(), "growth".to_string());
    VirtualKey {
        id: id.into(),
        generation_hash: format!("binding:{id}:g1"),
        name: format!("fixture {id}"),
        allowed_scopes: pools.map(|p| p.into_iter().map(ScopeRef::pool).collect()),
        enabled: true,
        created_at: 1_700_000_000,
        group: Some("eng".into()),
        labels,
        expires_at: Some(1_900_000_000),
        deleted_at: None,
        revision: 0,
    }
}

pub fn common(s: &SqliteStore) {
    s.put_key(&key("vk_live", Some(vec!["fast", "slow"]))).unwrap();
    s.put_key(&key("vk_all", None)).unwrap();
    s.put_key(&key("vk_none", Some(vec![]))).unwrap();
    s.put_key(&key("vk_dead", None)).unwrap();
    s.put_credential(&CredentialSecret {
        meta: CredentialMeta {
            id: "cred_1".into(), key_id: "vk_live".into(), kind: "sigv4".into(), slot: 0,
            public_id: "AKIAFIXTURE1".into(), secret_form: SecretForm::Recoverable,
            created_at: 1_700_000_000, updated_at: 1_700_000_001, expires_at: None,
            revoked_at: None, revoke_reason: None, revision: 0,
        },
        secret: "v1:plain:fixture-secret".into(),
    }).unwrap();
    s.delete_key("vk_dead").unwrap();
    s.add_denylist("vk_revoked_sub", "leaked").unwrap();
    s.append_audit(&AuditRecord { seq: 1, ts: 1_700_000_000, action: "hook.register".into(),
        resource: "hook:x".into(), outcome: "applied".into(), principal: "admin".into(),
        prev_hash: String::new(), hash: "h1".into() }).unwrap();
    s.append_audit(&AuditRecord { seq: 2, ts: 1_700_000_005, action: "plugin.install".into(),
        resource: "plugin:y".into(), outcome: "applied".into(), principal: "admin".into(),
        prev_hash: "h1".into(), hash: "h2".into() }).unwrap();
}
