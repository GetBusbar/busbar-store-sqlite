// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "../../testing/settings/integer_token.rs"]
mod settings_profile;

use busbar_contract::abi::sdk::store::StoreSlots;

#[test]
fn settings_schema_matches_lifecycle_shapes() {
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("settings.schema.json")).expect("schema JSON");
    let validator = settings_profile::validator(&schema).expect("valid settings schema");
    let cases: &[(&str, bool)] = &[
        (r#"{}"#, true),
        (r#"null"#, true),
        (r#"{"db_path":null,"busy_timeout_ms":null}"#, true),
        (r#"{"db_path":":memory:","busy_timeout_ms":0}"#, true),
        (r#"{"busy_timeout_ms":2147483647}"#, true),
        (r#"{"license_key":[]}"#, false),
        (r#"{"db_path":" "}"#, false),
        (r#"{"db_path":1}"#, false),
        (r#"{"busy_timeout_ms":-1}"#, false),
        (r#"{"busy_timeout_ms":2147483648}"#, false),
        (r#"{"busy_timeout_ms":1.5}"#, false),
        (r#"{"unknown":0}"#, false),
        (r#"[]"#, false),
    ];
    for &(text, accepted) in cases {
        let value: serde_json::Value = serde_json::from_str(text).expect("case JSON");
        assert_eq!(validator.is_valid(&value), accepted, "schema: {text}");
        assert_eq!(
            <crate::SqliteStore as StoreSlots>::validate(text.as_bytes()).is_ok(),
            accepted,
            "lifecycle: {text}"
        );
    }
    assert!(<crate::SqliteStore as StoreSlots>::validate(b"").is_ok());
}

#[test]
fn settings_schema_defaults_match_parser() {
    let settings = super::Settings::parse("{}").expect("defaults");
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("settings.schema.json")).unwrap();
    assert_eq!(schema["properties"]["db_path"]["default"], settings.db_path);
    assert_eq!(
        schema["properties"]["busy_timeout_ms"]["default"],
        settings.busy_timeout_ms
    );
    assert_eq!(super::Settings::parse("null").unwrap(), settings);
    assert_eq!(
        super::Settings::parse(r#"{"db_path":null,"busy_timeout_ms":null}"#).unwrap(),
        settings
    );
}

#[test]
fn settings_schema_has_no_unused_license_setting() {
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("settings.schema.json")).unwrap();
    assert!(schema["properties"].get("license_key").is_none());
}

#[test]
fn settings_schema_integer_tokens_match_native_parser() {
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("settings.schema.json")).unwrap();
    let profile = settings_profile::validator(&schema).unwrap();
    let standard = jsonschema::validator_for(&schema).unwrap();
    assert_eq!(schema["x-busbar-settings-profile"], "integer-token-v1");
    for (pointer, template, integer, kind) in [(
        r#"/properties/busy_timeout_ms"#,
        r#"{"busy_timeout_ms":TOKEN}"#,
        "1",
        "signed",
    )] {
        assert_eq!(
            schema.pointer(pointer).unwrap()["x-busbar-integer-token"],
            kind
        );
        for (token, accepted) in [
            (integer.to_string(), true),
            (format!("{integer}.0"), false),
            (format!("{integer}e0"), false),
            (format!("{integer}E+0"), false),
        ] {
            let text = template.replace("TOKEN", &token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(
                standard.is_valid(&value),
                "standard mathematical integer: {text}"
            );
            assert_eq!(profile.is_valid(&value), accepted, "profile: {text}");
            assert_eq!(
                <crate::SqliteStore as StoreSlots>::validate(text.as_bytes()).is_ok(),
                accepted,
                "native: {text}"
            );
        }
        // Do not infer signed negative-zero behavior from a regular expression:
        // the profile must agree with the actual lifecycle parser.
        for token in [
            "null",
            "0",
            "-0",
            "-0.0",
            "0e0",
            "-1",
            "18446744073709551616",
        ] {
            let text = template.replace("TOKEN", token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                profile.is_valid(&value),
                <crate::SqliteStore as StoreSlots>::validate(text.as_bytes()).is_ok(),
                "native sign/range: {text}"
            );
        }
    }
}
