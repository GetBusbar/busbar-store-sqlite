// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

fn main() -> std::io::Result<()> {
    use std::path::PathBuf;
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"))
        .canonicalize()?;
    let package = std::env::var("CARGO_PKG_NAME").expect("package name");
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("output dir"));
    let mut body = String::new();
    for (name, module) in [
        (
            "credential_flush_response_actual",
            "admin_application_credential_flush_response_actual",
        ),
        (
            "external_accepted_events",
            "kernel_application_external_accepted_events",
        ),
        ("misc_boot", "misc_boot"),
    ] {
        let source = manifest.join(format!("tests/application/{name}.rs"));
        if source.canonicalize()? != source {
            return Err(std::io::Error::other(
                "test source must be the owner's own declared path, without symlink escapes",
            ));
        }
        body.push_str(&format!(
            "        #[path = {source:?}]\n        mod {module};\n"
        ));
        println!("cargo::rerun-if-changed={}", source.display());
    }
    std::fs::write(
        output.join("context_test_source.rs"),
        format!(
            "#[doc(hidden)]\n#[macro_export]\nmacro_rules! __busbar_context_tests {{\n    \
             (sqlite_application, {package:?}) => {{\n{body}    }};\n}}\n"
        ),
    )?;
    println!(
        "cargo::rerun-if-changed={}",
        manifest.join("Cargo.toml").display()
    );
    Ok(())
}
