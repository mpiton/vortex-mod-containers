//! ABI smoke test for the release WASM artifact.

use std::path::PathBuf;

const WASM_REL_PATH: &str = "target/wasm32-wasip1/release/vortex_mod_containers.wasm";
const METALINK: &[u8] = br#"<metalink><file name="demo.bin"><size>42</size><url>https://example.com/demo.bin</url></file></metalink>"#;

fn load_plugin() -> extism::Plugin {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(WASM_REL_PATH);
    assert!(
        path.is_file(),
        "missing release WASM artifact; run `cargo build --target wasm32-wasip1 --release` first"
    );
    let manifest = extism::Manifest::new([extism::Wasm::file(path)]);
    extism::Plugin::new(&manifest, Vec::<extism::Function>::new(), true)
        .expect("load Containers WASM")
}

#[test]
fn wasm_container_exports_are_callable() {
    let mut plugin = load_plugin();
    let can_decrypt: String = plugin.call("can_decrypt", METALINK).expect("can_decrypt");
    let detect: String = plugin.call("detect", METALINK).expect("detect");
    let decrypt: String = plugin.call("decrypt", METALINK).expect("decrypt");
    let detect: serde_json::Value = serde_json::from_str(&detect).expect("detect JSON");
    let decrypt: serde_json::Value = serde_json::from_str(&decrypt).expect("decrypt JSON");

    assert_eq!(can_decrypt.trim(), "true");
    assert_eq!(detect["format"], "metalink");
    assert_eq!(decrypt["format"], "metalink");
    assert_eq!(decrypt["links"][0]["url"], "https://example.com/demo.bin");
}
