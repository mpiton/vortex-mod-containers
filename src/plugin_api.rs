//! WASM-only entry points: `#[plugin_fn]` exports.
//!
//! The container plugin does not import any host functions — all decoding is
//! pure (bytes in, JSON out). The host invokes these after the user drops a
//! `.dlc` / `.ccf` / `.rsdf` / `.metalink` / `.meta4` file into the Link
//! Grabber.

use extism_pdk::*;

use crate::error::PluginError;

#[plugin_fn]
pub fn can_decrypt(input: Vec<u8>) -> FnResult<String> {
    Ok(if crate::can_decrypt(&input) {
        "true".into()
    } else {
        "false".into()
    })
}

#[plugin_fn]
pub fn detect(input: Vec<u8>) -> FnResult<String> {
    let resp = crate::detect(&input);
    Ok(serde_json::to_string(&resp).map_err(json_err)?)
}

#[plugin_fn]
pub fn decrypt(input: Vec<u8>) -> FnResult<String> {
    let resp = crate::decrypt(&input).map_err(plugin_err)?;
    Ok(serde_json::to_string(&resp).map_err(json_err)?)
}

fn plugin_err(e: PluginError) -> WithReturnCode<Error> {
    Error::msg(e.to_string()).into()
}

fn json_err(e: serde_json::Error) -> WithReturnCode<Error> {
    Error::msg(e.to_string()).into()
}
