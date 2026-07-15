//! Plugin error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("unsupported container format")]
    UnsupportedFormat,

    #[error("malformed container: {0}")]
    Malformed(String),

    #[error("decryption failed: {0}")]
    Decrypt(String),

    #[error("XML parse error: {0}")]
    Xml(String),

    #[error("resource limit exceeded for {resource} (maximum {limit})")]
    LimitExceeded {
        resource: &'static str,
        limit: usize,
    },

    #[error("base64 decode error: {0}")]
    Base64(String),

    #[error("hex decode error: {0}")]
    Hex(String),

    #[error("UTF-8 decode error: {0}")]
    Utf8(String),

    #[error("missing required field: {0}")]
    MissingField(&'static str),
}

impl From<base64::DecodeError> for PluginError {
    fn from(e: base64::DecodeError) -> Self {
        Self::Base64(e.to_string())
    }
}

impl From<hex::FromHexError> for PluginError {
    fn from(e: hex::FromHexError) -> Self {
        Self::Hex(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for PluginError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::Utf8(e.to_string())
    }
}

impl From<std::str::Utf8Error> for PluginError {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::Utf8(e.to_string())
    }
}

impl From<quick_xml::Error> for PluginError {
    fn from(e: quick_xml::Error) -> Self {
        Self::Xml(e.to_string())
    }
}

impl From<quick_xml::events::attributes::AttrError> for PluginError {
    fn from(e: quick_xml::events::attributes::AttrError) -> Self {
        Self::Xml(e.to_string())
    }
}

impl From<quick_xml::encoding::EncodingError> for PluginError {
    fn from(e: quick_xml::encoding::EncodingError) -> Self {
        Self::Xml(e.to_string())
    }
}

impl From<quick_xml::escape::EscapeError> for PluginError {
    fn from(e: quick_xml::escape::EscapeError) -> Self {
        Self::Xml(e.to_string())
    }
}
