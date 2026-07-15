use quick_xml::events::{BytesRef, BytesText};

use crate::error::PluginError;

pub(crate) fn decode_text(text: &BytesText<'_>) -> Result<String, PluginError> {
    Ok(text.decode()?.into_owned())
}

pub(crate) fn decode_reference(reference: &BytesRef<'_>) -> Result<String, PluginError> {
    if let Some(character) = reference.resolve_char_ref()? {
        return Ok(character.to_string());
    }

    let name = reference.decode()?;
    quick_xml::escape::resolve_predefined_entity(&name)
        .map(str::to_string)
        .ok_or_else(|| PluginError::Xml(format!("unsupported entity reference '&{name};'")))
}
