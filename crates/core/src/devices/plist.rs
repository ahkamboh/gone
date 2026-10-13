//! A small XML property-list reader for `diskutil -plist` output.
//!
//! It understands the subset diskutil emits: dict, array, key, string,
//! integer, real, true, false, date, and data. It is not a general plist
//! library.

use std::fmt;

/// One value in a property list.
#[derive(Debug, Clone, PartialEq)]
pub enum Plist {
    Dict(Vec<(String, Plist)>),
    Array(Vec<Plist>),
    String(String),
    Integer(i128),
    Real(String),
    Boolean(bool),
    Date(String),
    Data(String),
}

impl Plist {
    pub fn as_dict(&self) -> Option<&[(String, Plist)]> {
        match self {
            Plist::Dict(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Plist]> {
        match self {
            Plist::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Plist::String(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Plist::Boolean(value) => Some(*value),
            _ => None,
        }
    }

    /// Non-negative integers. Disk sizes fit; a negative value is absent.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Plist::Integer(value) if *value >= 0 && *value <= u64::MAX as i128 => {
                Some(*value as u64)
            }
            _ => None,
        }
    }
}

pub fn dict_get<'a>(dict: &'a [(String, Plist)], key: &str) -> Option<&'a Plist> {
    dict.iter().find(|(k, _)| k == key).map(|(_, value)| value)
}

#[derive(Debug)]
pub struct ParseError {
    pub message: String,
    pub position: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.position)
    }
}

struct Parser<'a> {
    input: &'a str,
    index: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, index: 0 }
    }

    fn rest(&self) -> &'a str {
        &self.input[self.index..]
    }

    fn starts_with(&self, prefix: &str) -> bool {
        self.rest().starts_with(prefix)
    }

    fn bump(&mut self, n: usize) {
        self.index += n;
    }

    fn error(&self, message: impl Into<String>) -> ParseError {
        ParseError {
            message: message.into(),
            position: self.index,
        }
    }

    fn skip_ws(&mut self) {
        let bytes = self.rest().as_bytes();
        let mut n = 0;
        while n < bytes.len() && matches!(bytes[n], b' ' | b'\t' | b'\n' | b'\r') {
            n += 1;
        }
        self.bump(n);
    }

    fn skip_until(&mut self, marker: &str) -> Result<(), ParseError> {
        if let Some(at) = self.rest().find(marker) {
            self.bump(at + marker.len());
            Ok(())
        } else {
            Err(self.error(format!("missing {marker}")))
        }
    }

    fn skip_preamble(&mut self) -> Result<(), ParseError> {
        loop {
            self.skip_ws();
            if self.starts_with("<?") {
                self.skip_until("?>")?;
                continue;
            }
            if self.starts_with("<!--") {
                self.skip_until("-->")?;
                continue;
            }
            if self.starts_with("<!DOCTYPE") || self.starts_with("<!doctype") {
                self.skip_until(">")?;
                continue;
            }
            if self.starts_with("<plist") {
                self.skip_until(">")?;
                continue;
            }
            break;
        }
        Ok(())
    }

    fn parse_text_until(&mut self, end: &str) -> Result<String, ParseError> {
        let Some(at) = self.rest().find(end) else {
            return Err(self.error(format!("missing {end}")));
        };
        let raw = &self.rest()[..at];
        self.bump(at + end.len());
        decode_entities(raw).map_err(|message| self.error(message))
    }

    fn parse_value(&mut self) -> Result<Plist, ParseError> {
        self.skip_ws();
        if self.starts_with("<dict>") || self.starts_with("<dict ") || self.starts_with("<dict/>") {
            return self.parse_dict();
        }
        if self.starts_with("<array>")
            || self.starts_with("<array ")
            || self.starts_with("<array/>")
        {
            return self.parse_array();
        }
        if self.starts_with("<string/>") || self.starts_with("<string />") {
            self.bump(if self.starts_with("<string/>") { 9 } else { 10 });
            return Ok(Plist::String(String::new()));
        }
        if self.starts_with("<string>") || self.starts_with("<string ") {
            self.skip_until(">")?;
            return Ok(Plist::String(self.parse_text_until("</string>")?));
        }
        if self.starts_with("<integer>") || self.starts_with("<integer ") {
            self.skip_until(">")?;
            let text = self.parse_text_until("</integer>")?;
            let value = text
                .trim()
                .parse::<i128>()
                .map_err(|_| self.error(format!("bad integer {}", text.trim())))?;
            return Ok(Plist::Integer(value));
        }
        if self.starts_with("<real>") || self.starts_with("<real ") {
            self.skip_until(">")?;
            return Ok(Plist::Real(self.parse_text_until("</real>")?));
        }
        if self.starts_with("<date>") || self.starts_with("<date ") {
            self.skip_until(">")?;
            return Ok(Plist::Date(self.parse_text_until("</date>")?));
        }
        if self.starts_with("<data>") || self.starts_with("<data ") {
            self.skip_until(">")?;
            return Ok(Plist::Data(self.parse_text_until("</data>")?));
        }
        if self.starts_with("<true/>") || self.starts_with("<true />") {
            self.bump(if self.starts_with("<true/>") { 7 } else { 8 });
            return Ok(Plist::Boolean(true));
        }
        if self.starts_with("<false/>") || self.starts_with("<false />") {
            self.bump(if self.starts_with("<false/>") { 8 } else { 9 });
            return Ok(Plist::Boolean(false));
        }
        if self.starts_with("<true>") {
            self.skip_until("</true>")?;
            return Ok(Plist::Boolean(true));
        }
        if self.starts_with("<false>") {
            self.skip_until("</false>")?;
            return Ok(Plist::Boolean(false));
        }
        Err(self.error(format!(
            "unexpected plist markup starting {}",
            self.rest().chars().take(24).collect::<String>()
        )))
    }

    fn parse_dict(&mut self) -> Result<Plist, ParseError> {
        self.skip_ws();
        if self.starts_with("<dict/>") || self.starts_with("<dict />") {
            self.bump(if self.starts_with("<dict/>") { 7 } else { 8 });
            return Ok(Plist::Dict(Vec::new()));
        }
        self.skip_until(">")?;
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.starts_with("</dict>") {
                self.bump(7);
                break;
            }
            if self.starts_with("<key>") || self.starts_with("<key ") {
                self.skip_until(">")?;
                let key = self.parse_text_until("</key>")?;
                let value = self.parse_value()?;
                items.push((key, value));
                continue;
            }
            return Err(self.error("expected a key or the end of a dict"));
        }
        Ok(Plist::Dict(items))
    }

    fn parse_array(&mut self) -> Result<Plist, ParseError> {
        self.skip_ws();
        if self.starts_with("<array/>") || self.starts_with("<array />") {
            self.bump(if self.starts_with("<array/>") { 8 } else { 9 });
            return Ok(Plist::Array(Vec::new()));
        }
        self.skip_until(">")?;
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.starts_with("</array>") {
                self.bump(8);
                break;
            }
            items.push(self.parse_value()?);
        }
        Ok(Plist::Array(items))
    }
}

pub fn parse_plist(input: &str) -> Result<Plist, ParseError> {
    let mut parser = Parser::new(input);
    parser.skip_preamble()?;
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.starts_with("</plist>") {
        parser.bump(8);
    }
    Ok(value)
}

fn decode_entities(raw: &str) -> Result<String, String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(end) = rest.find(';') else {
            return Err("unterminated entity".to_string());
        };
        let entity = &rest[1..end];
        let ch = match entity {
            "amp" => "&".to_string(),
            "lt" => "<".to_string(),
            "gt" => ">".to_string(),
            "quot" => "\"".to_string(),
            "apos" => "'".to_string(),
            other if other.starts_with('#') => decode_numeric(other)?,
            other => return Err(format!("unknown entity {other}")),
        };
        out.push_str(&ch);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn decode_numeric(entity: &str) -> Result<String, String> {
    let code = if let Some(hex) = entity
        .strip_prefix("#x")
        .or_else(|| entity.strip_prefix("#X"))
    {
        u32::from_str_radix(hex, 16)
    } else if let Some(dec) = entity.strip_prefix('#') {
        dec.parse::<u32>()
    } else {
        return Err(format!("bad numeric entity {entity}"));
    }
    .map_err(|_| format!("bad numeric entity {entity}"))?;
    char::from_u32(code)
        .map(|ch| ch.to_string())
        .ok_or_else(|| format!("bad numeric entity {entity}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_diskutil_shape() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>DeviceIdentifier</key>
	<string>disk0</string>
	<key>Size</key>
	<integer>2001111162880</integer>
	<key>Internal</key>
	<true/>
	<key>SolidState</key>
	<false />
	<key>MountPoint</key>
	<string></string>
	<key>VolumeName</key>
	<string>Tom &amp; Jerry&#39;s</string>
	<key>SMART</key>
	<dict>
		<key>AVAILABLE_SPARE</key>
		<integer>100</integer>
	</dict>
	<key>Partitions</key>
	<array>
		<dict>
			<key>DeviceIdentifier</key>
			<string>disk0s1</string>
		</dict>
	</array>
</dict>
</plist>"#;
        let plist = parse_plist(xml).unwrap();
        let dict = plist.as_dict().unwrap();
        assert_eq!(
            dict_get(dict, "DeviceIdentifier").unwrap().as_str(),
            Some("disk0")
        );
        assert_eq!(
            dict_get(dict, "Size").unwrap().as_u64(),
            Some(2001111162880)
        );
        assert_eq!(dict_get(dict, "Internal").unwrap().as_bool(), Some(true));
        assert_eq!(dict_get(dict, "SolidState").unwrap().as_bool(), Some(false));
        assert_eq!(dict_get(dict, "MountPoint").unwrap().as_str(), Some(""));
        assert_eq!(
            dict_get(dict, "VolumeName").unwrap().as_str(),
            Some("Tom & Jerry's")
        );
        let parts = dict_get(dict, "Partitions").unwrap().as_array().unwrap();
        assert_eq!(parts.len(), 1);
    }
}
