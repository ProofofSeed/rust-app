// SPDX-License-Identifier: LGPL-3.0-or-later

//! BIP-32 path and child-index parsing and formatting.

pub const HARDENED: u32 = 0x8000_0000;

pub fn parse_component(s: &str) -> Result<u32, String> {
    let (digits, hardened) =
        if let Some(d) = s.strip_suffix('\'').or_else(|| s.strip_suffix(['h', 'H'])) {
            (d, true)
        } else {
            (s, false)
        };
    let value: u32 = digits
        .parse()
        .map_err(|_| format!("invalid path component {s:?}"))?;
    if value >= HARDENED {
        return Err(format!("path component {value} out of range (must be < 2^31)"));
    }
    Ok(if hardened { HARDENED | value } else { value })
}

pub fn parse_path(s: &str) -> Result<Vec<u32>, String> {
    let s = s.trim();
    let rest = s
        .strip_prefix("m/")
        .or_else(|| s.strip_prefix("M/"))
        .or_else(|| (s == "m" || s == "M").then_some(""))
        .ok_or_else(|| format!("path {s:?} must start with m/"))?;
    if rest.is_empty() {
        return Ok(Vec::new());
    }
    rest.split('/').map(parse_component).collect()
}

pub fn format_path(path: &[u32]) -> String {
    let mut s = String::from("m");
    for &c in path {
        s.push('/');
        s.push_str(&(c & !HARDENED).to_string());
        if c & HARDENED != 0 {
            s.push('\'');
        }
    }
    s
}

pub fn format_component(index: u32) -> String {
    let mut s = (index & !HARDENED).to_string();
    if index & HARDENED != 0 {
        s.push('\'');
    }
    s
}
