use hf_service::{EngineKind, TargetLanguage};

pub(crate) fn parse_lang(s: &str) -> Result<TargetLanguage, anyhow::Error> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

pub(crate) fn parse_engine(s: &str) -> Result<EngineKind, anyhow::Error> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

/// Parse a human duration string like "60m", "2h", "30s".
pub(crate) fn parse_duration(s: &str) -> Result<u64, anyhow::Error> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        return Ok(n.parse()?);
    }
    if let Some(n) = s.strip_suffix('m') {
        return Ok(n.parse::<u64>()? * 60);
    }
    if let Some(n) = s.strip_suffix('h') {
        return Ok(n.parse::<u64>()? * 3600);
    }
    // Fallback: parse as raw seconds.
    Ok(s.parse()?)
}

/// Parse a comma-separated list of unsigned integers, each decimal or `0x` hex.
#[cfg(feature = "automotive-scapy")]
pub(crate) fn parse_u32_list(input: &str) -> anyhow::Result<Vec<u32>> {
    input
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(|token| {
            token
                .strip_prefix("0x")
                .or_else(|| token.strip_prefix("0X"))
                .map_or_else(|| token.parse::<u32>(), |hex| u32::from_str_radix(hex, 16))
                .map_err(|_| anyhow::anyhow!("invalid integer '{token}'"))
        })
        .collect()
}
