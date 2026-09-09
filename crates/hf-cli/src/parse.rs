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
    let (number, multiplier) = if let Some(number) = s.strip_suffix('s') {
        (number, 1)
    } else if let Some(number) = s.strip_suffix('m') {
        (number, 60)
    } else if let Some(number) = s.strip_suffix('h') {
        (number, 3600)
    } else {
        (s, 1)
    };
    number
        .parse::<u64>()?
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("duration exceeds supported seconds range"))
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

#[cfg(test)]
mod duration_tests {
    use super::parse_duration;

    #[test]
    fn duration_conversion_rejects_values_that_exceed_seconds_capacity() {
        for (suffix, multiplier) in [('m', 60_u64), ('h', 3600)] {
            let too_large = u64::MAX / multiplier + 1;
            let error = parse_duration(&format!("{too_large}{suffix}")).unwrap_err();
            assert!(error.to_string().contains("duration exceeds"));
        }
    }

    #[test]
    fn duration_conversion_preserves_the_largest_representable_values() {
        for (suffix, multiplier) in [("", 1_u64), ("s", 1), ("m", 60), ("h", 3600)] {
            let value = u64::MAX / multiplier;
            assert_eq!(
                parse_duration(&format!(" {value}{suffix} ")).unwrap(),
                value * multiplier,
            );
        }
    }
}
