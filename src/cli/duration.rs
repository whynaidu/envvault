//! Human-friendly duration parsing shared across commands.
//!
//! Accepts `N<unit>` strings where `<unit>` is one of:
//!
//! | Unit | Meaning         |
//! |------|-----------------|
//! | `m`  | minutes         |
//! | `h`  | hours           |
//! | `d`  | days            |
//! | `w`  | weeks (7 days)  |
//! | `y`  | years (365 days)|
//!
//! Examples: `30m`, `24h`, `7d`, `2w`, `1y`.
//!
//! Returns a `chrono::Duration`. Callers add or subtract it from
//! `Utc::now()` depending on whether they need a past point (`audit
//! --since`) or a future point (`set --expires`).

use chrono::Duration;

use crate::errors::{EnvVaultError, Result};

/// Parse a duration string into a `chrono::Duration`.
///
/// Accepts a positive integer followed by a unit character from
/// `[m, h, d, w, y]`. Whitespace is trimmed.
pub fn parse_delta(input: &str) -> Result<Duration> {
    let input = input.trim();

    let (num_str, unit) = if let Some(s) = input.strip_suffix('y') {
        (s, 'y')
    } else if let Some(s) = input.strip_suffix('w') {
        (s, 'w')
    } else if let Some(s) = input.strip_suffix('d') {
        (s, 'd')
    } else if let Some(s) = input.strip_suffix('h') {
        (s, 'h')
    } else if let Some(s) = input.strip_suffix('m') {
        (s, 'm')
    } else {
        return Err(EnvVaultError::CommandFailed(format!(
            "invalid duration '{input}' — use format like 30m, 24h, 7d, 2w, or 1y"
        )));
    };

    let num: i64 = num_str.parse().map_err(|_| {
        EnvVaultError::CommandFailed(format!(
            "invalid duration '{input}' — number part must be a positive integer"
        ))
    })?;

    if num < 0 {
        return Err(EnvVaultError::CommandFailed(format!(
            "invalid duration '{input}' — negative values not supported"
        )));
    }

    let duration = match unit {
        'm' => Duration::minutes(num),
        'h' => Duration::hours(num),
        'd' => Duration::days(num),
        'w' => Duration::weeks(num),
        'y' => Duration::days(num * 365),
        _ => unreachable!(),
    };

    Ok(duration)
}

/// Parse a duration string and return `now + duration` (future point).
///
/// Used by `set --expires`.
pub fn parse_future(input: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    Ok(chrono::Utc::now() + parse_delta(input)?)
}

/// Parse a duration string and return `now - duration` (past point).
///
/// Used by `audit --since` and `audit purge --older-than`.
pub fn parse_past(input: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    Ok(chrono::Utc::now() - parse_delta(input)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_units() {
        assert_eq!(parse_delta("30m").unwrap(), Duration::minutes(30));
        assert_eq!(parse_delta("24h").unwrap(), Duration::hours(24));
        assert_eq!(parse_delta("7d").unwrap(), Duration::days(7));
        assert_eq!(parse_delta("2w").unwrap(), Duration::weeks(2));
        assert_eq!(parse_delta("1y").unwrap(), Duration::days(365));
    }

    #[test]
    fn zero_is_valid() {
        assert_eq!(parse_delta("0d").unwrap(), Duration::zero());
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(parse_delta("  7d ").unwrap(), Duration::days(7));
    }

    #[test]
    fn rejects_missing_unit() {
        assert!(parse_delta("7").is_err());
    }

    #[test]
    fn rejects_missing_number() {
        assert!(parse_delta("d").is_err());
    }

    #[test]
    fn rejects_unknown_unit() {
        assert!(parse_delta("7x").is_err());
    }

    #[test]
    fn rejects_negative() {
        assert!(parse_delta("-1d").is_err());
    }

    #[test]
    fn parse_future_is_after_now() {
        let future = parse_future("1h").unwrap();
        assert!(future > chrono::Utc::now());
    }

    #[test]
    fn parse_past_is_before_now() {
        let past = parse_past("1h").unwrap();
        assert!(past < chrono::Utc::now());
    }
}
