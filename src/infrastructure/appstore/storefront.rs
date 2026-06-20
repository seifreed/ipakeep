//! iTunes Store front resolution.
//!
//! The `X-Apple-Store-Front` header determines which regional store a commerce
//! request targets, and it must match the account's own store. Legacy auth
//! returned it in a response header, but the `GrandSlam` SPD payload does not
//! carry it, so we derive it from the account's country (the system locale, or
//! an explicit `--country` at login).

/// Apple store-front id for an ISO 3166-1 alpha-2 country code (case-insensitive),
/// formatted as `"<id>-1"` to match the codebase convention (see
/// `DEFAULT_US_STORE_FRONT`). Returns `None` for unknown countries.
pub fn storefront_for_country(country: &str) -> Option<String> {
    let id = match country.to_ascii_lowercase().as_str() {
        "us" => "143441",
        "gb" | "uk" => "143444",
        "es" => "143454",
        "fr" => "143442",
        "de" => "143443",
        "it" => "143450",
        "nl" => "143452",
        "pt" => "143453",
        "ie" => "143449",
        "be" => "143446",
        "at" => "143445",
        "ch" => "143459",
        "se" => "143456",
        "no" => "143457",
        "dk" => "143458",
        "fi" => "143447",
        "pl" => "143478",
        "ca" => "143455",
        "mx" => "143468",
        "br" => "143503",
        "au" => "143460",
        "nz" => "143461",
        "jp" => "143462",
        "cn" => "143465",
        "in" => "143467",
        "ru" => "143469",
        "kr" => "143466",
        "tr" => "143480",
        _ => return None,
    };
    Some(format!("{id}-1"))
}

/// Derive the ISO 3166-1 alpha-2 country code from the process locale
/// (`LC_ALL`/`LANG`, e.g. `es_ES.UTF-8` → `es`). Returns `None` when the locale
/// is absent or carries no region (e.g. `C`, `POSIX`).
pub fn locale_country() -> Option<String> {
    let locale = std::env::var("LC_ALL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var("LANG").ok())?;
    country_from_locale(&locale)
}

/// Extract the lowercase region from a POSIX locale string (`es_ES.UTF-8` → `es`).
fn country_from_locale(locale: &str) -> Option<String> {
    let region = locale
        .split('.')
        .next()
        .unwrap_or("")
        .split('_')
        .nth(1)
        .filter(|region| !region.is_empty())?;
    Some(region.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{country_from_locale, storefront_for_country};

    #[test]
    fn storefront_for_country_maps_known_countries_case_insensitively() {
        assert_eq!(storefront_for_country("es").as_deref(), Some("143454-1"));
        assert_eq!(storefront_for_country("US").as_deref(), Some("143441-1"));
        assert_eq!(storefront_for_country("gb").as_deref(), Some("143444-1"));
    }

    #[test]
    fn storefront_for_country_returns_none_for_unknown() {
        assert_eq!(storefront_for_country("zz"), None);
        assert_eq!(storefront_for_country(""), None);
    }

    #[test]
    fn country_from_locale_extracts_region() {
        assert_eq!(country_from_locale("es_ES.UTF-8").as_deref(), Some("es"));
        assert_eq!(country_from_locale("en_US").as_deref(), Some("us"));
        assert_eq!(country_from_locale("C"), None);
        assert_eq!(country_from_locale(""), None);
    }
}
