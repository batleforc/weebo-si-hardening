//! Kubernetes resource quantities (`500m`, `8Gi`, `1e3`), parsed exactly enough to compare —
//! RFC 0014's *Architecture*: "The domain represents quantities with its own parsed type for the
//! validation table, so the crate does not depend on `k8s-openapi`."

use std::cmp::Ordering;
use std::fmt;

/// A quantity, as an exact number of nano-units (`1` is `1n`, `1_000_000_000` is `1`).
///
/// `i128` holds every value a real cluster writes: the largest suffix, `Ei`, is about `1.2e27`
/// nano-units, eleven orders of magnitude below the limit. Finer than a nano-unit is truncated,
/// which the apiserver itself rounds away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Quantity(i128);

/// A string that is not a Kubernetes quantity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuantityError(pub String);

impl fmt::Display for QuantityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} is not a resource quantity", self.0)
    }
}

const NANO_PER_UNIT: i128 = 1_000_000_000;

impl Quantity {
    /// Nothing.
    pub const ZERO: Quantity = Quantity(0);

    /// A quantity of `nanos` nano-units.
    pub fn from_nanos(nanos: i128) -> Self {
        Self(nanos)
    }

    /// Render for a person: millicores for `cpu`, binary units for bytes (`memory`, `storage`),
    /// a plain number otherwise. Rounded down; for display only, never parsed back.
    pub fn display_for(self, resource: &str) -> String {
        let units = self.0 / NANO_PER_UNIT;
        if resource.contains("cpu") {
            return format!("{}m", self.0 / 1_000_000);
        }
        if resource.contains("memory") || resource.contains("storage") {
            for (suffix, shift) in [("Gi", 30), ("Mi", 20), ("Ki", 10)] {
                let unit = 1i128 << shift;
                if units >= unit {
                    let tenths = units * 10 / unit;
                    return format!("{}.{}{suffix}", tenths / 10, tenths % 10);
                }
            }
        }
        units.to_string()
    }

    /// Parse upstream's grammar: an optionally signed decimal number, then one of the binary
    /// suffixes (`Ki`…`Ei`), the decimal ones (`n`, `u`, `m`, none, `k`, `M`…`E`), or a decimal
    /// exponent (`e3`, `E-2`).
    pub fn parse(raw: &str) -> Result<Self, QuantityError> {
        let error = || QuantityError(raw.to_string());
        let (negative, rest) = match raw.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, raw.strip_prefix('+').unwrap_or(raw)),
        };
        let number_end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let (number, suffix) = rest.split_at(number_end);
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if whole.is_empty() && fraction.is_empty() || fraction.contains('.') {
            return Err(error());
        }
        let digits: i128 = format!("{whole}{fraction}").parse().map_err(|_| error())?;
        let scale = pow10(u32::try_from(fraction.len()).map_err(|_| error())?).ok_or_else(error)?;

        let (multiplier, divisor): (i128, i128) = match suffix {
            "n" => (1, 1),
            "u" => (1_000, 1),
            "m" => (1_000_000, 1),
            "" => (NANO_PER_UNIT, 1),
            "k" => (NANO_PER_UNIT * 1_000, 1),
            "M" => (NANO_PER_UNIT * pow10(6).ok_or_else(error)?, 1),
            "G" => (NANO_PER_UNIT * pow10(9).ok_or_else(error)?, 1),
            "T" => (NANO_PER_UNIT * pow10(12).ok_or_else(error)?, 1),
            "P" => (NANO_PER_UNIT * pow10(15).ok_or_else(error)?, 1),
            "E" => (NANO_PER_UNIT * pow10(18).ok_or_else(error)?, 1),
            "Ki" => (NANO_PER_UNIT << 10, 1),
            "Mi" => (NANO_PER_UNIT << 20, 1),
            "Gi" => (NANO_PER_UNIT << 30, 1),
            "Ti" => (NANO_PER_UNIT << 40, 1),
            "Pi" => (NANO_PER_UNIT << 50, 1),
            "Ei" => (NANO_PER_UNIT << 60, 1),
            exponent => {
                let digits = exponent
                    .strip_prefix('e')
                    .or_else(|| exponent.strip_prefix('E'))
                    .ok_or_else(error)?;
                let exponent: i32 = digits.parse().map_err(|_| error())?;
                if exponent >= 0 {
                    let power = pow10(exponent.unsigned_abs()).ok_or_else(error)?;
                    (NANO_PER_UNIT.checked_mul(power).ok_or_else(error)?, 1)
                } else {
                    (
                        NANO_PER_UNIT,
                        pow10(exponent.unsigned_abs()).ok_or_else(error)?,
                    )
                }
            }
        };
        let nanos = digits
            .checked_mul(multiplier)
            .ok_or_else(error)?
            .checked_div(scale.checked_mul(divisor).ok_or_else(error)?)
            .ok_or_else(error)?;
        Ok(Self(if negative { -nanos } else { nanos }))
    }

    /// The value in nano-units.
    pub fn nanos(self) -> i128 {
        self.0
    }

    /// `self / other` as a fraction in thousandths, for a saturation band: `1000` is "at the
    /// limit". `None` when `other` is zero — a quota of `0` is a ban, not a ratio.
    pub fn per_mille_of(self, other: Self) -> Option<i128> {
        if other.0 == 0 {
            return None;
        }
        self.0.checked_mul(1000).map(|scaled| scaled / other.0)
    }
}

impl PartialOrd<i128> for Quantity {
    fn partial_cmp(&self, other: &i128) -> Option<Ordering> {
        self.0.partial_cmp(other)
    }
}

impl PartialEq<i128> for Quantity {
    fn eq(&self, other: &i128) -> bool {
        self.0 == *other
    }
}

fn pow10(exponent: u32) -> Option<i128> {
    10i128.checked_pow(exponent)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn q(raw: &str) -> Quantity {
        Quantity::parse(raw).unwrap()
    }

    #[test]
    fn decimal_suffixes() {
        assert_eq!(q("1"), NANO_PER_UNIT);
        assert_eq!(q("500m"), NANO_PER_UNIT / 2);
        assert_eq!(q("100m"), q("0.1"));
        assert_eq!(q("1k"), q("1000"));
        assert_eq!(q("2M"), q("2000000"));
        assert_eq!(q("1n"), 1);
        assert_eq!(q("1u"), 1000);
    }

    #[test]
    fn binary_suffixes() {
        assert_eq!(q("1Ki"), q("1024"));
        assert_eq!(q("1Mi"), q("1048576"));
        assert_eq!(q("8Gi").nanos(), 8 * (1i128 << 30) * NANO_PER_UNIT);
        assert!(q("1Gi") > q("1G"));
        assert!(q("1Ei") > q("1E"));
    }

    #[test]
    fn exponents_and_fractions() {
        assert_eq!(q("1e3"), q("1k"));
        assert_eq!(q("5E-1"), q("500m"));
        assert_eq!(q("1.5Gi"), q("1536Mi"));
        assert_eq!(q(".5"), q("500m"));
        assert_eq!(q("-1"), -NANO_PER_UNIT);
    }

    #[test]
    fn the_ordering_the_validation_table_needs() {
        assert!(q("256Mi") < q("1Gi"));
        assert!(q("100m") < q("1"));
        assert!(q("4") > q("3999m"));
    }

    #[test]
    fn garbage_is_refused() {
        for raw in ["", "Gi", "1.2.3", "1Gb", "abc", "1 Gi", "1e", "1ee3", "."] {
            assert!(Quantity::parse(raw).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn display() {
        assert_eq!(q("2500m").display_for("requests.cpu"), "2500m");
        assert_eq!(q("9.5Gi").display_for("requests.memory"), "9.5Gi");
        assert_eq!(q("512Mi").display_for("limits.memory"), "512.0Mi");
        assert_eq!(q("23").display_for("pods"), "23");
    }

    #[test]
    fn per_mille() {
        assert_eq!(q("6").per_mille_of(q("8")), Some(750));
        assert_eq!(q("8").per_mille_of(q("8")), Some(1000));
        assert_eq!(q("0").per_mille_of(q("0")), None);
    }
}
