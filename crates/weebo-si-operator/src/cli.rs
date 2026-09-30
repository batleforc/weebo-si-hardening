//! Hand-rolled `--flag value` / `--flag=value` argv parsing, matching this repo's existing
//! convention (`bins/passwd-append`, `bins/preauth-proxy`) — no `clap`. Both spellings are
//! accepted because the Helm chart renders every valued flag as a single `--flag=value` argv entry.

/// The value of `--name` in `args`, given either as `--name value` or `--name=value`.
pub fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().enumerate().find_map(|(i, arg)| {
        if arg == name {
            args.get(i + 1).map(String::as_str)
        } else {
            arg.strip_prefix(name)?.strip_prefix('=')
        }
    })
}

/// Whether the bare boolean flag `--name` is present in `args`.
pub fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn flag_reads_the_space_separated_form() {
        let args = argv(&["webhook", "--addr", "0.0.0.0:9443"]);
        assert_eq!(flag(&args, "--addr"), Some("0.0.0.0:9443"));
    }

    #[test]
    fn flag_reads_the_equals_form_the_chart_renders() {
        let args = argv(&["webhook", "--operator-identity=system:serviceaccount:ns:sa"]);
        assert_eq!(
            flag(&args, "--operator-identity"),
            Some("system:serviceaccount:ns:sa")
        );
    }

    #[test]
    fn flag_does_not_match_a_longer_flag_sharing_its_prefix() {
        let args = argv(&["--addr-extra=1", "--addrx", "2"]);
        assert_eq!(flag(&args, "--addr"), None);
    }

    #[test]
    fn flag_is_none_when_absent_or_valueless() {
        assert_eq!(flag(&argv(&["webhook"]), "--addr"), None);
        assert_eq!(flag(&argv(&["--addr"]), "--addr"), None);
    }
}
