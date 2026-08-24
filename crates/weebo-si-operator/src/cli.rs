//! Hand-rolled `--flag value` argv parsing, matching this repo's existing convention
//! (`bins/passwd-append`, `bins/preauth-proxy`) — no `clap`.

/// The value following `--name` in `args`, if present.
pub fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Whether the bare boolean flag `--name` is present in `args`.
pub fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}
