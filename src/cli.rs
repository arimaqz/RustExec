//! Argument handling for explicit, administrator-selected execution targets.
use std::{collections::HashSet, fmt, fs};

#[derive(Clone)]
pub struct Options {
    pub hosts: Vec<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub service_name: Option<String>,
    pub timeout_secs: u32,
    pub system: bool,
    pub interactive: Option<u32>,
    pub detached: bool,
    pub copy: bool,
    pub force_copy: bool,
    pub workdir: Option<String>,
    pub priority: u32,
    pub affinity: Option<usize>,
    pub command: Vec<String>,
}

// Never expose a password through diagnostic formatting.
impl fmt::Debug for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options")
            .field("hosts", &self.hosts)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("service_name", &self.service_name)
            .field("timeout_secs", &self.timeout_secs)
            .field("system", &self.system)
            .field("interactive", &self.interactive)
            .field("detached", &self.detached)
            .field("copy", &self.copy)
            .field("force_copy", &self.force_copy)
            .field("workdir", &self.workdir)
            .field("priority", &self.priority)
            .field("affinity", &self.affinity)
            // Command arguments can themselves contain passwords.
            .field("command", &"[REDACTED ARGUMENTS]")
            .finish()
    }
}

fn value(args: &[String], i: &mut usize, switch: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .filter(|v| !v.is_empty())
        .cloned()
        .ok_or_else(|| format!("{switch} requires a nonempty argument"))
}

fn host(raw: &str) -> Result<String, String> {
    let name = raw.trim().strip_prefix("\\\\").unwrap_or(raw.trim());
    if name.is_empty()
        || name.starts_with('-')
        || name
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "\\/*?,@:".contains(c))
    {
        return Err("Invalid host: use an explicit computer name or IPv4 address (no wildcards, paths, ports, or stdin targets)".into());
    }
    Ok(name.to_owned())
}

fn affinity(raw: &str) -> Result<usize, String> {
    let mut mask = 0usize;
    for item in raw.split(',') {
        let cpu = item
            .parse::<u32>()
            .map_err(|_| "-a requires a comma-separated list of 1-based CPU numbers")?;
        if cpu == 0 || cpu > usize::BITS {
            return Err(format!(
                "-a CPU numbers must be between 1 and {}",
                usize::BITS
            ));
        }
        mask |= 1usize << (cpu - 1);
    }
    Ok(mask)
}

/// Parse arguments excluding the program name. Once a command is seen, all
/// remaining arguments belong to that command and are preserved verbatim.
pub fn parse(args: Vec<String>) -> Result<Options, String> {
    if args.iter().any(|s| s.contains('\0')) {
        return Err("Arguments must not contain embedded NUL characters".into());
    }
    let mut options = Options {
        hosts: Vec::new(),
        username: None,
        password: None,
        service_name: None,
        timeout_secs: 30,
        system: false,
        interactive: None,
        detached: false,
        copy: false,
        force_copy: false,
        workdir: None,
        priority: 0x20,
        affinity: None,
        command: Vec::new(),
    };
    let mut i = 0;
    let mut seen = HashSet::new();
    let mut target_seen = false;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            options.command = args[i + 1..].to_vec();
            break;
        }
        if arg.starts_with("\\\\") || arg.starts_with('@') {
            if target_seen {
                return Err(
                    "Specify targets only once, using \\\\host1,host2 or @hostsfile".into(),
                );
            }
            target_seen = true;
            if let Some(path) = arg.strip_prefix('@') {
                if path.is_empty() || path == "-" {
                    return Err("@ requires a host file path; stdin targets are unsupported".into());
                }
                let text =
                    fs::read_to_string(path).map_err(|_| "Could not read the UTF-8 host file")?;
                for line in text.trim_start_matches('\u{feff}').lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        options.hosts.push(host(line)?);
                    }
                }
            } else {
                for name in arg[2..].split(',') {
                    options.hosts.push(host(name)?);
                }
            }
            if options.hosts.is_empty() {
                return Err("At least one explicit host is required".into());
            }
        } else if arg.starts_with('-') || arg.starts_with('/') {
            let switch = arg.to_ascii_lowercase();
            let duplicate_key = match switch.as_str() {
                "-low" | "-belownormal" | "-normal" | "-abovenormal" | "-high" | "-realtime"
                | "-background" => "priority",
                _ => switch.as_str(),
            };
            if !seen.insert(duplicate_key.to_owned()) {
                return Err(format!("Duplicate or conflicting option: {duplicate_key}"));
            }
            match switch.as_str() {
                "-u" => options.username = Some(value(&args, &mut i, "-u")?),
                "-p" => options.password = Some(value(&args, &mut i, "-p")?),
                "-r" => {
                    let name = value(&args, &mut i, "-r")?;
                    if name.len() > 256 || name.chars().any(|c| c.is_control() || "\\/".contains(c))
                    {
                        return Err("-r requires a service name of at most 256 bytes without slashes or control characters".into());
                    }
                    options.service_name = Some(name);
                }
                "-w" => options.workdir = Some(value(&args, &mut i, "-w")?),
                "-n" => {
                    options.timeout_secs = value(&args, &mut i, "-n")?
                        .parse()
                        .map_err(|_| "-n requires a positive integer timeout in seconds")?;
                    if options.timeout_secs == 0 || options.timeout_secs > 3600 {
                        return Err("-n timeout must be between 1 and 3600 seconds".into());
                    }
                }
                "-s" => options.system = true,
                "-i" => {
                    options.interactive = Some(u32::MAX);
                    if let Some(next) = args.get(i + 1)
                        && !next.is_empty()
                        && next.bytes().all(|c| c.is_ascii_digit())
                    {
                        i += 1;
                        let session = next
                            .parse::<u32>()
                            .map_err(|_| "-i session number is out of range")?;
                        if session >= u32::MAX - 1 {
                            return Err(
                                "-i session number is reserved for the active console".into()
                            );
                        }
                        options.interactive = Some(session);
                    }
                }
                "-d" => options.detached = true,
                "-c" => options.copy = true,
                "-f" => options.force_copy = true,
                "-a" => options.affinity = Some(affinity(&value(&args, &mut i, "-a")?)?),
                "-low" => options.priority = 0x40,
                "-belownormal" => options.priority = 0x4000,
                "-normal" => options.priority = 0x20,
                "-abovenormal" => options.priority = 0x8000,
                "-high" => options.priority = 0x80,
                "-realtime" => options.priority = 0x100,
                "-background" => options.priority = 0x0010_0000,
                "-accepteula" | "-nobanner" => {}
                "-?" | "--help" => return Err("Help requested".into()),
                _ => return Err(format!("Unsupported option: {switch}")),
            }
        } else {
            options.command = args[i..].to_vec();
            break;
        }
        i += 1;
    }
    if options.command.is_empty() || options.command[0].is_empty() {
        return Err("A command is required".into());
    }
    if options.password.is_some() && options.username.is_none() {
        return Err("-p requires -u".into());
    }
    if options.force_copy && !options.copy {
        return Err("-f requires -c".into());
    }
    let mut unique = HashSet::new();
    options
        .hosts
        .retain(|name| unique.insert(name.to_ascii_lowercase()));
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(args: &[&str]) -> Result<Options, String> {
        parse(args.iter().map(|s| (*s).to_owned()).collect())
    }

    #[test]
    fn preserves_child_quoting_spaces_and_switches() {
        let o = run(&[r"C:\Program Files\tool.exe", "a b", "-s", "", "\\\\child"]).unwrap();
        assert_eq!(
            o.command,
            vec![r"C:\Program Files\tool.exe", "a b", "-s", "", "\\\\child"]
        );
        assert!(!o.system);
        assert!(o.hosts.is_empty());
    }
    #[test]
    fn explicit_targets_and_credentials() {
        let o = run(&[
            r"\\HOST,host,127.0.0.1",
            "-u",
            r"domain\user",
            "-p",
            "-secret",
            "-n",
            "5",
            "cmd",
        ])
        .unwrap();
        assert_eq!(o.hosts, vec!["HOST", "127.0.0.1"]);
        assert_eq!(o.password.as_deref(), Some("-secret"));
        assert_eq!(o.timeout_secs, 5);
        assert!(!format!("{o:?}").contains("-secret"));
    }
    #[test]
    fn interactive_ambiguity_and_separator() {
        assert_eq!(run(&["-i", "cmd"]).unwrap().interactive, Some(u32::MAX));
        assert_eq!(run(&["-i", "0", "cmd"]).unwrap().interactive, Some(0));
        let o = run(&["-i", "--", "123", "-d"]).unwrap();
        assert_eq!(o.interactive, Some(u32::MAX));
        assert_eq!(o.command, vec!["123", "-d"]);
        assert!(run(&["-i", "4294967295", "cmd"]).is_err());
        assert!(run(&["-i", "4294967294", "cmd"]).is_err());
        assert!(run(&["-i", "4294967296", "cmd"]).is_err());
    }
    #[test]
    fn invalid_constraints_and_options() {
        for args in [
            vec![],
            vec!["-u"],
            vec!["-p", "secret", "cmd"],
            vec!["-f", "cmd"],
            vec!["-n", "0", "cmd"],
            vec!["-n", "no", "cmd"],
            vec!["-x", "cmd"],
            vec!["-low", "-high", "cmd"],
            vec!["-r", "bad/name", "cmd"],
            vec!["--"],
            vec!["cmd", "bad\0arg"],
        ] {
            assert!(run(&args).is_err(), "unexpected success for {:?}", args);
        }
    }
    #[test]
    fn affinity_is_one_based_and_bounded() {
        assert_eq!(run(&["-a", "1,3,3", "cmd"]).unwrap().affinity, Some(5));
        for cpus in ["0", "", "1,", "1-3", "99999999999999"] {
            assert!(run(&["-a", cpus, "cmd"]).is_err());
        }
        let top = usize::BITS.to_string();
        assert_eq!(
            run(&["-a", &top, "cmd"]).unwrap().affinity,
            Some(1usize << (usize::BITS - 1))
        );
    }
    #[test]
    fn disallows_enumeration_paths_and_stdin_hosts() {
        for target in [
            r"\\*",
            r"\\host\share",
            r"\\",
            r"\\host,",
            r"\\host:445",
            "@-",
            "@",
        ] {
            assert!(run(&[target, "cmd"]).is_err());
        }
        assert!(run(&[r"\\one", r"\\two", "cmd"]).is_err());
    }
    #[test]
    fn host_file_one_host_per_line_with_comments_and_bom() {
        let path =
            std::env::temp_dir().join(format!("psexec-rs-cli-hosts-{}.txt", std::process::id()));
        fs::write(
            &path,
            "\u{feff}alpha\r\n# comment\r\n\r\n beta \r\nALPHA\r\n",
        )
        .unwrap();
        let token = format!("@{}", path.display());
        let parsed = run(&[&token, "cmd"]);
        fs::remove_file(path).unwrap();
        assert_eq!(parsed.unwrap().hosts, vec!["alpha", "beta"]);
    }
}
