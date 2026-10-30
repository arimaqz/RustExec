use std::io::{self, Read, Write};
pub const MAX_STRING: usize = 1024 * 1024;
pub const MAX_ARGS: usize = 4096;
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub system: bool,
    pub interactive: Option<u32>,
    pub detached: bool,
    pub priority: u32,
    pub affinity: Option<usize>,
    pub workdir: Option<String>,
    pub command: Vec<String>,
}
fn bad(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
pub fn put_u32(w: &mut impl Write, n: u32) -> io::Result<()> {
    w.write_all(&n.to_le_bytes())
}
pub fn get_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
pub fn put_string(w: &mut impl Write, s: &str) -> io::Result<()> {
    if s.len() > MAX_STRING || s.contains('\0') {
        return Err(bad("String too long or contains NUL"));
    }
    put_u32(w, s.len() as u32)?;
    w.write_all(s.as_bytes())
}
pub fn get_string(r: &mut impl Read) -> io::Result<String> {
    let n = get_u32(r)? as usize;
    if n > MAX_STRING {
        return Err(bad("String length exceeds protocol limit"));
    }
    let mut b = vec![0; n];
    r.read_exact(&mut b)?;
    let s = String::from_utf8(b).map_err(|_| bad("Invalid UTF-8"))?;
    if s.contains('\0') {
        return Err(bad("Embedded NUL"));
    }
    Ok(s)
}
impl Request {
    pub fn write(&self, w: &mut impl Write) -> io::Result<()> {
        if self.command.is_empty() || self.command.len() > MAX_ARGS {
            return Err(bad("Invalid argument count"));
        }
        w.write_all(b"RSEXEC01")?;
        put_u32(w, u32::from(self.system) | u32::from(self.detached) << 1)?;
        put_u32(w, self.interactive.unwrap_or(u32::MAX - 1))?;
        put_u32(w, self.priority)?;
        w.write_all(&(self.affinity.unwrap_or(0) as u64).to_le_bytes())?;
        put_string(w, self.workdir.as_deref().unwrap_or(""))?;
        put_u32(w, self.command.len() as u32)?;
        for a in &self.command {
            put_string(w, a)?;
        }
        w.flush()
    }
    pub fn read(r: &mut impl Read) -> io::Result<Self> {
        let mut magic = [0; 8];
        r.read_exact(&mut magic)?;
        if &magic != b"RSEXEC01" {
            return Err(bad("Protocol version mismatch"));
        }
        let flags = get_u32(r)?;
        if flags & !3 != 0 {
            return Err(bad("Unknown request flags"));
        }
        let session = get_u32(r)?;
        let priority = get_u32(r)?;
        if ![0x20, 0x40, 0x80, 0x100, 0x4000, 0x8000, 0x100000].contains(&priority) {
            return Err(bad("Invalid priority"));
        }
        let mut affinity = [0; 8];
        r.read_exact(&mut affinity)?;
        let affinity =
            usize::try_from(u64::from_le_bytes(affinity)).map_err(|_| bad("Affinity overflow"))?;
        let wd = get_string(r)?;
        let count = get_u32(r)? as usize;
        if count == 0 || count > MAX_ARGS {
            return Err(bad("Invalid argument count"));
        }
        let mut command = Vec::with_capacity(count);
        let mut total = 0;
        for _ in 0..count {
            let a = get_string(r)?;
            total += a.len();
            if total > MAX_STRING {
                return Err(bad("Command exceeds limit"));
            }
            command.push(a);
        }
        if command[0].is_empty() {
            return Err(bad("Empty executable"));
        }
        Ok(Self {
            system: flags & 1 != 0,
            detached: flags & 2 != 0,
            interactive: if session == u32::MAX - 1 {
                None
            } else {
                Some(session)
            },
            priority,
            affinity: if affinity == 0 { None } else { Some(affinity) },
            workdir: if wd.is_empty() { None } else { Some(wd) },
            command,
        })
    }
}
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c == '"' || c.is_whitespace()) {
        return arg.to_owned();
    }
    let mut s = String::from("\"");
    let mut slashes = 0;
    for c in arg.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        if c == '"' {
            s.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
        } else {
            s.extend(std::iter::repeat_n('\\', slashes));
        }
        slashes = 0;
        s.push(c);
    }
    s.extend(std::iter::repeat_n('\\', slashes * 2));
    s.push('"');
    s
}
pub fn command_line(args: &[String]) -> String {
    args.iter()
        .map(|s| quote_arg(s))
        .collect::<Vec<_>>()
        .join(" ")
}
pub fn process_command_line(args: &[String]) -> String {
    let executable = args.first().map(String::as_str).unwrap_or("");
    let base = executable.rsplit(['\\', '/']).next().unwrap_or(executable);
    if (base.eq_ignore_ascii_case("cmd.exe") || base.eq_ignore_ascii_case("cmd"))
        && let Some(index) = args
            .iter()
            .position(|s| s.eq_ignore_ascii_case("/c") || s.eq_ignore_ascii_case("/k"))
        && args.len() == index + 2
    {
        // cmd.exe consumes a raw command tail rather than CRT argv quoting.
        // /S deterministically removes this outer quote pair, preserving the
        // user's quotes inside the shell program (e.g. paths with spaces).
        let mut prefix = args[..index].to_vec();
        if !prefix.iter().any(|s| s.eq_ignore_ascii_case("/s")) {
            prefix.push("/s".into());
        }
        prefix.push(args[index].clone());
        return format!("{} \"{}\"", command_line(&prefix), args[index + 1]);
    }
    command_line(args)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_roundtrip() {
        let r = Request {
            system: false,
            interactive: Some(u32::MAX),
            detached: false,
            priority: 0x20,
            affinity: Some(5),
            workdir: Some("C:\\a b".into()),
            command: vec!["cmd.exe".into(), "/c".into(), "echo café".into()],
        };
        let mut b = vec![];
        r.write(&mut b).unwrap();
        assert_eq!(Request::read(&mut &b[..]).unwrap(), r);
    }
    #[test]
    fn rejects_bad_version() {
        assert!(Request::read(&mut &b"INVALID!"[..]).is_err());
    }
    #[test]
    fn rejects_oversize() {
        let mut b = vec![];
        put_u32(&mut b, (MAX_STRING + 1) as u32).unwrap();
        assert!(get_string(&mut &b[..]).is_err());
    }
    #[test]
    fn rejects_nul() {
        assert!(put_string(&mut vec![], "a\0b").is_err());
    }
    #[test]
    fn rejects_truncated_request() {
        let r = Request {
            system: true,
            interactive: None,
            detached: true,
            priority: 0x20,
            affinity: None,
            workdir: None,
            command: vec!["x".into()],
        };
        let mut b = vec![];
        r.write(&mut b).unwrap();
        for end in 0..b.len() {
            assert!(Request::read(&mut &b[..end]).is_err());
        }
    }
    #[test]
    fn quotes_windows_arguments() {
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg("a b\\"), "\"a b\\\\\"");
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
    }
    #[test]
    fn cmd_tail_preserves_inner_quotes() {
        let args = ["cmd.exe", "/d", "/q", "/c", "del /q \"C:\\a b\\file.txt\""].map(String::from);
        assert_eq!(
            process_command_line(&args),
            "cmd.exe /d /q /s /c \"del /q \"C:\\a b\\file.txt\"\""
        );
    }
}
