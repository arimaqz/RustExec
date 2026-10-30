mod cli;
#[cfg(windows)]
mod client;
#[cfg(windows)]
mod process;
mod protocol;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod win;
const HELP: &str = r#"RustExec — independent PsExec-style Windows process runner
Usage: rsexec [\\host[,host2] | @hosts.txt] [options] command [arguments]
 -u user [-p password]  Network credentials (hidden prompt if -p omitted)
 -s                    Run as SYSTEM through temporary local/remote service
 -i [session]          Target interactive desktop; defaults to console session
 -n seconds            Pipe connection timeout (default 30)
 -r name               Temporary service name (existing services are refused)
 -c [-f]               Copy executable to remote ADMIN$; -f permits replacement
 -w directory          Target working directory
 -a 1,3                CPU affinity (one-based CPU indices)
 -low|-belownormal|-normal|-abovenormal|-high|-realtime|-background
 -d                    Detach; return process ID instead of exit status
 --                    End option parsing
 -? | --help           Show this help
 --version             Show this implementation's version
Notes: independent protocol; not compatible with PSEXESVC. Requires normal
Windows administrator access for service mode, ADMIN$/SMB and SCM access remotely.
Unsupported PsExec flags are rejected. No account profile or second-hop delegation.
"#;
#[cfg(windows)]
fn run(mut options: cli::Options) -> std::io::Result<u32> {
    if options.hosts.is_empty() && options.username.is_some() {
        return Err(std::io::Error::other(
            "Local -u is not implemented; use runas.exe or specify an explicit remote host",
        ));
    }
    if let Some(user) = &options.username {
        if options.password.is_none() {
            options.password = Some(win::prompt_password()?);
        }
        let _credentials = win::Credentials::network(user, options.password.as_deref().unwrap())?;
        return hosts(&options);
    }
    hosts(&options)
}
#[cfg(windows)]
fn hosts(options: &cli::Options) -> std::io::Result<u32> {
    if options.hosts.is_empty() {
        if options.copy {
            return Err(std::io::Error::other("-c requires a remote host"));
        }
        if options.system || options.interactive.is_some() {
            return client::run(options, None, true);
        }
        let child = process::spawn(&client::request(options), None, false)?;
        if options.detached {
            eprintln!("Process {} started", child.pid);
            Ok(child.pid)
        } else {
            child.wait()
        }
    } else {
        let mut result = 0;
        let mut stream_stdin = true;
        for host in &options.hosts {
            match client::run(options, Some(host), stream_stdin) {
                Ok(code) => {
                    if code != 0 {
                        result = code;
                    }
                }
                Err(e) => {
                    eprintln!("{host}: {e}");
                    result = 1;
                }
            }
            stream_stdin = false;
        }
        Ok(result)
    }
}
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || matches!(args[0].as_str(), "-?" | "--help" | "-help") {
        print!("{HELP}");
        return;
    }
    if args[0] == "--version" {
        println!("rsexec {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    #[cfg(windows)]
    if args[0] == "--service" {
        if args.len() != 4 {
            eprintln!("Invalid internal service arguments");
            std::process::exit(2);
        }
        let timeout = args[3]
            .parse::<u32>()
            .ok()
            .filter(|n| *n > 0 && *n <= 3600)
            .unwrap_or(30);
        if let Err(e) = service::dispatch(args[1].clone(), args[2].clone(), timeout) {
            eprintln!("Service: {e}");
            std::process::exit(1);
        }
        return;
    }
    let options = match cli::parse(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}\nUse --help for usage.");
            std::process::exit(2);
        }
    };
    #[cfg(windows)]
    match run(options) {
        Ok(code) => std::process::exit(code as i32),
        Err(e) => {
            eprintln!("rsexec: {e}");
            std::process::exit(1);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = options;
        eprintln!("Execution requires Windows; protocol and CLI tests are portable.");
        std::process::exit(1);
    }
}
