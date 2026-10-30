use crate::{
    cli::Options,
    protocol::{self, Request},
    win,
};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
    ptr::{null, null_mut},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Storage::FileSystem::DELETE,
    System::{Console::*, Services::*},
};
static CANCEL: AtomicBool = AtomicBool::new(false);
static CANCEL_COUNT: AtomicU32 = AtomicU32::new(0);
fn trace(message: &str) {
    if std::env::var_os("RSEXEC_TRACE").is_some() {
        eprintln!("[rsexec] {message}");
    }
}
unsafe extern "system" fn ctrl(code: u32) -> i32 {
    if code == CTRL_C_EVENT || code == CTRL_BREAK_EVENT {
        let count = CANCEL_COUNT.fetch_add(1, Ordering::SeqCst);
        if count == 0 {
            CANCEL.store(true, Ordering::SeqCst);
            1
        } else {
            0
        }
    } else {
        0
    }
}

struct RemoveRemoteFile(Option<PathBuf>);
impl RemoveRemoteFile {
    fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }
    fn disarm(&mut self) {
        self.0 = None;
    }
}
impl Drop for RemoveRemoteFile {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

struct JoinRelays(Vec<JoinHandle<io::Result<()>>>);
impl JoinRelays {
    fn push(&mut self, handle: JoinHandle<io::Result<()>>) {
        self.0.push(handle);
    }
    fn finish(mut self) -> io::Result<()> {
        for handle in self.0.drain(..) {
            handle
                .join()
                .map_err(|_| io::Error::other("Stream relay panicked"))??;
        }
        Ok(())
    }
}
struct Sc(SC_HANDLE);
// SCM functions accept these opaque handles from multiple threads. Ownership stays in Arc.
unsafe impl Send for Sc {}
unsafe impl Sync for Sc {}
impl Drop for Sc {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
struct Lease {
    service: Arc<Sc>,
    copied: Option<std::path::PathBuf>,
    complete: bool,
}
impl Drop for Lease {
    fn drop(&mut self) {
        unsafe {
            if !self.complete {
                let mut status = std::mem::zeroed();
                ControlService(self.service.0, SERVICE_CONTROL_STOP, &mut status);
            }
            DeleteService(self.service.0);
            if let Some(path) = &self.copied {
                let start = Instant::now();
                loop {
                    match std::fs::remove_file(path) {
                        Ok(()) => break,
                        Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                        Err(_) if start.elapsed() < Duration::from_secs(5) => {
                            std::thread::sleep(Duration::from_millis(100))
                        }
                        Err(e) => {
                            eprintln!(
                                "Service is marked for deletion; could not remove {}: {e}",
                                path.display()
                            );
                            break;
                        }
                    }
                }
            }
        }
    }
}
fn sc(raw: SC_HANDLE) -> io::Result<Sc> {
    if raw.is_null() {
        Err(win::last())
    } else {
        Ok(Sc(raw))
    }
}
pub fn request(options: &Options) -> Request {
    Request {
        system: options.system,
        interactive: options.interactive,
        detached: options.detached,
        priority: options.priority,
        affinity: options.affinity,
        workdir: options.workdir.clone(),
        command: options.command.clone(),
    }
}
pub fn run(options: &Options, host: Option<&str>, stream_stdin: bool) -> io::Result<u32> {
    let id = win::random_id()?;
    let service = options
        .service_name
        .clone()
        .unwrap_or_else(|| format!("RustExec_{}", &id[..12]));
    if service.is_empty()
        || service.len() > 64
        || !service
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c))
    {
        return Err(io::Error::other(
            "Service name must contain 1-64 ASCII letters, digits, '_' or '-'",
        ));
    }
    let pipe = format!("rsexec-{id}");
    let exe = std::env::current_exe()?;
    let mut req = request(options);
    let mut copied = None;
    let service_path = if let Some(host) = host {
        let name = format!("rsexec-{id}.exe");
        let destination = PathBuf::from(format!("\\\\{host}\\ADMIN$\\{name}"));
        let mut guard = RemoveRemoteFile::new(destination.clone());
        win::copy_replace(&exe, &destination, false)?;
        guard.disarm();
        copied = Some(destination);
        trace("Temporary service executable copied");
        format!("%SystemRoot%\\{name}")
    } else {
        exe.to_string_lossy().into_owned()
    };
    let result = (|| {
        if options.copy {
            let host = host.ok_or_else(|| io::Error::other("-c requires a remote target"))?;
            let source = std::path::Path::new(&req.command[0]);
            let basename = source
                .file_name()
                .ok_or_else(|| io::Error::other("Copy source has no filename"))?
                .to_string_lossy();
            win::validate_remote_basename(&basename)?;
            let destination = PathBuf::from(format!("\\\\{host}\\ADMIN$\\{basename}"));
            win::copy_replace(source, &destination, options.force_copy)?;
            // Resolve the remote executable via a distinct request field: service expands this
            // known prefix on the target, not against the client's Windows directory.
            req.command[0] = format!("%SystemRoot%\\{basename}");
        }
        let machine = host.map(|h| win::wide(&format!("\\\\{h}")));
        let manager = sc(unsafe {
            OpenSCManagerW(
                machine.as_ref().map_or(null(), |m| m.as_ptr()),
                null(),
                SC_MANAGER_CREATE_SERVICE,
            )
        })?;
        let launch = protocol::command_line(&[
            service_path.clone(),
            "--service".into(),
            service.clone(),
            pipe.clone(),
            options.timeout_secs.to_string(),
        ]);
        let handle = sc(unsafe {
            CreateServiceW(
                manager.0,
                win::wide(&service).as_ptr(),
                win::wide(&format!("RustExec temporary command ({})", &id[..12])).as_ptr(),
                SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                win::wide(&launch).as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
            )
        })?;
        let mut lease = Lease {
            service: Arc::new(handle),
            copied: copied.take(),
            complete: false,
        };
        unsafe {
            win::check(StartServiceW(lease.service.0, 0, null()))?;
        }
        trace("Service started");
        // Demand-start service is marked for deletion immediately; an interrupted client
        // cannot leave an installed auto-start service behind.
        unsafe {
            win::check(DeleteService(lease.service.0))?;
        }
        let timeout = Duration::from_secs(options.timeout_secs as u64);
        let name = format!("\\\\{}\\pipe\\{pipe}", host.unwrap_or("."));
        let mut ctl = win::open_pipe(&name, timeout)?;
        trace("Control pipe connected");
        req.write(&mut ctl)?;
        CANCEL.store(false, Ordering::SeqCst);
        CANCEL_COUNT.store(0, Ordering::SeqCst);
        unsafe {
            win::check(SetConsoleCtrlHandler(Some(ctrl), 1))?;
        }
        let active = Arc::new(AtomicBool::new(true));
        let watch_active = active.clone();
        let svc = lease.service.clone();
        let watcher = std::thread::spawn(move || {
            while watch_active.load(Ordering::SeqCst) {
                if CANCEL.load(Ordering::SeqCst) {
                    unsafe {
                        let mut s = std::mem::zeroed();
                        ControlService(svc.0, SERVICE_CONTROL_STOP, &mut s);
                    }
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let mut relays = JoinRelays(Vec::new());
        let execution = (|| {
            let first = protocol::get_u32(&mut ctl)?;
            trace(&format!("First service response: {first}"));
            if first == 3 {
                return Err(io::Error::other(protocol::get_string(&mut ctl)?));
            }
            if first == 1 {
                let mut input = win::open_pipe(&format!("{name}-in"), timeout)?;
                trace("stdin pipe connected");
                input.write_all(&[1])?;
                let mut ack = [0];
                input.read_exact(&mut ack)?;
                if ack != [1] {
                    return Err(io::Error::other("stdin handshake rejected"));
                }
                let mut output = win::open_pipe(&format!("{name}-out"), timeout)?;
                trace("stdout pipe connected");
                output.write_all(&[1])?;
                output.read_exact(&mut ack)?;
                if ack != [1] {
                    return Err(io::Error::other("stdout handshake rejected"));
                }
                let mut error = win::open_pipe(&format!("{name}-err"), timeout)?;
                trace("stderr pipe connected");
                error.write_all(&[1])?;
                error.read_exact(&mut ack)?;
                if ack != [1] {
                    return Err(io::Error::other("stderr handshake rejected"));
                }
                if stream_stdin {
                    // Detached: joining this would wait on the console after the child exits.
                    // Later hosts do not read stdin again.
                    std::thread::spawn(move || {
                        let _ = io::copy(&mut io::stdin().lock(), &mut input);
                    });
                } else {
                    drop(input);
                }
                relays.push(std::thread::spawn(move || {
                    io::copy(&mut output, &mut io::stdout().lock()).map(|_| ())
                }));
                relays.push(std::thread::spawn(move || {
                    io::copy(&mut error, &mut io::stderr().lock()).map(|_| ())
                }));
                let kind = protocol::get_u32(&mut ctl)?;
                if kind == 3 {
                    return Err(io::Error::other(protocol::get_string(&mut ctl)?));
                }
                if kind != 4 {
                    return Err(io::Error::other("Expected process-start response"));
                }
            } else if first != 4 {
                return Err(io::Error::other("Unexpected service response"));
            }
            let pid = protocol::get_u32(&mut ctl)?;
            eprintln!(
                "Process {pid} started on {}",
                host.unwrap_or("local system")
            );
            if req.detached {
                return Ok(pid);
            }
            let kind = protocol::get_u32(&mut ctl)?;
            if kind == 3 {
                return Err(io::Error::other(protocol::get_string(&mut ctl)?));
            }
            if kind != 2 {
                return Err(io::Error::other("Expected exit status"));
            }
            let code = protocol::get_u32(&mut ctl)?;
            Ok(code)
        })();
        let relay_result = relays.finish();
        active.store(false, Ordering::SeqCst);
        let _ = watcher.join();
        unsafe {
            SetConsoleCtrlHandler(Some(ctrl), 0);
        }
        lease.complete = execution.is_ok() && relay_result.is_ok();
        execution.and_then(|code| relay_result.map(|_| code))
    })();
    if let Some(path) = copied {
        let _ = std::fs::remove_file(path);
    }
    result
}
