use crate::{
    process,
    protocol::{self, Request},
    win,
};
use std::{
    io::{self, Write},
    os::windows::io::AsRawHandle,
    ptr::null_mut,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::*,
    System::{JobObjects::*, Services::*, Threading::*},
};
static CONFIG: OnceLock<(String, String, u32)> = OnceLock::new();
static STATUS: AtomicUsize = AtomicUsize::new(0);
static CHILD: Mutex<Option<ActiveChild>> = Mutex::new(None);
static STOP: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
struct ActiveChild {
    process: usize,
    job: usize,
}

struct Running {
    process: usize,
    job: usize,
    finished: bool,
}
impl Drop for Running {
    fn drop(&mut self) {
        if let Ok(mut active) = CHILD.lock() {
            *active = None;
        }
        if !self.finished {
            terminate_handles(self.process, self.job);
        }
    }
}

fn terminate_handles(process: usize, job: usize) {
    unsafe {
        if job != 0 {
            TerminateJobObject(job as HANDLE, ERROR_CANCELLED);
        } else if process != 0 {
            TerminateProcess(process as HANDLE, ERROR_CANCELLED);
        }
    }
}

fn terminate_active_child() {
    if let Ok(guard) = CHILD.lock()
        && let Some(active) = *guard
    {
        terminate_handles(active.process, active.job);
    }
}

fn status(state: u32, error: u32) {
    let h = STATUS.load(Ordering::SeqCst) as SERVICE_STATUS_HANDLE;
    if h.is_null() {
        return;
    }
    let s = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: error,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
            1
        } else {
            0
        },
        dwWaitHint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
            30000
        } else {
            0
        },
    };
    unsafe {
        SetServiceStatus(h, &s);
    }
}
unsafe extern "system" fn control(
    code: u32,
    _event: u32,
    _data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    if code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN {
        STOP.store(true, Ordering::SeqCst);
        status(SERVICE_STOP_PENDING, 0);
        terminate_active_child();
    }
    NO_ERROR
}
fn terminate_child() {
    terminate_active_child();
}
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let (name, pipe, timeout) = CONFIG.get().unwrap();
    let h = unsafe {
        RegisterServiceCtrlHandlerExW(win::wide(name).as_ptr(), Some(control), null_mut())
    };
    if h.is_null() {
        return;
    }
    STATUS.store(h as usize, Ordering::SeqCst);
    status(SERVICE_START_PENDING, 0);
    status(SERVICE_RUNNING, 0);
    let result = serve(pipe, *timeout);
    status(
        SERVICE_STOPPED,
        result
            .err()
            .map(|e| e.raw_os_error().unwrap_or(ERROR_INVALID_DATA as i32))
            .unwrap_or(0) as u32,
    );
}
pub fn dispatch(name: String, pipe: String, timeout: u32) -> io::Result<()> {
    CONFIG
        .set((name.clone(), pipe, timeout))
        .map_err(|_| io::Error::other("Service already initialized"))?;
    let mut name = win::wide(&name);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    unsafe { win::check(StartServiceCtrlDispatcherW(table.as_ptr())) }
}
fn serve(pipe: &str, timeout: u32) -> io::Result<()> {
    let control = win::new_pipe(&format!("\\\\.\\pipe\\{pipe}"))?;
    win::accept(&control, Duration::from_secs(timeout as u64))?;
    let mut ctl = control.into_file();
    let request = Request::read(&mut ctl);
    let result = request.and_then(|request| execute(request, pipe, timeout, &mut ctl));
    if let Err(e) = &result {
        let _ = protocol::put_u32(&mut ctl, 3);
        let _ = protocol::put_string(&mut ctl, &e.to_string());
        let _ = ctl.flush();
    }
    result
}
fn track_child(child: &process::Child) -> io::Result<()> {
    *CHILD
        .lock()
        .map_err(|_| io::Error::other("Child lock poisoned"))? = Some(ActiveChild {
        process: child.process.0 as usize,
        job: child.job_handle(),
    });
    Ok(())
}

fn execute(
    mut request: Request,
    pipe: &str,
    timeout: u32,
    ctl: &mut std::fs::File,
) -> io::Result<()> {
    if let Some(name) = request.command[0].strip_prefix("%SystemRoot%\\") {
        let root = std::env::var("SystemRoot")
            .map_err(|_| io::Error::other("Service SystemRoot is not set"))?;
        request.command[0] = std::path::Path::new(&root)
            .join(name)
            .to_string_lossy()
            .into_owned();
    }
    let caller = win::pipe_token(ctl.as_raw_handle() as HANDLE)?;
    let sid = win::token_sid(caller.0)?;
    let token = if request.system {
        win::system_token()?
    } else {
        caller
    };
    if let Some(session) = request.interactive {
        win::set_session(token.0, session)?;
    }
    if request.detached || request.interactive.is_some() {
        let mut child = process::spawn(&request, Some(token.0), false)?;
        let job = child.job_handle();
        let mut running = Running {
            process: child.process.0 as usize,
            job,
            finished: request.detached,
        };
        if !request.detached {
            track_child(&child)?;
        }
        protocol::put_u32(ctl, 4)?;
        protocol::put_u32(ctl, child.pid)?;
        ctl.flush()?;
        if !request.detached {
            let code = child.wait()?;
            running.finished = true;
            *CHILD
                .lock()
                .map_err(|_| io::Error::other("Child lock poisoned"))? = None;
            protocol::put_u32(ctl, 2)?;
            protocol::put_u32(ctl, code)?;
            ctl.flush()?;
            child.close_job();
        }
        return Ok(());
    }
    let input = win::new_pipe(&format!("\\\\.\\pipe\\{pipe}-in"))?;
    let output = win::new_pipe(&format!("\\\\.\\pipe\\{pipe}-out"))?;
    let error = win::new_pipe(&format!("\\\\.\\pipe\\{pipe}-err"))?;
    protocol::put_u32(ctl, 1)?;
    ctl.flush()?;
    let deadline = Duration::from_secs(timeout as u64);
    let mut input = win::connect_stream(input, &sid, deadline)
        .map_err(|e| io::Error::new(e.kind(), format!("stdin pipe: {e}")))?;
    let mut output = win::connect_stream(output, &sid, deadline)
        .map_err(|e| io::Error::new(e.kind(), format!("stdout pipe: {e}")))?;
    let mut error = win::connect_stream(error, &sid, deadline)
        .map_err(|e| io::Error::new(e.kind(), format!("stderr pipe: {e}")))?;
    if STOP.load(Ordering::SeqCst) {
        return Err(io::Error::other("Service stopped before launch"));
    }
    let mut child = process::spawn(&request, Some(token.0), true)?;
    let job = child.job_handle();
    track_child(&child)?;
    let mut running = Running {
        process: child.process.0 as usize,
        job,
        finished: false,
    };
    protocol::put_u32(ctl, 4)?;
    protocol::put_u32(ctl, child.pid)?;
    ctl.flush()?;
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let stdin_copy: JoinHandle<()> = std::thread::spawn(move || {
        let _ = io::copy(&mut input, &mut stdin);
    });
    let out = std::thread::spawn(move || {
        let r = io::copy(&mut stdout, &mut output);
        if r.is_err() {
            terminate_child();
        }
        r
    });
    let err = std::thread::spawn(move || {
        let r = io::copy(&mut stderr, &mut error);
        if r.is_err() {
            terminate_child();
        }
        r
    });
    let code = child.wait();
    running.finished = code.is_ok();
    let exit = code?;
    *CHILD
        .lock()
        .map_err(|_| io::Error::other("Child lock poisoned"))? = None;
    protocol::put_u32(ctl, 2)?;
    protocol::put_u32(ctl, exit)?;
    ctl.flush()?;
    child.close_job();
    let _ = stdin_copy.join();
    let _ = out.join();
    let _ = err.join();
    Ok(())
}
