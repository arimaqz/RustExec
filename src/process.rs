//! Windows child creation. Profiles are not loaded for an explicit user token.
use crate::{
    protocol::{Request, process_command_line},
    win::{Handle, check, last, wide},
};
use std::{
    ffi::c_void,
    fs::File,
    io,
    mem::{size_of, zeroed},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, GENERIC_READ, GENERIC_WRITE, HANDLE,
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_OBJECT_0,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
    System::{
        Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
        JobObjects::*,
        Pipes::CreatePipe,
        Threading::*,
    },
};

pub struct Child {
    pub process: Handle,
    job: Option<Handle>,
    pub pid: u32,
    pub stdin: Option<File>,
    pub stdout: Option<File>,
    pub stderr: Option<File>,
}
impl Child {
    pub fn wait(&self) -> io::Result<u32> {
        unsafe {
            if WaitForSingleObject(self.process.0, INFINITE) != WAIT_OBJECT_0 {
                return Err(last());
            }
            let mut code = 0;
            check(GetExitCodeProcess(self.process.0, &mut code))?;
            Ok(code)
        }
    }
    pub fn close_job(&mut self) {
        drop(self.job.take());
    }
    pub fn job_handle(&self) -> usize {
        self.job.as_ref().map(|j| j.0 as usize).unwrap_or(0)
    }
}

struct Environment(*mut c_void);
impl Drop for Environment {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                DestroyEnvironmentBlock(self.0);
            }
        }
    }
}

// Explicit inheritance list prevents unrelated inheritable service/IPC handles
// from reaching the new process, including when multiple clients run concurrently.
struct Attributes {
    storage: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
    fn new(handles: &[HANDLE]) -> io::Result<Self> {
        unsafe {
            let mut bytes = 0;
            InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes);
            if bytes == 0 {
                return Err(last());
            }
            let mut result = Self {
                storage: vec![0; bytes.div_ceil(size_of::<usize>())],
                initialized: false,
            };
            check(InitializeProcThreadAttributeList(
                result.ptr(),
                1,
                0,
                &mut bytes,
            ))?;
            result.initialized = true;
            check(UpdateProcThreadAttribute(
                result.ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                null_mut(),
                null(),
            ))?;
            Ok(result)
        }
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.ptr());
            }
        }
    }
}

fn pipe(parent_writes: bool) -> io::Result<(Handle, Handle)> {
    unsafe {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let (mut read, mut write) = (null_mut(), null_mut());
        check(CreatePipe(&mut read, &mut write, &sa, 0))?;
        let read = Handle::new(read)?;
        let write = Handle::new(write)?;
        let (parent, child) = if parent_writes {
            (write, read)
        } else {
            (read, write)
        };
        check(SetHandleInformation(parent.0, HANDLE_FLAG_INHERIT, 0))?;
        Ok((parent, child))
    }
}

fn null_handle() -> io::Result<Handle> {
    unsafe {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        Handle::new(CreateFileW(
            wide("NUL").as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        ))
    }
}

fn duplicate(raw: HANDLE) -> io::Result<Handle> {
    unsafe {
        let current = GetCurrentProcess();
        let mut copy = null_mut();
        check(DuplicateHandle(
            current,
            raw,
            current,
            &mut copy,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        ))?;
        Handle::new(copy)
    }
}

fn kill_on_close_job() -> io::Result<Handle> {
    unsafe {
        let job = Handle::new(CreateJobObjectW(null(), null()))?;
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        check(SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ))?;
        Ok(job)
    }
}

pub fn spawn(req: &Request, token: Option<HANDLE>, redirect: bool) -> io::Result<Child> {
    if req.command.is_empty()
        || req.command[0].is_empty()
        || req.command.iter().any(|s| s.contains('\0'))
        || req.workdir.as_ref().is_some_and(|s| s.contains('\0'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid executable, command, or working directory",
        ));
    }
    let mut line = wide(&process_command_line(&req.command));
    if line.len() > 32767 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Command line exceeds Windows UTF-16 limit",
        ));
    }
    let directory = req.workdir.as_deref().map(wide);
    let mut desktop = wide("winsta0\\default");
    let mut child_handles = Vec::new();
    let (mut stdin, mut stdout, mut stderr) = (None, None, None);
    // Windows cannot inherit service-session handles into another session.
    // Desktop mode gets its own console and does not use pipe redirection.
    if req.interactive.is_some() && token.is_some() {
    } else if req.detached {
        child_handles.push(null_handle()?);
        child_handles.push(null_handle()?);
        child_handles.push(null_handle()?);
    } else if redirect {
        let (input, child_input) = pipe(true)?;
        let (output, child_output) = pipe(false)?;
        let (error, child_error) = pipe(false)?;
        stdin = Some(input.into_file());
        stdout = Some(output.into_file());
        stderr = Some(error.into_file());
        child_handles.extend([child_input, child_output, child_error]);
    } else {
        let standard = unsafe {
            [
                GetStdHandle(STD_INPUT_HANDLE),
                GetStdHandle(STD_OUTPUT_HANDLE),
                GetStdHandle(STD_ERROR_HANDLE),
            ]
        };
        if standard
            .iter()
            .all(|h| !h.is_null() && *h != INVALID_HANDLE_VALUE)
        {
            for h in standard {
                child_handles.push(duplicate(h)?);
            }
        }
    }
    let inherited: Vec<HANDLE> = child_handles.iter().map(|h| h.0).collect();
    let mut attributes = if inherited.is_empty() {
        None
    } else {
        Some(Attributes::new(&inherited)?)
    };
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = if attributes.is_some() {
        size_of::<STARTUPINFOEXW>()
    } else {
        size_of::<STARTUPINFOW>()
    } as u32;
    if let Some(attributes) = &mut attributes {
        startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = inherited[0];
        startup.StartupInfo.hStdOutput = inherited[1];
        startup.StartupInfo.hStdError = inherited[2];
        startup.lpAttributeList = attributes.ptr();
    }
    if req.interactive.is_some() {
        startup.StartupInfo.lpDesktop = desktop.as_mut_ptr();
    }
    let mut env = Environment(null_mut());
    if let Some(token) = token {
        unsafe {
            check(CreateEnvironmentBlock(&mut env.0, token, 0))?;
        }
    }
    let mut flags = CREATE_SUSPENDED;
    if attributes.is_some() {
        flags |= EXTENDED_STARTUPINFO_PRESENT;
    }
    if token.is_some() {
        flags |= CREATE_UNICODE_ENVIRONMENT;
    }
    if req.interactive.is_some() {
        flags |= CREATE_NEW_CONSOLE;
    } else if req.detached {
        flags |= CREATE_NO_WINDOW;
    }
    let mut information: PROCESS_INFORMATION = unsafe { zeroed() };
    unsafe {
        let directory = directory.as_ref().map_or(null(), |s| s.as_ptr());
        let inherit = i32::from(attributes.is_some());
        let ok = if let Some(token) = token {
            CreateProcessAsUserW(
                token,
                null(),
                line.as_mut_ptr(),
                null(),
                null(),
                inherit,
                flags,
                env.0,
                directory,
                &startup.StartupInfo,
                &mut information,
            )
        } else {
            CreateProcessW(
                null(),
                line.as_mut_ptr(),
                null(),
                null(),
                inherit,
                flags,
                null(),
                directory,
                &startup.StartupInfo,
                &mut information,
            )
        };
        check(ok)?;
    }
    let process = Handle::new(information.hProcess)?;
    let thread = Handle::new(information.hThread)?;
    let job = if req.detached {
        None
    } else {
        Some(kill_on_close_job()?)
    };
    let configure = || -> io::Result<()> {
        unsafe {
            if let Some(job) = &job {
                check(AssignProcessToJobObject(job.0, process.0))?;
            }
            // PROCESS_MODE_BACKGROUND_BEGIN is valid only for the current
            // process. A child receives BELOW_NORMAL instead; IO priority is
            // unchanged (documented compatibility limitation).
            let priority = if req.priority == 0x0010_0000 {
                BELOW_NORMAL_PRIORITY_CLASS
            } else {
                req.priority
            };
            check(SetPriorityClass(process.0, priority))?;
            if let Some(mask) = req.affinity {
                check(SetProcessAffinityMask(process.0, mask))?;
            }
            if ResumeThread(thread.0) == u32::MAX {
                return Err(last());
            }
        }
        Ok(())
    };
    if let Err(error) = configure() {
        unsafe {
            TerminateProcess(process.0, 1);
            WaitForSingleObject(process.0, 5000);
        }
        return Err(error);
    }
    // Close the parent's copies of child pipe ends immediately so readers see
    // EOF when the process exits, rather than waiting on these extra handles.
    drop(child_handles);
    Ok(Child {
        process,
        job,
        pid: information.dwProcessId,
        stdin,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    #[test]
    fn cmd_script_preserves_quoted_file_paths() {
        let file = std::env::temp_dir().join(format!(
            "rsexec quoted {}.txt",
            crate::win::random_id().unwrap()
        ));
        let script = format!("echo QUOTED_PATH_OK>\"{}\"", file.display());
        let child = spawn(&request(&["/d", "/q", "/c", &script]), None, true).unwrap();
        assert_eq!(child.wait().unwrap(), 0);
        let content = std::fs::read_to_string(&file).unwrap();
        std::fs::remove_file(&file).unwrap();
        assert!(content.contains("QUOTED_PATH_OK"));
    }

    fn request(arguments: &[&str]) -> Request {
        let root = std::env::var("SystemRoot").expect("Windows system directory");
        let executable = format!("{root}\\System32\\cmd.exe");
        Request {
            system: false,
            interactive: None,
            detached: false,
            priority: NORMAL_PRIORITY_CLASS,
            affinity: None,
            workdir: None,
            command: std::iter::once(executable)
                .chain(arguments.iter().map(|s| (*s).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn redirected_child_reports_exit_and_closes_streams() {
        let mut child = spawn(
            &request(&["/d", "/q", "/c", "echo output& echo error 1>&2& exit /b 37"]),
            None,
            true,
        )
        .unwrap();
        drop(child.stdin.take());
        let mut output = String::new();
        let mut error = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut error)
            .unwrap();
        assert_eq!(child.wait().unwrap(), 37);
        assert_eq!(output.trim(), "output");
        assert_eq!(error.trim(), "error");
    }

    #[test]
    fn detached_child_has_no_parent_pipe_handles() {
        let mut req = request(&["/d", "/q", "/c", "exit", "0"]);
        req.detached = true;
        let child = spawn(&req, None, true).unwrap();
        assert!(child.stdin.is_none() && child.stdout.is_none() && child.stderr.is_none());
        assert_ne!(child.pid, 0);
        assert_eq!(child.wait().unwrap(), 0);
    }

    #[test]
    fn job_closes_grandchild_stdout_after_parent_exits() {
        let mut child = spawn(
            &request(&[
                "/d",
                "/q",
                "/c",
                "start /b cmd /d /q /c ping -n 120 127.0.0.1",
            ]),
            None,
            true,
        )
        .unwrap();
        drop(child.stdin.take());
        let mut stdout = child.stdout.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            stdout.read(&mut buf)
        });
        assert_eq!(child.wait().unwrap(), 0);
        child.close_job();
        let _ = reader.join().expect("reader thread panicked");
    }
}
