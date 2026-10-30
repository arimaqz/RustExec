use std::{
    fs::File,
    io::{self, IsTerminal, Read, Write},
    os::windows::io::{FromRawHandle, RawHandle},
    path::Path,
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Console::*, Pipes::*, RemoteDesktop::*, Threading::*},
};
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
pub fn last() -> io::Error {
    io::Error::last_os_error()
}
pub fn check(ok: i32) -> io::Result<()> {
    if ok == 0 { Err(last()) } else { Ok(()) }
}
pub struct Handle(pub HANDLE);
impl Handle {
    pub fn new(h: HANDLE) -> io::Result<Self> {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            Err(last())
        } else {
            Ok(Self(h))
        }
    }
    pub fn into_file(self) -> File {
        let h = self.0;
        std::mem::forget(self);
        unsafe { File::from_raw_handle(h as RawHandle) }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
pub struct Credentials {
    token: Handle,
}
impl Credentials {
    pub fn network(user: &str, password: &str) -> io::Result<Self> {
        let (domain, name) = user
            .split_once('\\')
            .map_or((None, user), |(d, n)| (Some(d), n));
        let name = wide(name);
        let domain = domain.map(wide);
        let mut password = wide(password);
        let mut token = null_mut();
        let ok = unsafe {
            LogonUserW(
                name.as_ptr(),
                domain.as_ref().map_or(null(), |d| d.as_ptr()),
                password.as_ptr(),
                LOGON32_LOGON_NEW_CREDENTIALS,
                LOGON32_PROVIDER_WINNT50,
                &mut token,
            )
        };
        // Prevent the compiler from eliding the temporary UTF-16 password wipe.
        for c in &mut password {
            unsafe {
                std::ptr::write_volatile(c, 0);
            }
        }
        check(ok)?;
        let token = Handle::new(token)?;
        unsafe {
            check(ImpersonateLoggedOnUser(token.0))?;
        }
        Ok(Self { token })
    }
}
impl Drop for Credentials {
    fn drop(&mut self) {
        unsafe {
            RevertToSelf();
        }
        let _ = &self.token;
    }
}
pub fn prompt_password() -> io::Result<String> {
    if !io::stdin().is_terminal() {
        return Err(io::Error::other(
            "-u without -p needs an interactive console",
        ));
    }
    let h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0;
    unsafe {
        check(GetConsoleMode(h, &mut mode))?;
        check(SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT))?;
    }
    struct Restore(HANDLE, u32);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                SetConsoleMode(self.0, self.1);
            }
        }
    }
    let restore = Restore(h, mode);
    eprint!("Password: ");
    io::stderr().flush()?;
    let mut s = String::new();
    let read = io::stdin().read_line(&mut s);
    drop(restore);
    eprintln!();
    read?;
    while s.ends_with(['\r', '\n']) {
        s.pop();
    }
    Ok(s)
}
pub fn token_sid(token: HANDLE) -> io::Result<Vec<u8>> {
    unsafe {
        let mut n = 0;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut n);
        if n == 0 {
            return Err(last());
        }
        let mut storage = vec![0usize; (n as usize).div_ceil(std::mem::size_of::<usize>())];
        check(GetTokenInformation(
            token,
            TokenUser,
            storage.as_mut_ptr().cast(),
            n,
            &mut n,
        ))?;
        let user = &*storage.as_ptr().cast::<TOKEN_USER>();
        let n = GetLengthSid(user.User.Sid);
        let mut sid = vec![0; n as usize];
        check(CopySid(n, sid.as_mut_ptr().cast(), user.User.Sid))?;
        Ok(sid)
    }
}
pub fn pipe_token(pipe: HANDLE) -> io::Result<Handle> {
    unsafe {
        check(ImpersonateNamedPipeClient(pipe))?;
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                unsafe {
                    RevertToSelf();
                }
            }
        }
        let _revert = Revert;
        let mut raw = null_mut();
        check(OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            1,
            &mut raw,
        ))?;
        let source = Handle::new(raw)?;
        let mut sid = null_mut();
        check(ConvertStringSidToSidW(
            wide("S-1-5-32-544").as_ptr(),
            &mut sid,
        ))?;
        let mut admin = 0;
        let ok = CheckTokenMembership(source.0, sid, &mut admin);
        LocalFree(sid);
        check(ok)?;
        if admin == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Named-pipe caller must have an enabled Administrators SID",
            ));
        }
        let mut token = null_mut();
        check(DuplicateTokenEx(
            source.0,
            TOKEN_ALL_ACCESS,
            null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut token,
        ))?;
        Handle::new(token)
    }
}
pub fn system_token() -> io::Result<Handle> {
    unsafe {
        let mut raw = null_mut();
        check(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut raw,
        ))?;
        let raw = Handle::new(raw)?;
        let mut primary = null_mut();
        check(DuplicateTokenEx(
            raw.0,
            TOKEN_ALL_ACCESS,
            null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        ))?;
        Handle::new(primary)
    }
}
pub fn set_session(token: HANDLE, session: u32) -> io::Result<()> {
    let session = if session == u32::MAX {
        unsafe { WTSGetActiveConsoleSessionId() }
    } else {
        session
    };
    if session == u32::MAX {
        return Err(io::Error::other("No active console session"));
    }
    unsafe {
        check(SetTokenInformation(
            token,
            TokenSessionId,
            (&session as *const u32).cast(),
            4,
        ))
    }
}
pub fn new_pipe(name: &str) -> io::Result<Handle> {
    unsafe {
        let mut sd = null_mut();
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide("D:P(A;;GA;;;SY)(A;;GA;;;BA)").as_ptr(),
            1,
            &mut sd,
            null_mut(),
        ))?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let raw = CreateNamedPipeW(
            wide(name).as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
            1,
            65536,
            65536,
            30000,
            &sa,
        );
        let saved = last();
        LocalFree(sd);
        if raw == INVALID_HANDLE_VALUE {
            Err(saved)
        } else {
            Handle::new(raw)
        }
    }
}
pub fn accept(pipe: &Handle, timeout: Duration) -> io::Result<()> {
    let start = Instant::now();
    loop {
        unsafe {
            // In PIPE_NOWAIT mode TRUE only means the instance is listening.
            // Only ERROR_PIPE_CONNECTED establishes an actual connection.
            if ConnectNamedPipe(pipe.0, null_mut()) == 0 {
                match GetLastError() {
                    ERROR_PIPE_CONNECTED => break,
                    ERROR_PIPE_LISTENING => {}
                    _ => return Err(last()),
                }
            }
        }
        if start.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Named-pipe client did not connect",
            ));
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let mode = PIPE_READMODE_BYTE | PIPE_WAIT;
    unsafe { check(SetNamedPipeHandleState(pipe.0, &mode, null(), null())) }
}
pub fn open_pipe(name: &str, timeout: Duration) -> io::Result<File> {
    let start = Instant::now();
    loop {
        unsafe {
            let raw = CreateFileW(
                wide(name).as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                null_mut(),
            );
            if raw != INVALID_HANDLE_VALUE {
                return Ok(Handle::new(raw)?.into_file());
            }
            let e = GetLastError();
            if e != ERROR_FILE_NOT_FOUND && e != ERROR_PIPE_BUSY {
                return Err(last());
            }
        }
        if start.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Service pipe was not available",
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
pub fn connect_stream(pipe: Handle, sid: &[u8], timeout: Duration) -> io::Result<File> {
    accept(&pipe, timeout)?;
    let mut file = pipe.into_file();
    let mut hello = [0];
    file.read_exact(&mut hello)?;
    if hello[0] != 1 {
        return Err(io::Error::other("Invalid stream handshake"));
    }
    use std::os::windows::io::AsRawHandle;
    let token = pipe_token(file.as_raw_handle() as HANDLE)?;
    let peer = token_sid(token.0)?;
    if peer != sid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Stream caller differs from control caller",
        ));
    }
    // The peer must not close an empty stdin stream before authentication and
    // connection acceptance have completed on the server.
    file.write_all(&[1])?;
    Ok(file)
}

pub fn validate_remote_basename(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['\\', '/', ':'])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Remote filename must be a single path component without separators",
        ));
    }
    Ok(())
}

/// Copy `source` to `destination` without truncating an existing file until the
/// payload is complete. With `replace`, publish atomically over an existing file.
pub fn copy_replace(source: &Path, destination: &Path, replace: bool) -> io::Result<()> {
    let name = destination
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid destination path"))?;
    validate_remote_basename(name)?;
    if !replace && destination.try_exists()? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Destination already exists",
        ));
    }
    let id = random_id()?;
    let partial = destination.with_file_name(format!("{name}.{id}.partial"));
    let mut src = std::fs::File::open(source)?;
    let mut tmp = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)?;
    let copy_result = io::copy(&mut src, &mut tmp).and_then(|_| tmp.flush());
    if let Err(e) = copy_result {
        drop(tmp);
        let _ = std::fs::remove_file(&partial);
        return Err(e);
    }
    drop(tmp);
    let publish = || -> io::Result<()> {
        if replace {
            unsafe {
                check(MoveFileExW(
                    wide(&partial.to_string_lossy()).as_ptr(),
                    wide(&destination.to_string_lossy()).as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                ))?;
            }
        } else {
            std::fs::rename(&partial, destination)?;
        }
        Ok(())
    };
    if let Err(e) = publish() {
        let _ = std::fs::remove_file(&partial);
        return Err(e);
    }
    Ok(())
}

pub fn random_id() -> io::Result<String> {
    let mut b = [0u8; 16];
    let status = unsafe {
        windows_sys::Win32::Security::Cryptography::BCryptGenRandom(
            null_mut(),
            b.as_mut_ptr(),
            b.len() as u32,
            windows_sys::Win32::Security::Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "BCryptGenRandom failed: {status:#x}"
        )));
    }
    Ok(b.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonblocking_accept_waits_for_peer_and_ack_precedes_eof() {
        let name = format!("\\\\.\\pipe\\rsexec-regression-{}", random_id().unwrap());
        let server_name = name.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            // Default DACL allows this unelevated test user. Production pipes use
            // their explicit SYSTEM/Administrators DACL and authenticate the SID.
            let raw = unsafe {
                CreateNamedPipeW(
                    wide(&server_name).as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
                    1,
                    4096,
                    4096,
                    1000,
                    null(),
                )
            };
            let pipe = Handle::new(raw).unwrap();
            ready_tx.send(()).unwrap();
            accept(&pipe, Duration::from_secs(3)).unwrap();
            let mut f = pipe.into_file();
            let mut hello = [0];
            f.read_exact(&mut hello).unwrap();
            assert_eq!(hello, [1]);
            f.write_all(&[1]).unwrap();
            let mut remainder = vec![];
            f.read_to_end(&mut remainder).unwrap();
            assert!(remainder.is_empty());
        });
        ready_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let mut f = open_pipe(&name, Duration::from_secs(3)).unwrap();
        f.write_all(&[1]).unwrap();
        let mut ack = [0];
        f.read_exact(&mut ack).unwrap();
        assert_eq!(ack, [1]);
        drop(f);
        server.join().unwrap();
    }

    #[test]
    fn copy_replace_preserves_destination_on_failure() {
        let dir = std::env::temp_dir().join(format!("rsexec-copy-{}", random_id().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("target.bin");
        std::fs::write(&dest, b"KEEP").unwrap();
        assert!(copy_replace(Path::new("missing-source-file"), &dest, true).is_err());
        assert_eq!(std::fs::read(&dest).unwrap(), b"KEEP");
        let src = dir.join("source.bin");
        std::fs::write(&src, b"NEW").unwrap();
        copy_replace(&src, &dest, true).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"NEW");
        let fresh = dir.join("new.bin");
        copy_replace(&src, &fresh, false).unwrap();
        assert_eq!(std::fs::read(&fresh).unwrap(), b"NEW");
        assert!(copy_replace(&src, &fresh, false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore = "Requires explicitly supplied lab credentials and host"]
    fn authorized_lab_remove_test_copy() {
        let host = std::env::var("RSEXEC_TEST_HOST").expect("RSEXEC_TEST_HOST");
        let user = std::env::var("RSEXEC_TEST_USER").expect("RSEXEC_TEST_USER");
        let password = std::env::var("RSEXEC_TEST_PASSWORD").expect("RSEXEC_TEST_PASSWORD");
        let basename = std::env::var("RSEXEC_TEST_COPY_NAME").expect("RSEXEC_TEST_COPY_NAME");
        let id = basename
            .strip_prefix("rsexec lab probe ")
            .and_then(|s| s.strip_suffix(".exe"))
            .expect("Not a RustExec lab test filename");
        assert!(
            id.len() == 10 && id.bytes().all(|c| c.is_ascii_hexdigit()),
            "Unexpected test run ID"
        );
        assert!(!host.contains(['\\', '/']), "Invalid host");
        let _credentials = Credentials::network(&user, &password).unwrap();
        let exact_path = format!("\\\\{host}\\ADMIN$\\{basename}");
        match std::fs::remove_file(&exact_path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => panic!("Exact test artifact removal failed: {e}"),
        }
        assert!(!std::path::Path::new(&exact_path).try_exists().unwrap());
        println!("Removed exact lab copy: {basename}");
    }

    #[test]
    #[ignore = "Requires explicitly supplied lab credentials and host"]
    fn authorized_lab_cleanup() {
        use windows_sys::Win32::System::Services::*;
        let host = std::env::var("RSEXEC_TEST_HOST").expect("RSEXEC_TEST_HOST");
        let user = std::env::var("RSEXEC_TEST_USER").expect("RSEXEC_TEST_USER");
        let password = std::env::var("RSEXEC_TEST_PASSWORD").expect("RSEXEC_TEST_PASSWORD");
        let services = std::env::var("RSEXEC_TEST_SERVICES").expect("RSEXEC_TEST_SERVICES");
        let _credentials = Credentials::network(&user, &password).unwrap();
        let manager = unsafe {
            OpenSCManagerW(
                wide(&format!("\\\\{host}")).as_ptr(),
                null(),
                SC_MANAGER_CONNECT,
            )
        };
        assert!(!manager.is_null(), "SCM connection failed: {}", last());
        for name in services.split(',').filter(|s| !s.is_empty()) {
            let service =
                unsafe { OpenServiceW(manager, wide(name).as_ptr(), SERVICE_QUERY_STATUS) };
            if !service.is_null() {
                unsafe {
                    CloseServiceHandle(service);
                    CloseServiceHandle(manager);
                }
                panic!("Temporary service still present: {name}");
            }
            assert_eq!(
                unsafe { GetLastError() },
                ERROR_SERVICE_DOES_NOT_EXIST,
                "Unexpected service query failure for {name}"
            );
        }
        unsafe {
            CloseServiceHandle(manager);
        }
        let artifacts = std::fs::read_dir(format!("\\\\{host}\\ADMIN$"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                let s = e.file_name().to_string_lossy().to_lowercase();
                s.starts_with("rsexec-") && s.ends_with(".exe")
            })
            .map(|e| e.file_name())
            .collect::<Vec<_>>();
        assert!(
            artifacts.is_empty(),
            "Service artifacts remain: {artifacts:?}"
        );
        println!(
            "Confirmed {} temporary services absent; no rsexec service executables remain",
            services.split(',').filter(|s| !s.is_empty()).count()
        );
    }
}
