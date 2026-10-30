# RustExec

Independent Rust reconstruction of the core Windows process-execution architecture observed in a reference **PsExec64 2.43** build. This is original Rust source with its own client/service protocol, not Microsoft's source, an exact feature clone, or a PSEXESVC-compatible client. The reference binary and embedded Microsoft service are not included in this repository.

## Build and run

Use an x64 Windows MSVC Rust toolchain (Rust 1.88 or later) and the Windows linker/SDK. This build used Rust/Cargo 1.95.0. The sole direct dependency is `windows-sys` 0.61.2.

```powershell
cargo build --locked --release
cargo test --locked
.\target\release\rsexec.exe --help
.\target\release\rsexec.exe cmd.exe /d /c whoami
```

For a service-mode test, open an elevated PowerShell:

```powershell
.\target\release\rsexec.exe -s cmd.exe /d /c whoami
```

On a Windows host you administer, replace `SERVER` with its actual name:

```powershell
.\target\release\rsexec.exe \\SERVER cmd.exe /d /c whoami
.\target\release\rsexec.exe \\SERVER -u 'DOMAIN\Admin' cmd.exe /d /c whoami
.\target\release\rsexec.exe \\SERVER -s cmd.exe /d /c whoami
.\target\release\rsexec.exe \\SERVER -c 'C:\Tools\mytool.exe' argument1
```

`-u` without `-p` prompts with console echo disabled. Credentials establish a Windows new-credentials logon context for SMB and SCM; the password is not included in our pipe request. No UAC elevation or firewall configuration is performed by the tool. Remote service mode requires administrative access to `ADMIN$`, SMB named pipes and Service Control Manager, plus Windows rights to create the requested token/process.

## Implemented behavior

| Area | Behavior |
|---|---|
| Local execution | Direct Unicode Win32 process creation, inherited stdin/stdout/stderr, child exit code |
| Remote execution | Copy this executable to a unique `ADMIN$` filename; create and start a demand-start LocalSystem service; connect to its pipes |
| Identity | Service duplicates the authenticated admin pipe caller's token by default; `-s` selects the service's SYSTEM token |
| Console streams | Separate authenticated stdin, stdout, stderr pipes; byte streaming without console emulation |
| Desktop session | `-i [session]` changes the child token's session and selects `winsta0\default`; opens a separate console; no stdio forwarding in this mode |
| Copy | `-c` copies the requested executable into the target Windows directory; `-f` explicitly allows replacing that copied executable |
| Process settings | Working directory, one-based CPU affinity mask, CPU priority classes |
| Detached mode | `-d` returns the process ID, uses NUL streams outside desktop mode, and lets the child continue |
| Targets | Explicit host, comma-separated hosts, or a UTF-8 host file; multiple targets execute sequentially |
| Cleanup | Mark service for deletion immediately after startup; close service/process/pipe handles; stop failed executions; retry removal of the unique service executable |

Ordinary service-mode commands return the child's exit code. Detached mode returns its PID as the exit code. Setup failures return 1 and argument errors return 2. For multiple targets, the last observed nonzero result is returned; stdin is streamed as consumed rather than replayed for each target.

## Protocol and access checks

One executable acts as both client and service. SCM invokes its internal `--service` entry point. A per-run 128-bit random identifier names the control and standard-stream pipes. The control request uses a version magic (`RSEXEC01`), bounded UTF-8 strings, and explicit integer fields. Credentials are absent from that request.

Pipe DACLs allow SYSTEM and Administrators. The service impersonates each pipe connection to verify an enabled Administrators SID, then reverts. Stream connections must match the control caller's SID. A duplicated primary token is passed to `CreateProcessAsUserW`; handle inheritance is restricted to explicitly selected child handles. Process priority and affinity are set while the child is suspended, then it is resumed. A failed setup terminates the child.

The original has CryptoAPI application-level encryption and a different handshake; this reconstruction does **not** reproduce that encryption. Commands and stream bytes rely on the selected Windows SMB transport configuration for confidentiality. This protocol is not interchangeable with Microsoft's PSEXESVC.

## Compatibility limits

- `-h`, `-l`, `-e`, `-v`, `-g`, `-x`, wildcard/domain enumeration and local `-u` are not implemented and are rejected. `-accepteula` and `-nobanner` are accepted compatibility no-ops; this implementation has no Microsoft EULA dialog or banner.
- Account profiles are not loaded. User tokens obtained through SMB do not provide explicit second-hop credential delegation.
- Desktop execution has no standard-stream forwarding: Windows cannot inherit service-session handles into another session. Session-token privileges and desktop ACLs remain enforced.
- `-background` currently maps to below-normal CPU priority; it does not change memory or I/O priority.
- CPU affinity covers one `usize` mask, not multiple processor groups.
- `-n` controls pipe connection waits, not all operating-system SMB/RPC call durations or the child runtime.
- A pre-existing service of the requested name is refused, rather than reused or replaced. Service names accept up to 64 ASCII letters, digits, `_`, and `-`.
- Files copied with `-c` remain on the target. Only the unique service executable is automatically removed. A failed/abrupt run may leave that file; deletion failures report its path.
- Ctrl-C first asks the service to stop the child process tree (kill-on-close job). A second Ctrl-C returns control to the default handler so the client can exit. A client forcibly terminated by the OS may not complete cleanup.
- Use an absolute target executable path for reliable resolution. Token-based process creation uses the service's executable search path.
- Console transport is byte streaming, not ConPTY or a full terminal emulator. IPv6 host notation is currently unsupported.

## Verification performed

On Windows with the MSVC toolchain:

- `cargo test --locked`: unit tests for CLI parsing, protocol wire format, `cmd.exe` quoting, redirected stdio, detached handles, pipe connect ordering, atomic copy helpers, and job cleanup.
- `cargo clippy --offline --all-targets -- -D warnings`: passed.
- `cargo build --locked --release`: passed.

Two integration tests in `win.rs` (`authorized_lab_*`) are ignored by default. They require explicit environment variables and an administrator-controlled lab host; they do not run in CI.

Optional remote integration: [`scripts/Test-Lab.ps1`](scripts/Test-Lab.ps1) runs against a host you specify. It prompts for a password (secure string), writes reports under `lab-output/` (gitignored), and does not commit credentials or hostnames to the repository.

Regression coverage includes fixes for nonblocking pipe acceptance with empty stdin and for `cmd.exe /c` quoting with embedded path quotes.

Desktop-session execution, multihost use, second-hop network access, and Ctrl-C against a live remote service remain best verified on your own lab. Local `-s` without elevation correctly fails with access denied before service creation.

## Relevant references

- [Microsoft PsExec usage](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
- [Microsoft service startup lifecycle](https://learn.microsoft.com/en-us/windows/win32/services/starting-a-service)
- [Microsoft named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)

These describe the original tool and Windows interfaces. Behavior of this crate is defined by `src/`, not by any local reverse-engineering notes kept outside the repository.
