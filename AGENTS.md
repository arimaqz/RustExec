# RustExec agent guide

`rsexec` is an independent Rust client and temporary SCM service. The crate is `rsexec` 0.1.0, edition 2024, Rust 1.88 or later. The only dependency is `windows-sys` 0.61.2. This is not Microsoft source and is not wire-compatible with `PSEXESVC`. The request magic is `RSEXEC01`. Application-level CryptoAPI encryption from the inspected binary is intentionally absent.

[README.md](README.md) is the user-facing behavior and compatibility reference. This file says where the code lives, how to verify a change, and which constraints must stay in place.

## Module map

- [src/main.rs](src/main.rs) — help, `--service` dispatch, local versus remote routing, exit codes (child code, detached PID, setup `1`, parse `2`)
- [src/cli.rs](src/cli.rs) — portable parsing; passwords and command arguments are redacted in `Debug`
- [src/protocol.rs](src/protocol.rs) — portable length-prefixed UTF-8 request and `cmd.exe /c` quoting
- [src/client.rs](src/client.rs) — copy to `ADMIN$`, SCM lease, stream relay, cleanup on drop
- [src/service.rs](src/service.rs) — dispatcher, token choice, stdio or desktop/detached paths
- [src/process.rs](src/process.rs) — suspended create, priority and affinity, restricted handle inheritance
- [src/win.rs](src/win.rs) — credentials, pipe DACL, admin SID check, `PIPE_NOWAIT` accept
- [scripts/Test-Lab.ps1](scripts/Test-Lab.ps1) — optional remote integration script; writes gitignored output under `lab-output/`

Windows-only modules are behind `#[cfg(windows)]`. CLI parsing and the wire format stay portable. Keep local static-analysis trees out of git (`analysis/` is gitignored).

## Verify

On x64 Windows with the MSVC linker:

```powershell
cargo test --locked
cargo clippy --offline --all-targets -- -D warnings
cargo build --locked --release
```

Non-Windows builds may run the CLI and protocol tests. Execution exits 1. Ignored lab tests and `Test-Lab.ps1` need an administrator-controlled host and must not store passwords in committed files. Desktop session, Ctrl-C, multi-host, and second-hop paths are not covered by CI.

## Invariants

- Credentials stay in the Windows logon context. They are not written into the pipe request, `Debug`, or committed JSON.
- Pipes use `D:P(A;;GA;;;SY)(A;;GA;;;BA)`. Each connection is impersonated, must have an enabled Administrators SID (`S-1-5-32-544`), and stream callers must match the control caller. `RevertToSelf` stays in a drop guard.
- `ConnectNamedPipe` in `PIPE_NOWAIT` is connected only on `ERROR_PIPE_CONNECTED`. The client waits for the stream acknowledgment before sending stdin.
- A raw `cmd.exe` or `cmd` `/c` or `/k` tail uses `/s` and one outer quote pair. Other commands use CRT argv quoting.
- Service names are 1–64 ASCII letters, digits, `_`, or `-`. An existing service is refused. The service executable is copied with `create_new` under a 128-bit id and removed by the client `Lease` drop. If removal fails, print the leftover path.
- `-c` copies are not deleted automatically. Unsupported PsExec flags stay rejected. `-accepteula` and `-nobanner` stay no-ops.
- Do not add the original `PsExec64.exe`, embedded `PSEXESVC`, or lab passwords to the tree.

## Change style

Match the existing modules: `io::Result` for runtime failures, `String` for parse errors, RAII `Drop` for Win32 handles, `unsafe` kept at the call site, and tests in the same file. Comment only where Windows semantics are easy to misread, such as pipe connect and the `cmd.exe` tail. Prefer no new crates. If a user-visible flag or limit changes, update the README compatibility section in the same change. Do not record a lab result that was not actually run.
