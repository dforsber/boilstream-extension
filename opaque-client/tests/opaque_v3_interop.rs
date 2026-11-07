//! New production C ABI against an unmodified OPAQUE 3 server in another process.
//! The old dependency is test-only and is never linked into our release library.
use opaque_client::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use std::{ptr, slice};

struct Peer {
    child: Child,
    input: ChildStdin,
    output: Arc<Mutex<BufReader<ChildStdout>>>,
}
impl Peer {
    fn new() -> Self {
        static BINARY: OnceLock<PathBuf> = OnceLock::new();
        let binary = BINARY.get_or_init(|| {
            let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let target = crate_dir.join("../build/legacy-peer");
            let status = Command::new(env!("CARGO"))
                .args(["build", "--locked", "--manifest-path"])
                .arg(crate_dir.join("tests/legacy-peer/Cargo.toml"))
                .arg("--target-dir")
                .arg(&target)
                .env("CARGO_BUILD_BUILD_DIR", target.join("build"))
                .status()
                .expect("Build legacy protocol peer");
            assert!(
                status.success(),
                "Legacy peer must build; never skip interoperability"
            );
            target.join("debug").join(format!(
                "opaque-v3-interop-peer{}",
                std::env::consts::EXE_SUFFIX
            ))
        });
        let mut child = Command::new(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = Arc::new(Mutex::new(BufReader::new(child.stdout.take().unwrap())));
        Self {
            child,
            input,
            output,
        }
    }
    fn request(&mut self, op: &str, bytes: &[u8]) -> Value {
        writeln!(
            self.input,
            "{}",
            json!({"op":op, "bytes":hex::encode(bytes)})
        )
        .unwrap();
        self.input.flush().unwrap();
        let reader = Arc::clone(&self.output);
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let read = reader.lock().unwrap().read_line(&mut line);
            let _ = sender.send((read, line));
        });
        // On timeout, unwinding drops Peer, kills the child and releases the reader.
        let (read, line) = receiver
            .recv_timeout(Duration::from_secs(60))
            .expect("Legacy peer response timed out");
        assert!(read.unwrap() > 0, "Legacy peer exited");
        serde_json::from_str(&line).unwrap()
    }
    fn message(&mut self, op: &str, bytes: &[u8]) -> Vec<u8> {
        hex::decode(self.request(op, bytes)["bytes"].as_str().unwrap()).unwrap()
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn empty() -> OpaqueBuffer {
    OpaqueBuffer {
        data: ptr::null_mut(),
        len: 0,
    }
}
fn bytes(b: &OpaqueBuffer) -> &[u8] {
    assert!(!b.data.is_null());
    unsafe { slice::from_raw_parts(b.data, b.len) }
}
fn exchange(password: &[u8], tamper: bool, old_record: bool) {
    let mut peer = Peer::new();
    let registered = b"synthetic-test-password";
    let mut export = empty();
    let expected_export = if old_record {
        peer.message("enroll-v3", registered)
    } else {
        let mut state = ptr::null_mut();
        let start = opaque_client_registration_start(
            registered.as_ptr().cast(),
            registered.len(),
            &mut state,
        );
        assert!(matches!(start.error, OpaqueError::Success));
        let response = peer.message("register", bytes(&start.buffer));
        opaque_free_buffer(start.buffer);
        let mut upload = empty();
        assert!(matches!(
            opaque_client_registration_finish(
                state,
                response.as_ptr(),
                response.len(),
                &mut upload,
                &mut export
            ),
            OpaqueError::Success
        ));
        assert_eq!(peer.request("save", bytes(&upload))["saved"], true);
        opaque_free_buffer(upload);
        bytes(&export).to_vec()
    };
    let mut login = ptr::null_mut();
    let start = opaque_client_login_start(password.as_ptr().cast(), password.len(), &mut login);
    assert!(matches!(start.error, OpaqueError::Success));
    let mut response = peer.message("login", bytes(&start.buffer));
    opaque_free_buffer(start.buffer);
    if tamper {
        *response.last_mut().unwrap() ^= 1;
    }
    let (mut finalization, mut session, mut login_export) = (empty(), empty(), empty());
    let result = opaque_client_login_finish(
        login,
        response.as_ptr(),
        response.len(),
        &mut finalization,
        &mut session,
        &mut login_export,
    );
    if password != registered || tamper {
        assert!(matches!(result, OpaqueError::ProtocolError));
        for b in [&finalization, &session, &login_export] {
            assert!(b.data.is_null());
            assert_eq!(b.len, 0);
        }
    } else {
        assert!(matches!(result, OpaqueError::Success));
        let expected = peer.request("finish", bytes(&finalization));
        assert_eq!(
            bytes(&session),
            hex::decode(expected["session_key"].as_str().unwrap()).unwrap()
        );
        assert_eq!(expected_export, bytes(&login_export));
        assert_eq!(session.len, 64);
    }
    for b in [finalization, session, login_export, export] {
        opaque_free_buffer(b);
    }
}
#[test]
fn production_client_authenticates_against_v3_server() {
    exchange(b"synthetic-test-password", false, false);
}
#[test]
fn v3_interop_rejects_wrong_password_without_keys() {
    exchange(b"wrong-test-password", false, true);
}
#[test]
fn v3_interop_rejects_tampered_proof_without_keys() {
    exchange(b"synthetic-test-password", true, true);
}

#[test]
fn existing_v3_password_record_authenticates_without_reset() {
    exchange(b"synthetic-test-password", false, true);
}
