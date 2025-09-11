use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

fn make_policy_yaml(root: &str, log_path: &str) -> String {
    if cfg!(target_os = "windows") {
        format!(
            "version: 1\nallowed_roots:\n  - {}\nwrite_rules: []\nlogging:\n  file: {}\ncommands: []\n",
            root,
            yaml_escape(&win_to_yaml_path(log_path))
        )
    } else {
        format!(
            "version: 1\nallowed_roots:\n  - {}\nwrite_rules: []\nlogging:\n  file: {}\ncommands: []\n",
            root,
            yaml_escape(log_path)
        )
    }
}

fn yaml_escape(p: &str) -> String { format!("\"{}\"", p.replace('\\', "/")) }
#[cfg(target_os = "windows")]
fn win_to_yaml_path(p: &str) -> String { p.replace('\\', "/") }
#[cfg(not(target_os = "windows"))]
fn win_to_yaml_path(p: &str) -> String { p.to_string() }

fn send_line(stdin: &mut impl Write, json: &str) {
    writeln!(stdin, "{}", json).expect("write json line");
    stdin.flush().ok();
}

#[test]
fn e2e_file_tools_read_and_policy_deny() {
    let server_bin = env!("CARGO_BIN_EXE_mdmcpsrvr");
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().to_string_lossy().to_string();
    let policy_path = temp.path().join("policy.yaml");
    let log_path = temp.path().join("audit.log");
    std::fs::write(&policy_path, make_policy_yaml(&root, &log_path.to_string_lossy())).expect("write policy");
    println!("E2E audit log file: {}", log_path.display());

    // Create a test file inside allowed root
    let test_file = temp.path().join("hello.txt");
    std::fs::write(&test_file, b"Hello E2E File Tools").unwrap();

    let mut child = Command::new(server_bin)
        .arg("--config")
        .arg(&policy_path)
        .arg("--stdio")
        .arg("--log-level")
        .arg("error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(l) = line { let _ = tx.send(l); } else { break; }
        }
    });

    // initialize
    let init = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "e2e", "version": "0.0.1"}
        }
    });
    send_line(&mut stdin, &init.to_string());

    // read_bytes tool on allowed file
    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "read_bytes",
            "arguments": {"path": test_file.to_string_lossy(), "offset": 0, "length": 64}
        }
    });
    send_line(&mut stdin, &call.to_string());

    // fs.read on forbidden path
    let forbidden_path = if cfg!(target_os = "windows") { "C:/" } else { "/" };
    let fs_read = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "fs.read",
        "params": {"path": forbidden_path, "encoding": "utf8"}
    });
    send_line(&mut stdin, &fs_read.to_string());

    // Collect responses: expect success for id=2 and error for id=3
    let mut saw_file_ok = false;
    let mut saw_policy_deny = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline && (!saw_file_ok || !saw_policy_deny) {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                let v: serde_json::Value = serde_json::from_str(&line).expect("json resp");
                match v.get("id") {
                    Some(id) if *id == serde_json::json!(2) => {
                        assert!(v.get("error").is_none(), "read_bytes error: {}", line);
                        let blocks = v["result"]["content"].as_array().cloned().unwrap_or_default();
                        let text = blocks
                            .iter()
                            .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                            .collect::<Vec<_>>()
                            .join("\n");
                        assert!(text.contains("Hello E2E File Tools"), "unexpected content: {}", text);
                        saw_file_ok = true;
                    }
                    Some(id) if *id == serde_json::json!(3) => {
                        // Expect an error for policy deny
                        let err = v.get("error");
                        assert!(err.is_some(), "fs.read expected error: {}", line);
                        saw_policy_deny = true;
                    }
                    _ => {}
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }

    assert!(saw_file_ok && saw_policy_deny, "did not receive expected responses");
    assert!(std::fs::metadata(&log_path).is_ok(), "audit log not created at {}", log_path.display());

    let _ = child.kill();
    if std::env::var("MDMCP_E2E_KEEP_TMP").is_ok() {
        let kept = temp.into_path();
        println!("E2E temp dir kept: {}", kept.display());
    }
}
