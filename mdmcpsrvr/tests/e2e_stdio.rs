use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

fn make_policy_yaml(root: &str, log_path: &str) -> String {
    if cfg!(target_os = "windows") {
        format!(
            "version: 1\nallowed_roots:\n  - {}\nwrite_rules: []\nlogging:\n  file: {}\ncommands:\n  - id: echo\n    exec: C:/Windows/System32/cmd.exe\n    args:\n      fixed: ['{}', '{}']\n    platform: ['windows']\n",
            root,
            yaml_escape(&win_to_yaml_path(log_path)),
            "/c",
            "echo"
        )
    } else {
        format!(
            "version: 1\nallowed_roots:\n  - {}\nwrite_rules: []\nlogging:\n  file: {}\ncommands:\n  - id: echo\n    exec: /bin/echo\n    args:\n      fixed: []\n    platform: ['linux', 'macos']\n",
            root,
            yaml_escape(log_path)
        )
    }
}

fn yaml_escape(p: &str) -> String {
    format!("\"{}\"", p.replace('\\', "/"))
}

#[cfg(target_os = "windows")]
fn win_to_yaml_path(p: &str) -> String {
    p.replace('\\', "/")
}
#[cfg(not(target_os = "windows"))]
fn win_to_yaml_path(p: &str) -> String {
    p.to_string()
}

fn send_line(stdin: &mut impl Write, json: &str) {
    writeln!(stdin, "{}", json).expect("write json line");
    stdin.flush().ok();
}

#[test]
fn e2e_stdio_initialize_tools_and_run_command() {
    // Path to the built mdmcpsrvr binary provided by Cargo
    let server_bin = env!("CARGO_BIN_EXE_mdmcpsrvr");

    // Temp policy
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().to_string_lossy().to_string();
    let policy_path = temp.path().join("policy.yaml");
    let log_path = temp.path().join("audit.log");
    std::fs::write(
        &policy_path,
        make_policy_yaml(&root, &log_path.to_string_lossy()),
    )
    .expect("write policy");

    // Print audit log location; visible with: cargo test -p mdmcpsrvr --test e2e_stdio -- --nocapture
    println!("E2E audit log file: {}", log_path.display());

    // Spawn server
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

    // Reader thread to collect stdout lines
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(l) = line {
                let _ = tx.send(l);
            } else {
                break;
            }
        }
    });

    // 1) initialize
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

    // 2) tools/list
    let list = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    send_line(&mut stdin, &list.to_string());

    // 3) tools/call run_command echo
    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "run_command",
            "arguments": {"command_id": "echo", "args": ["hello-e2e"]}
        }
    });
    send_line(&mut stdin, &call.to_string());

    // Collect responses until we see id=3 result
    let mut saw_init = false;
    let mut saw_list = false;
    let mut saw_run = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline && (!saw_run || !saw_init || !saw_list) {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                let v: serde_json::Value = serde_json::from_str(&line).expect("json resp");
                let id = v.get("id").cloned().unwrap_or(serde_json::json!(null));
                if id == serde_json::json!(1) {
                    assert!(v.get("error").is_none(), "init error: {}", line);
                    saw_init = true;
                } else if id == serde_json::json!(2) {
                    assert!(v.get("error").is_none(), "tools/list error: {}", line);
                    // Ensure run_command tool is offered
                    let tools = v["result"]["tools"].as_array().cloned().unwrap_or_default();
                    let has_run = tools.iter().any(|t| t["name"] == "run_command");
                    assert!(has_run, "run_command not in tools: {}", line);
                    saw_list = true;
                } else if id == serde_json::json!(3) {
                    assert!(v.get("error").is_none(), "tools/call error: {}", line);
                    // Check the content contains the echo text
                    let content = v["result"]["content"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    let text = content
                        .iter()
                        .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                        .collect::<Vec<_>>()
                        .join("\n");
                    assert!(text.contains("hello-e2e"), "unexpected output: {}", text);
                    saw_run = true;
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }

    assert!(
        saw_init && saw_list && saw_run,
        "did not receive all responses"
    );
    // Ensure audit log file was created
    assert!(
        std::fs::metadata(&log_path).is_ok(),
        "audit log not created at {}",
        log_path.display()
    );

    // Cleanup
    let _ = child.kill();
    let _ = child.wait();

    // Optionally persist temp dir for log inspection
    if std::env::var("MDMCP_E2E_KEEP_TMP").is_ok() {
        let kept = temp.keep();
        println!("E2E temp dir kept: {}", kept.display());
    }
}
