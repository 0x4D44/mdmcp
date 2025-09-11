use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

fn policy_yaml_with_command(root: &str, log_path: &str, with_echo: bool) -> String {
    let (exec, fixed) = if cfg!(target_os = "windows") {
        ("C:/Windows/System32/cmd.exe", "fixed: ['-invalid-','-invalid-']") // unused placeholder when no echo
    } else {
        ("/bin/echo", "fixed: []")
    };
    let logging = format!("logging:\n  file: \"{}\"\n", log_path.replace('\\', "/"));
    let base = format!(
        "version: 1\nallowed_roots:\n  - {}\nwrite_rules: []\n{}commands:\n",
        root,
        logging
    );
    if with_echo {
        if cfg!(target_os = "windows") {
            format!(
                "{}  - id: echo\n    exec: C:/Windows/System32/cmd.exe\n    args:\n      fixed: ['/c','echo']\n    platform: ['windows']\n",
                base
            )
        } else {
            format!(
                "{}  - id: echo\n    exec: /bin/echo\n    args:\n      {}\n    platform: ['linux','macos']\n",
                base, fixed
            )
        }
    } else {
        base
    }
}

fn send_line(stdin: &mut impl Write, json: &str) {
    writeln!(stdin, "{}", json).expect("write json line");
    stdin.flush().ok();
}

#[test]
fn e2e_reload_policy_adds_command() {
    let server_bin = env!("CARGO_BIN_EXE_mdmcpsrvr");
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().to_string_lossy().to_string();
    let policy_path = temp.path().join("policy.yaml");
    let log_path = temp.path().join("audit.log");
    // Start with no commands
    std::fs::write(&policy_path, policy_yaml_with_command(&root, &log_path.to_string_lossy(), false)).unwrap();
    println!("E2E audit log file: {}", log_path.display());

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

    // tools/list before reload: run_command tool may exist but with empty enum/oneOf
    let list1 = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    send_line(&mut stdin, &list1.to_string());

    // Update policy to add echo command
    std::fs::write(&policy_path, policy_yaml_with_command(&root, &log_path.to_string_lossy(), true)).unwrap();

    // tools/call reload_policy
    let reload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "reload_policy", "arguments": {}}
    });
    send_line(&mut stdin, &reload.to_string());

    // tools/list after reload: expect run_command enum to contain echo
    let list2 = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/list",
        "params": {}
    });
    send_line(&mut stdin, &list2.to_string());

    let mut saw_reload_ok = false;
    let mut has_echo_after = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    while std::time::Instant::now() < deadline && !(saw_reload_ok && has_echo_after) {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                let v: serde_json::Value = serde_json::from_str(&line).expect("json resp");
                if v.get("id") == Some(&serde_json::json!(3)) {
                    assert!(v.get("error").is_none(), "reload_policy error: {}", line);
                    saw_reload_ok = true;
                }
                if v.get("id") == Some(&serde_json::json!(4)) {
                    assert!(v.get("error").is_none(), "tools/list error: {}", line);
                    let tools = v["result"]["tools"].as_array().cloned().unwrap_or_default();
                    let run_tool = tools.iter().find(|t| t["name"] == "run_command");
                    if let Some(rt) = run_tool {
                        // Look inside oneOf/enum string set
                        let oneof = rt["inputSchema"]["properties"]["command_id"]["oneOf"].as_array().cloned().unwrap_or_default();
                        let enum_ids = rt["inputSchema"]["properties"]["command_id"]["enum"].as_array().cloned().unwrap_or_default();
                        let oneof_has_echo = oneof.iter().any(|e| e.get("const") == Some(&serde_json::json!("echo")));
                        let enum_has_echo = enum_ids.iter().any(|e| *e == serde_json::json!("echo"));
                        has_echo_after = oneof_has_echo || enum_has_echo;
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }

    assert!(saw_reload_ok && has_echo_after, "reload and echo not verified");
    assert!(std::fs::metadata(&log_path).is_ok(), "audit log not created at {}", log_path.display());

    let _ = child.kill();
    if std::env::var("MDMCP_E2E_KEEP_TMP").is_ok() {
        let kept = temp.into_path();
        println!("E2E temp dir kept: {}", kept.display());
    }
}
