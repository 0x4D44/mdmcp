use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

fn make_policy_yaml(root: &str, log_path: &str) -> String {
    let log = format!("\"{}\"", log_path.replace('\\', "/"));
    format!(
        "version: 1\nallowed_roots:\n  - {}\nwrite_rules: []\nlogging:\n  file: {}\ncommands: []\n",
        root, log
    )
}

fn send_line(stdin: &mut impl Write, json: &str) {
    writeln!(stdin, "{}", json).expect("write json line");
    stdin.flush().ok();
}

#[test]
fn e2e_resources_and_server_info() {
    let server_bin = env!("CARGO_BIN_EXE_mdmcpsrvr");
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().to_string_lossy().to_string();
    let policy_path = temp.path().join("policy.yaml");
    let log_path = temp.path().join("audit.log");
    std::fs::write(
        &policy_path,
        make_policy_yaml(&root, &log_path.to_string_lossy()),
    )
    .unwrap();
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
            if let Ok(l) = line {
                let _ = tx.send(l);
            } else {
                break;
            }
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

    // server_info (json)
    let server_info = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "server_info", "arguments": {"format": "json"}}
    });
    send_line(&mut stdin, &server_info.to_string());

    // list_accessible_directories
    let list_dirs = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "list_accessible_directories", "arguments": {}}
    });
    send_line(&mut stdin, &list_dirs.to_string());

    // resources/list
    let res_list = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "resources/list",
        "params": {}
    });
    send_line(&mut stdin, &res_list.to_string());

    // resources/read mdmcp://commands/catalog
    let res_read = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "resources/read",
        "params": {"uri": "mdmcp://commands/catalog"}
    });
    send_line(&mut stdin, &res_read.to_string());

    let mut ok_info = false;
    let mut ok_dirs = false;
    let mut ok_res_list = false;
    let mut ok_res_read = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    while std::time::Instant::now() < deadline
        && !(ok_info && ok_dirs && ok_res_list && ok_res_read)
    {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                let v: serde_json::Value = serde_json::from_str(&line).expect("json resp");
                match v.get("id") {
                    Some(id) if *id == serde_json::json!(2) => {
                        assert!(v.get("error").is_none(), "server_info error: {}", line);
                        let text = v["result"]["content"][0]["text"].as_str().unwrap_or("");
                        assert!(
                            text.contains("\"server\""),
                            "unexpected server_info content"
                        );
                        ok_info = true;
                    }
                    Some(id) if *id == serde_json::json!(3) => {
                        assert!(v.get("error").is_none(), "list dirs error: {}", line);
                        let text = v["result"]["content"][0]["text"].as_str().unwrap_or("");
                        // Robust on Windows where long/short user dir may differ; match leaf temp dir name
                        let leaf = std::path::Path::new(&root)
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("");
                        assert!(
                            text.contains(leaf),
                            "dirs output missing leaf '{}'; got: {}",
                            leaf,
                            text
                        );
                        ok_dirs = true;
                    }
                    Some(id) if *id == serde_json::json!(4) => {
                        assert!(v.get("error").is_none(), "resources/list error: {}", line);
                        let resources = v["result"]["resources"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default();
                        let has_catalog = resources
                            .iter()
                            .any(|r| r["uri"] == "mdmcp://commands/catalog");
                        assert!(has_catalog, "resources/list missing catalog: {}", line);
                        ok_res_list = true;
                    }
                    Some(id) if *id == serde_json::json!(5) => {
                        assert!(v.get("error").is_none(), "resources/read error: {}", line);
                        let text = v["result"]["content"][0]["text"].as_str().unwrap_or("[]");
                        let parsed: serde_json::Value =
                            serde_json::from_str(text).unwrap_or(serde_json::json!([]));
                        assert!(parsed.is_array(), "catalog not array json");
                        ok_res_read = true;
                    }
                    _ => {}
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }

    assert!(
        ok_info && ok_dirs && ok_res_list && ok_res_read,
        "not all resource/info checks passed"
    );
    assert!(
        std::fs::metadata(&log_path).is_ok(),
        "audit log not created at {}",
        log_path.display()
    );

    let _ = child.kill();
    let _ = child.wait();
    if std::env::var("MDMCP_E2E_KEEP_TMP").is_ok() {
        let kept = temp.keep();
        println!("E2E temp dir kept: {}", kept.display());
    }
}
