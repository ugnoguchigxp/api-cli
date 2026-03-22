use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

fn run_success(config_root: &std::path::Path, args: &[&str]) -> String {
    let assert = Command::cargo_bin("api-cli")
        .expect("binary exists")
        .env("HOME", config_root)
        .env("XDG_CONFIG_HOME", config_root)
        .args(args)
        .assert()
        .success();
    String::from_utf8(assert.get_output().stdout.clone()).expect("stdout must be UTF-8")
}

#[test]
fn provider_lifecycle_and_auth_status_work_through_main() {
    let dir = tempdir().expect("temp dir");
    let config_root = dir.path();

    let out = run_success(
        config_root,
        &[
            "provider",
            "add",
            "--id",
            "p1",
            "--base-url",
            "https://api.example.com",
            "--auth-type",
            "api-key",
        ],
    );
    assert!(out.contains("Provider 'p1' added successfully."));

    let list = run_success(config_root, &["--json", "provider", "list"]);
    let list_json: Value = serde_json::from_str(&list).expect("valid JSON list");
    let items = list_json.as_array().expect("providers should be an array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].get("id").and_then(Value::as_str), Some("p1"));

    let status = run_success(config_root, &["auth", "status", "p1"]);
    assert!(status.contains("Not logged in."));

    let removed = run_success(config_root, &["provider", "remove", "p1"]);
    assert!(removed.contains("Provider 'p1' removed."));

    let after = run_success(config_root, &["--json", "provider", "list"]);
    let after_json: Value = serde_json::from_str(&after).expect("valid JSON list");
    assert_eq!(after_json.as_array().map(|a| a.len()), Some(0));
}

#[test]
fn oauth_provider_add_is_reflected_in_json_list() {
    let dir = tempdir().expect("temp dir");
    let config_root = dir.path();

    let _ = run_success(
        config_root,
        &[
            "provider",
            "add",
            "--id",
            "oauth1",
            "--base-url",
            "https://api.oauth.example.com",
            "--auth-type",
            "oauth-pkce",
            "--scopes",
            "read,write",
            "--client-id",
            "client-1",
            "--auth-url",
            "https://id.example.com/auth",
            "--token-url",
            "https://id.example.com/token",
        ],
    );

    let list = run_success(config_root, &["--json", "--pretty", "provider", "list"]);
    let list_json: Value = serde_json::from_str(&list).expect("valid JSON list");
    let items = list_json.as_array().expect("providers should be an array");
    assert_eq!(items.len(), 1);
    let p = &items[0];
    assert_eq!(p.get("id").and_then(Value::as_str), Some("oauth1"));
    assert_eq!(p.get("auth_type").and_then(Value::as_str), Some("oauth-pkce"));
    assert_eq!(p.get("client_id").and_then(Value::as_str), Some("client-1"));
    assert_eq!(
        p.get("auth_url").and_then(Value::as_str),
        Some("https://id.example.com/auth")
    );
    assert_eq!(
        p.get("token_url").and_then(Value::as_str),
        Some("https://id.example.com/token")
    );
}

#[test]
fn api_call_with_invalid_json_body_returns_error() {
    let dir = tempdir().expect("temp dir");
    let config_root = dir.path();

    let assert = Command::cargo_bin("api-cli")
        .expect("binary exists")
        .env("HOME", config_root)
        .env("XDG_CONFIG_HOME", config_root)
        .args(["api", "call", "p1", "POST", "/v1/x", "--body", "{invalid"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).expect("stderr UTF-8");
    assert!(stderr.contains("Invalid JSON body") || stderr.contains("Internal error"));
}
