use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

fn run_success(config_root: &std::path::Path, args: &[&str]) -> String {
    let assert = Command::cargo_bin("api-cli")
        .expect("binary exists")
        .env("HOME", config_root)
        .env("XDG_CONFIG_HOME", config_root)
        .env("API_CLI_VAULT_KEY_BACKEND", "file")
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
    assert_eq!(list_json.get("ok").and_then(Value::as_bool), Some(true));
    let items = list_json
        .get("data")
        .and_then(Value::as_array)
        .expect("providers should be an array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].get("id").and_then(Value::as_str), Some("p1"));

    let status = run_success(config_root, &["auth", "status", "p1"]);
    assert!(status.contains("Not logged in."));

    let removed = run_success(config_root, &["provider", "remove", "p1"]);
    assert!(removed.contains("Provider 'p1' removed."));

    let after = run_success(config_root, &["--json", "provider", "list"]);
    let after_json: Value = serde_json::from_str(&after).expect("valid JSON list");
    assert_eq!(
        after_json
            .get("data")
            .and_then(Value::as_array)
            .map(|a| a.len()),
        Some(0)
    );
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
    let items = list_json
        .get("data")
        .and_then(Value::as_array)
        .expect("providers should be an array");
    assert_eq!(items.len(), 1);
    let p = &items[0];
    assert_eq!(p.get("id").and_then(Value::as_str), Some("oauth1"));
    assert_eq!(
        p.get("auth_type").and_then(Value::as_str),
        Some("oauth-pkce")
    );
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
        .env("API_CLI_VAULT_KEY_BACKEND", "file")
        .args(["api", "call", "p1", "POST", "/v1/x", "--body", "{invalid"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).expect("stderr UTF-8");
    assert!(stderr.contains("Invalid JSON body") || stderr.contains("Internal error"));
}

#[test]
fn json_errors_are_a_single_machine_readable_document() {
    let dir = tempdir().expect("temp dir");
    let assert = Command::cargo_bin("api-cli")
        .expect("binary exists")
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("API_CLI_VAULT_KEY_BACKEND", "file")
        .args(["--json", "api", "call", "missing", "GET", "/"])
        .assert()
        .failure();

    assert!(assert.get_output().stdout.is_empty());
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).expect("stderr UTF-8");
    assert_eq!(stderr.lines().count(), 1);
    let error: Value = serde_json::from_str(stderr.trim()).expect("single JSON error");
    assert_eq!(error.get("ok").and_then(Value::as_bool), Some(false));
    assert_eq!(
        error.pointer("/error/code").and_then(Value::as_str),
        Some("provider_not_found")
    );
}

#[test]
fn json_parse_errors_are_also_a_single_machine_readable_document() {
    let assert = Command::cargo_bin("api-cli")
        .expect("binary exists")
        .args(["--json", "unknown-command"])
        .assert()
        .failure();

    assert!(assert.get_output().stdout.is_empty());
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).expect("stderr UTF-8");
    assert_eq!(stderr.lines().count(), 1);
    let error: Value = serde_json::from_str(stderr.trim()).expect("single JSON error");
    assert_eq!(
        error.pointer("/error/code").and_then(Value::as_str),
        Some("cli_parse")
    );
}

#[test]
fn help_keeps_claps_success_exit_code() {
    Command::cargo_bin("api-cli")
        .expect("binary exists")
        .arg("--help")
        .assert()
        .success();
}

#[test]
fn empty_audit_list_uses_the_json_envelope() {
    let directory = tempdir().expect("temp dir");
    let output = run_success(directory.path(), &["--json", "audit", "list"]);
    let document: Value = serde_json::from_str(&output).expect("valid JSON");
    assert_eq!(document.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        document.get("data").and_then(Value::as_array).map(Vec::len),
        Some(0)
    );
}

#[test]
fn remote_api_key_provisioning_is_machine_readable_end_to_end() {
    let directory = tempdir().expect("temp dir");
    let config_root = directory.path();

    let added = run_success(
        config_root,
        &[
            "--json",
            "--pretty",
            "provider",
            "add",
            "--id",
            "remote-api",
            "--base-url",
            "https://api.example.com/v1/",
            "--auth-type",
            "api-key",
            "--api-key-header",
            "X-API-Key",
            "--allow-private-network",
        ],
    );
    let added: Value = serde_json::from_str(&added).expect("valid add response");
    assert_eq!(
        added.pointer("/data/added").and_then(Value::as_bool),
        Some(true)
    );

    let login = Command::cargo_bin("api-cli")
        .expect("binary exists")
        .env("HOME", config_root)
        .env("XDG_CONFIG_HOME", config_root)
        .env("API_CLI_VAULT_KEY_BACKEND", "file")
        .args([
            "--json",
            "auth",
            "login",
            "remote-api",
            "--api-key-stdin",
            "--principal-id",
            "principal-42",
            "--tenant-id",
            "tenant-7",
        ])
        .write_stdin("test-secret\r\n")
        .assert()
        .success();
    let login: Value =
        serde_json::from_slice(&login.get_output().stdout).expect("valid login JSON");
    assert_eq!(
        login.pointer("/data/principal_id").and_then(Value::as_str),
        Some("principal-42")
    );
    assert_eq!(
        login.pointer("/data/tenant_id").and_then(Value::as_str),
        Some("tenant-7")
    );

    let status = run_success(
        config_root,
        &[
            "--json",
            "auth",
            "status",
            "remote-api",
            "--principal-id",
            "principal-42",
            "--tenant-id",
            "tenant-7",
        ],
    );
    let status: Value = serde_json::from_str(&status).expect("valid status response");
    assert_eq!(
        status.pointer("/data/status").and_then(Value::as_str),
        Some("active")
    );

    let removed = run_success(config_root, &["--json", "provider", "remove", "remote-api"]);
    let removed: Value = serde_json::from_str(&removed).expect("valid remove response");
    assert_eq!(
        removed.pointer("/data/removed").and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn guarded_cli_branches_return_stable_json_errors() {
    let directory = tempdir().expect("temp dir");
    let config_root = directory.path();

    for arguments in [
        vec!["--json", "mcp", "serve"],
        vec!["--json", "audit", "show", "missing-event"],
        vec![
            "--json",
            "provider",
            "add",
            "--id",
            "invalid",
            "--base-url",
            "https://api.example.com",
            "--auth-type",
            "not-supported",
        ],
    ] {
        let assert = Command::cargo_bin("api-cli")
            .expect("binary exists")
            .env("HOME", config_root)
            .env("XDG_CONFIG_HOME", config_root)
            .env("API_CLI_VAULT_KEY_BACKEND", "file")
            .args(arguments)
            .assert()
            .failure();
        assert!(assert.get_output().stdout.is_empty());
        let error: Value = serde_json::from_slice(&assert.get_output().stderr)
            .expect("failure must be one JSON document");
        assert_eq!(error.get("ok").and_then(Value::as_bool), Some(false));
        assert!(error
            .pointer("/error/code")
            .and_then(Value::as_str)
            .is_some());
    }
}

#[test]
fn action_validation_and_openapi_import_work_through_main() {
    let dir = tempdir().expect("temp dir");
    let action = dir.path().join("customer.get.yaml");
    fs::write(
        &action,
        r#"
api_version: apicli.dev/v1alpha1
kind: Action
metadata:
  name: customer.get
  description: Get a customer
  enabled: true
spec:
  input_schema:
    type: object
    additionalProperties: false
    properties:
      customer_id: {type: string}
    required: [customer_id]
  executor:
    provider: crm
    operation_id: getCustomer
    method: GET
    path: /customers/{customer_id}
    parameters:
      customer_id: path
  risk: read
  approval: never
"#,
    )
    .expect("write action");
    let validated = run_success(
        dir.path(),
        &["action", "validate", action.to_str().expect("path")],
    );
    assert!(validated.contains("customer.get"));

    let openapi = dir.path().join("openapi.yaml");
    fs::write(
        &openapi,
        r#"
openapi: 3.1.0
info: {title: CRM, version: "1"}
paths:
  /customers/{customer_id}:
    get:
      operationId: getCustomer
      parameters:
        - {in: path, name: customer_id, required: true, schema: {type: string}}
      responses:
        "200": {description: ok}
"#,
    )
    .expect("write OpenAPI");
    let output = dir.path().join("imported");
    let imported = run_success(
        dir.path(),
        &[
            "openapi",
            "import",
            openapi.to_str().expect("path"),
            "--provider",
            "crm",
            "--output-dir",
            output.to_str().expect("path"),
        ],
    );
    assert!(imported.contains("getcustomer.yaml"));
    let draft = fs::read_to_string(output.join("getcustomer.yaml")).expect("read draft");
    assert!(draft.contains("enabled: false"));
    assert!(draft.contains("provider: crm"));
}
