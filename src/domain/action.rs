use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

fn default_api_version() -> String {
    "apicli.dev/v1alpha1".into()
}

fn default_kind() -> String {
    "Action".into()
}

fn default_version() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_timeout_ms() -> u64 {
    10_000
}

fn default_max_response_bytes() -> usize {
    1024 * 1024
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActionDefinition {
    #[serde(default = "default_api_version")]
    pub api_version: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    pub metadata: ActionMetadata,
    pub spec: ActionSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActionMetadata {
    pub name: String,
    #[serde(default = "default_version")]
    pub version: u32,
    pub description: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    pub input_schema: Value,
    #[serde(default)]
    pub output_schema: Option<Value>,
    pub executor: HttpExecutorDefinition,
    pub risk: RiskLevel,
    pub approval: ApprovalMode,
    #[serde(default)]
    pub broker_scopes: Vec<String>,
    #[serde(default)]
    pub upstream_scopes: Vec<String>,
    #[serde(default)]
    pub constraints: ActionConstraints,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpExecutorDefinition {
    #[serde(default = "default_executor_kind")]
    pub kind: String,
    pub provider: String,
    pub operation_id: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub parameters: BTreeMap<String, ParameterLocation>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ParameterLocation {
    Path,
    Query,
    Body,
}

fn default_executor_kind() -> String {
    "openapi".into()
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RiskLevel {
    Read,
    ReversibleWrite,
    Destructive,
    Privileged,
}

impl RiskLevel {
    pub fn is_read_only(self) -> bool {
        self == Self::Read
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalMode {
    Never,
    Always,
    Policy,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActionConstraints {
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default)]
    pub response_mask: Vec<String>,
    #[serde(default)]
    pub idempotency_header: Option<String>,
    /// Input field copied into If-Match and removed from the upstream body.
    #[serde(default)]
    pub if_match_argument: Option<String>,
    /// Explicit policy opt-in required for privileged Actions.
    #[serde(default)]
    pub allow_privileged: bool,
}

impl Default for ActionConstraints {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout_ms(),
            max_response_bytes: default_max_response_bytes(),
            response_mask: Vec::new(),
            idempotency_header: None,
            if_match_argument: None,
            allow_privileged: false,
        }
    }
}
