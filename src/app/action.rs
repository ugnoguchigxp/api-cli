use crate::app::api::{ApiApp, ApiRequestOptions};
use crate::app::approval::{ApprovalApp, ApprovalSubject};
use crate::domain::action::{ActionDefinition, ApprovalMode, ParameterLocation};
use crate::error::{CliError, Result};
use crate::infra::db::MetadataDb;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const MAX_ACTION_DEFINITIONS: usize = 512;
const MAX_TOTAL_DEFINITION_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Default)]
pub struct ActionRegistry {
    actions: Arc<BTreeMap<String, ActionDefinition>>,
}

impl ActionRegistry {
    pub fn load(directory: &Path) -> Result<Self> {
        if !directory.exists() {
            fs::create_dir_all(directory)?;
        }
        let directory_metadata = fs::symlink_metadata(directory)?;
        if !directory_metadata.file_type().is_dir() || directory_metadata.file_type().is_symlink() {
            return Err(CliError::InvalidAction(format!(
                "{} must be a regular directory, not a symlink",
                directory.display()
            )));
        }
        let mut paths = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            if !matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("yaml" | "yml" | "json")
            ) {
                continue;
            }
            let file_type = entry.file_type()?;
            if !file_type.is_file() || file_type.is_symlink() {
                return Err(CliError::InvalidAction(format!(
                    "{} must be a regular ActionDefinition file",
                    path.display()
                )));
            }
            paths.push(path);
        }
        paths.sort();
        if paths.len() > MAX_ACTION_DEFINITIONS {
            return Err(CliError::InvalidAction(format!(
                "Action Registry exceeds the {MAX_ACTION_DEFINITIONS} definition limit"
            )));
        }

        let mut actions = BTreeMap::new();
        let mut total_bytes = 0_u64;
        for path in paths {
            total_bytes = total_bytes.saturating_add(fs::metadata(&path)?.len());
            if total_bytes > MAX_TOTAL_DEFINITION_BYTES {
                return Err(CliError::InvalidAction(
                    "Action Registry exceeds the 16 MiB total definition limit".into(),
                ));
            }
            let action = Self::read_definition(&path)?;
            Self::validate_definition(&action)?;
            if actions
                .insert(action.metadata.name.clone(), action)
                .is_some()
            {
                return Err(CliError::InvalidAction(format!(
                    "duplicate action name in {}",
                    path.display()
                )));
            }
        }
        Ok(Self {
            actions: Arc::new(actions),
        })
    }

    #[cfg(test)]
    pub fn from_actions(actions: Vec<ActionDefinition>) -> Result<Self> {
        let mut map = BTreeMap::new();
        for action in actions {
            Self::validate_definition(&action)?;
            if map.insert(action.metadata.name.clone(), action).is_some() {
                return Err(CliError::InvalidAction("duplicate action name".into()));
            }
        }
        Ok(Self {
            actions: Arc::new(map),
        })
    }

    pub fn read_definition(path: &Path) -> Result<ActionDefinition> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(CliError::InvalidAction(format!(
                "{} must be a regular ActionDefinition file",
                path.display()
            )));
        }
        if metadata.len() > 1024 * 1024 {
            return Err(CliError::InvalidAction(format!(
                "{} exceeds the 1 MiB definition limit",
                path.display()
            )));
        }
        let bytes = fs::read(path)?;
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("json") => serde_json::from_slice(&bytes)
                .map_err(|error| CliError::InvalidAction(format!("{}: {error}", path.display()))),
            _ => serde_yaml::from_slice(&bytes)
                .map_err(|error| CliError::InvalidAction(format!("{}: {error}", path.display()))),
        }
    }

    pub fn validate_file(path: &Path) -> Result<ActionDefinition> {
        let action = Self::read_definition(path)?;
        Self::validate_definition(&action)?;
        Ok(action)
    }

    pub fn validate_definition(action: &ActionDefinition) -> Result<()> {
        if action.api_version != "apicli.dev/v1alpha1" || action.kind != "Action" {
            return Err(CliError::InvalidAction(
                "api_version must be apicli.dev/v1alpha1 and kind must be Action".into(),
            ));
        }
        let name = &action.metadata.name;
        if name.is_empty()
            || name.len() > 128
            || !name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        {
            return Err(CliError::InvalidAction(format!(
                "invalid action name: {name}"
            )));
        }
        if action.metadata.version == 0 {
            return Err(CliError::InvalidAction(format!(
                "{name}: metadata.version must be greater than zero"
            )));
        }
        if action.metadata.description.trim().is_empty()
            || action.metadata.description.len() > 4096
            || action
                .metadata
                .description
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        {
            return Err(CliError::InvalidAction(format!(
                "{name}: description is empty, too long, or contains unsafe control characters"
            )));
        }
        if action.spec.executor.provider.trim().is_empty()
            || action.spec.executor.operation_id.trim().is_empty()
            || !action.spec.executor.path.starts_with('/')
        {
            return Err(CliError::InvalidAction(format!(
                "{name}: executor provider, operation_id, method, and absolute path are required"
            )));
        }
        if action.spec.executor.provider.len() > 128
            || !action
                .spec
                .executor
                .provider
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        {
            return Err(CliError::InvalidAction(format!(
                "{name}: executor provider must be a valid provider ID"
            )));
        }
        if action.spec.executor.operation_id.len() > 256
            || action
                .spec
                .executor
                .operation_id
                .chars()
                .any(char::is_control)
        {
            return Err(CliError::InvalidAction(format!(
                "{name}: executor operation_id is too long or contains control characters"
            )));
        }
        if action.spec.executor.kind != "openapi" {
            return Err(CliError::InvalidAction(format!(
                "{name}: unsupported executor kind {}",
                action.spec.executor.kind
            )));
        }
        if action.spec.executor.path.len() > 8 * 1024
            || action.spec.executor.path.contains(['?', '#'])
            || action.spec.executor.path.contains('\\')
            || action
                .spec
                .executor
                .path
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
            || action.spec.executor.path.chars().any(char::is_control)
        {
            return Err(CliError::InvalidAction(format!(
                "{name}: executor path cannot contain traversal, a query, fragment, or control character"
            )));
        }
        validate_executor_path_segments(&action.spec.executor.path, name)?;
        let method = action.spec.executor.method.to_ascii_uppercase();
        if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
            return Err(CliError::InvalidAction(format!(
                "{name}: unsupported HTTP method {method}"
            )));
        }
        if action.spec.risk.is_read_only() != matches!(method.as_str(), "GET") {
            return Err(CliError::InvalidAction(format!(
                "{name}: read risk must use GET and write risks must not use GET"
            )));
        }
        if !action.spec.risk.is_read_only() && action.spec.approval == ApprovalMode::Never {
            return Err(CliError::InvalidAction(format!(
                "{name}: write action cannot disable approval"
            )));
        }
        if action.spec.risk.is_read_only() && action.spec.approval != ApprovalMode::Never {
            return Err(CliError::InvalidAction(format!(
                "{name}: read-only Action must use approval: never"
            )));
        }
        if action.spec.approval == ApprovalMode::Policy {
            return Err(CliError::InvalidAction(format!(
                "{name}: approval: policy is reserved until a policy engine is configured; use always"
            )));
        }
        if action.spec.risk == crate::domain::action::RiskLevel::Privileged
            && !action.spec.constraints.allow_privileged
        {
            return Err(CliError::InvalidAction(format!(
                "{name}: privileged Action requires constraints.allow_privileged: true"
            )));
        }
        jsonschema::validator_for(&action.spec.input_schema).map_err(|error| {
            CliError::InvalidAction(format!("{name}: invalid input schema: {error}"))
        })?;
        let input_object = action.spec.input_schema.as_object().ok_or_else(|| {
            CliError::InvalidAction(format!("{name}: input schema must be an object"))
        })?;
        if input_object.get("type").and_then(Value::as_str) != Some("object") {
            return Err(CliError::InvalidAction(format!(
                "{name}: input schema root type must be object"
            )));
        }
        if input_object
            .get("additionalProperties")
            .and_then(Value::as_bool)
            != Some(false)
        {
            return Err(CliError::InvalidAction(format!(
                "{name}: input schema must set additionalProperties: false"
            )));
        }
        let input_properties = input_object
            .get("properties")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                CliError::InvalidAction(format!("{name}: input schema properties are required"))
            })?;
        validate_closed_input_objects(&action.spec.input_schema, name)?;
        let required_properties = input_object
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        let path_parameters = extract_path_parameters(&action.spec.executor.path, name)?;
        for parameter in &path_parameters {
            if action.spec.executor.parameters.get(parameter.as_str())
                != Some(&ParameterLocation::Path)
            {
                return Err(CliError::InvalidAction(format!(
                    "{name}: path placeholder {parameter} must be mapped to parameters.{parameter}: path"
                )));
            }
            if !required_properties.contains(parameter.as_str()) {
                return Err(CliError::InvalidAction(format!(
                    "{name}: path parameter {parameter} must be required by the input schema"
                )));
            }
        }
        for (parameter, location) in &action.spec.executor.parameters {
            let Some(parameter_schema) = input_properties.get(parameter) else {
                return Err(CliError::InvalidAction(format!(
                    "{name}: executor parameter {parameter} is absent from input schema"
                )));
            };
            if *location == ParameterLocation::Path && !path_parameters.contains(parameter) {
                return Err(CliError::InvalidAction(format!(
                    "{name}: path parameter {parameter} has no path placeholder"
                )));
            }
            if matches!(location, ParameterLocation::Path | ParameterLocation::Query)
                && !schema_is_scalar(parameter_schema, &action.spec.input_schema, 0)
            {
                return Err(CliError::InvalidAction(format!(
                    "{name}: {location:?} parameter {parameter} must have an explicit scalar schema type"
                )));
            }
            if method == "GET" && *location == ParameterLocation::Body {
                return Err(CliError::InvalidAction(format!(
                    "{name}: GET parameter {parameter} cannot be mapped to the request body"
                )));
            }
        }
        if method == "GET" {
            for (parameter, schema) in input_properties {
                if !action.spec.executor.parameters.contains_key(parameter)
                    && !schema_is_scalar(schema, &action.spec.input_schema, 0)
                {
                    return Err(CliError::InvalidAction(format!(
                        "{name}: implicit query parameter {parameter} must have an explicit scalar schema type"
                    )));
                }
            }
        }
        validate_schema_references(
            &action.spec.input_schema,
            &action.spec.input_schema,
            0,
            name,
        )?;
        if let Some(schema) = &action.spec.output_schema {
            jsonschema::validator_for(schema).map_err(|error| {
                CliError::InvalidAction(format!("{name}: invalid output schema: {error}"))
            })?;
            validate_schema_references(schema, schema, 0, name)?;
        }
        let mut response_masks = BTreeSet::new();
        if action.spec.constraints.response_mask.len() > 256 {
            return Err(CliError::InvalidAction(format!(
                "{name}: response_mask cannot contain more than 256 pointers"
            )));
        }
        for pointer in &action.spec.constraints.response_mask {
            if pointer.len() > 2048
                || !is_valid_json_pointer(pointer)
                || !response_masks.insert(pointer)
            {
                return Err(CliError::InvalidAction(format!(
                    "{name}: response mask must be a unique JSON Pointer no longer than 2048 bytes: {pointer}"
                )));
            }
        }
        if let Some(header) = &action.spec.constraints.idempotency_header {
            if action.spec.risk.is_read_only() {
                return Err(CliError::InvalidAction(format!(
                    "{name}: read-only Action cannot configure an idempotency header"
                )));
            }
            validate_executor_header(header, name)?;
            if header.eq_ignore_ascii_case("if-match") {
                return Err(CliError::InvalidAction(format!(
                    "{name}: idempotency header cannot override If-Match"
                )));
            }
        }
        if let Some(argument) = &action.spec.constraints.if_match_argument {
            if action.spec.risk.is_read_only() {
                return Err(CliError::InvalidAction(format!(
                    "{name}: read-only Action cannot configure If-Match"
                )));
            }
            if action
                .spec
                .input_schema
                .pointer(&format!(
                    "/properties/{}",
                    argument.replace('~', "~0").replace('/', "~1")
                ))
                .is_none()
            {
                return Err(CliError::InvalidAction(format!(
                    "{name}: if_match_argument {argument} is not present in input_schema.properties"
                )));
            }
            if !required_properties.contains(argument.as_str()) {
                return Err(CliError::InvalidAction(format!(
                    "{name}: if_match_argument {argument} must be required by the input schema"
                )));
            }
            if !input_properties
                .get(argument)
                .is_some_and(|schema| schema_is_scalar(schema, &action.spec.input_schema, 0))
            {
                return Err(CliError::InvalidAction(format!(
                    "{name}: if_match_argument {argument} must have an explicit scalar schema type"
                )));
            }
        }
        if action.spec.constraints.timeout_ms == 0 || action.spec.constraints.timeout_ms > 300_000 {
            return Err(CliError::InvalidAction(format!(
                "{name}: timeout_ms must be between 1 and 300000"
            )));
        }
        if action.spec.constraints.max_response_bytes == 0
            || action.spec.constraints.max_response_bytes > 16 * 1024 * 1024
        {
            return Err(CliError::InvalidAction(format!(
                "{name}: max_response_bytes must be between 1 and 16777216"
            )));
        }
        validate_scopes(&action.spec.broker_scopes, name, "broker_scopes")?;
        validate_scopes(&action.spec.upstream_scopes, name, "upstream_scopes")?;
        Ok(())
    }

    pub fn list(&self) -> Vec<&ActionDefinition> {
        self.actions
            .values()
            .filter(|action| action.metadata.enabled)
            .collect()
    }

    pub fn get(&self, name: &str) -> Option<&ActionDefinition> {
        self.actions
            .get(name)
            .filter(|action| action.metadata.enabled)
    }
}

fn validate_executor_header(header: &str, action_name: &str) -> Result<()> {
    let parsed = reqwest::header::HeaderName::from_bytes(header.as_bytes()).map_err(|error| {
        CliError::InvalidAction(format!("{action_name}: invalid executor header: {error}"))
    })?;
    if is_forbidden_request_header(&parsed) {
        return Err(CliError::InvalidAction(format!(
            "{action_name}: sensitive executor header is forbidden: {header}"
        )));
    }
    Ok(())
}

pub(crate) fn is_forbidden_request_header(header: &reqwest::header::HeaderName) -> bool {
    matches!(
        header.as_str(),
        "authorization"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "proxy-connection"
            | "host"
            | "cookie"
            | "connection"
            | "content-length"
            | "expect"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn validate_executor_path_segments(path: &str, action_name: &str) -> Result<()> {
    for segment in path.split('/') {
        let bytes = segment.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != b'%' {
                decoded.push(bytes[index]);
                index += 1;
                continue;
            }
            if index + 2 >= bytes.len() {
                return Err(CliError::InvalidAction(format!(
                    "{action_name}: executor path contains invalid percent encoding"
                )));
            }
            let Some(high) = (bytes[index + 1] as char).to_digit(16) else {
                return Err(CliError::InvalidAction(format!(
                    "{action_name}: executor path contains invalid percent encoding"
                )));
            };
            let Some(low) = (bytes[index + 2] as char).to_digit(16) else {
                return Err(CliError::InvalidAction(format!(
                    "{action_name}: executor path contains invalid percent encoding"
                )));
            };
            decoded.push(((high << 4) | low) as u8);
            index += 3;
        }
        if decoded == b"."
            || decoded == b".."
            || decoded.contains(&b'/')
            || decoded.contains(&b'\\')
            || decoded.iter().any(|byte| byte.is_ascii_control())
        {
            return Err(CliError::InvalidAction(format!(
                "{action_name}: executor path contains an encoded traversal or control character"
            )));
        }
    }
    Ok(())
}

fn extract_path_parameters(path: &str, action_name: &str) -> Result<BTreeSet<String>> {
    let mut parameters = BTreeSet::new();
    let mut remaining = path;
    while let Some(open) = remaining.find('{') {
        if remaining[..open].contains('}') {
            return Err(CliError::InvalidAction(format!(
                "{action_name}: unmatched path placeholder closing brace"
            )));
        }
        let after_open = &remaining[open + 1..];
        let close = after_open.find('}').ok_or_else(|| {
            CliError::InvalidAction(format!("{action_name}: unclosed path placeholder"))
        })?;
        let parameter = &after_open[..close];
        if parameter.is_empty() || parameter.contains(['{', '}']) {
            return Err(CliError::InvalidAction(format!(
                "{action_name}: invalid path placeholder"
            )));
        }
        parameters.insert(parameter.to_string());
        remaining = &after_open[close + 1..];
    }
    if remaining.contains('}') {
        return Err(CliError::InvalidAction(format!(
            "{action_name}: unmatched path placeholder closing brace"
        )));
    }
    Ok(parameters)
}

fn is_valid_json_pointer(pointer: &str) -> bool {
    pointer.starts_with('/')
        && pointer.as_bytes().iter().enumerate().all(|(index, byte)| {
            *byte != b'~' || matches!(pointer.as_bytes().get(index + 1), Some(b'0' | b'1'))
        })
}

fn validate_scopes(scopes: &[String], action_name: &str, field: &str) -> Result<()> {
    if scopes.len() > 256 {
        return Err(CliError::InvalidAction(format!(
            "{action_name}: {field} cannot contain more than 256 scopes"
        )));
    }
    let mut unique = BTreeSet::new();
    for scope in scopes {
        if scope.is_empty()
            || scope.trim() != scope
            || scope.len() > 256
            || scope.chars().any(char::is_whitespace)
            || !unique.insert(scope)
        {
            return Err(CliError::InvalidAction(format!(
                "{action_name}: {field} contains an empty, overlong, malformed, or duplicate scope"
            )));
        }
    }
    Ok(())
}

fn schema_is_scalar(schema: &Value, root: &Value, depth: usize) -> bool {
    if depth > 64 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| root.pointer(pointer))
            .is_some_and(|resolved| schema_is_scalar(resolved, root, depth + 1));
    }
    matches!(
        schema.get("type").and_then(Value::as_str),
        Some("string" | "number" | "integer" | "boolean")
    )
}

fn validate_closed_input_objects(schema: &Value, action_name: &str) -> Result<()> {
    let Some(object) = schema.as_object() else {
        return Ok(());
    };
    let is_object_schema = object.get("type").and_then(Value::as_str) == Some("object")
        || object.contains_key("properties");
    if is_object_schema
        && object.get("additionalProperties").and_then(Value::as_bool) != Some(false)
    {
        return Err(CliError::InvalidAction(format!(
            "{action_name}: every input object schema must set additionalProperties: false"
        )));
    }
    if object
        .get("patternProperties")
        .and_then(Value::as_object)
        .is_some_and(|patterns| !patterns.is_empty())
        || object
            .get("unevaluatedProperties")
            .is_some_and(|value| value.as_bool() != Some(false))
    {
        return Err(CliError::InvalidAction(format!(
            "{action_name}: input object schemas cannot allow dynamic property names"
        )));
    }
    if let Some(properties) = object.get("properties").and_then(Value::as_object) {
        for property in properties.values() {
            validate_closed_input_objects(property, action_name)?;
        }
    }
    for keyword in ["items", "not", "if", "then", "else", "contains"] {
        if let Some(child) = object.get(keyword) {
            validate_closed_input_objects(child, action_name)?;
        }
    }
    for keyword in ["prefixItems", "allOf", "anyOf", "oneOf"] {
        if let Some(children) = object.get(keyword).and_then(Value::as_array) {
            for child in children {
                validate_closed_input_objects(child, action_name)?;
            }
        }
    }
    for keyword in ["$defs", "definitions", "dependentSchemas"] {
        if let Some(children) = object.get(keyword).and_then(Value::as_object) {
            for child in children.values() {
                validate_closed_input_objects(child, action_name)?;
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct ActionApp {
    registry: ActionRegistry,
    api_app: ApiApp,
    approvals: ApprovalApp,
}

struct TicketExecutionGuard {
    approvals: ApprovalApp,
    ticket_id: String,
    principal_id: String,
    tenant_id: String,
    client_id: String,
    armed: bool,
}

impl TicketExecutionGuard {
    fn new(approvals: &ApprovalApp, ticket_id: &str, identity: &ExecutionIdentity) -> Self {
        Self {
            approvals: approvals.clone(),
            ticket_id: ticket_id.into(),
            principal_id: identity.principal_id.clone(),
            tenant_id: identity.tenant_id.clone(),
            client_id: identity.client_id.clone(),
            armed: true,
        }
    }

    fn finish(mut self, outcome: &str) -> Result<()> {
        self.approvals.finish(
            &self.ticket_id,
            &self.principal_id,
            &self.tenant_id,
            &self.client_id,
            outcome,
        )?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for TicketExecutionGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.approvals.finish(
                &self.ticket_id,
                &self.principal_id,
                &self.tenant_id,
                &self.client_id,
                "unknown",
            );
        }
    }
}

impl ActionApp {
    pub fn new(registry: ActionRegistry, api_app: &ApiApp, metadata_db: &MetadataDb) -> Self {
        Self {
            registry,
            api_app: api_app.clone(),
            approvals: ApprovalApp::new(metadata_db),
        }
    }

    pub fn registry(&self) -> &ActionRegistry {
        &self.registry
    }

    pub fn is_available(
        &self,
        identity: &ExecutionIdentity,
        action: &ActionDefinition,
    ) -> Result<bool> {
        Ok(authorize(identity, action).is_ok()
            && self.api_app.provider_is_authenticated_for(
                &action.spec.executor.provider,
                &identity.principal_id,
                &identity.tenant_id,
                &action.spec.upstream_scopes,
            )?)
    }

    pub fn prepare(
        &self,
        identity: &ExecutionIdentity,
        name: &str,
        input: &Value,
    ) -> Result<String> {
        let action = self
            .registry
            .get(name)
            .ok_or_else(|| CliError::ActionNotFound(name.into()))?;
        validate_instance(&action.spec.input_schema, input, "input")?;
        authorize(identity, action)?;
        if !self.is_available(identity, action)? {
            return Err(CliError::AuthorizationDenied(format!(
                "no upstream credential with the required scopes for {}",
                action.metadata.name
            )));
        }
        if action.spec.risk.is_read_only() {
            return Err(CliError::InvalidAction(format!(
                "{name} is read-only and does not require an approval ticket"
            )));
        }
        self.approvals.prepare(
            &identity.principal_id,
            &identity.tenant_id,
            &identity.client_id,
            action,
            input,
        )
    }

    pub fn approve(&self, identity: &ExecutionIdentity, ticket: &str) -> Result<()> {
        self.approvals.approve(
            ticket,
            &identity.principal_id,
            &identity.tenant_id,
            &identity.client_id,
        )
    }

    pub fn deny(&self, identity: &ExecutionIdentity, ticket: &str) -> Result<()> {
        self.approvals.deny(
            ticket,
            &identity.principal_id,
            &identity.tenant_id,
            &identity.client_id,
        )
    }

    pub async fn run_for(
        &self,
        identity: &ExecutionIdentity,
        name: &str,
        input: Value,
        approval_ticket: Option<&str>,
    ) -> Result<Value> {
        let action = self
            .registry
            .get(name)
            .ok_or_else(|| CliError::ActionNotFound(name.into()))?;
        if action.spec.risk.is_read_only() && approval_ticket.is_some() {
            return Err(CliError::InvalidApproval);
        }
        validate_instance(&action.spec.input_schema, &input, "input")?;
        authorize(identity, action)?;
        if !self.is_available(identity, action)? {
            return Err(CliError::AuthorizationDenied(format!(
                "no upstream credential with the required scopes for {}",
                action.metadata.name
            )));
        }
        let claimed_ticket = if !action.spec.risk.is_read_only() {
            let ticket = match approval_ticket {
                Some(ticket) => ticket,
                None => {
                    let ticket = self.approvals.prepare(
                        &identity.principal_id,
                        &identity.tenant_id,
                        &identity.client_id,
                        action,
                        &input,
                    )?;
                    return Err(CliError::ApprovalRequired {
                        action: name.into(),
                        ticket,
                    });
                }
            };
            self.approvals.consume(
                ticket,
                &identity.principal_id,
                &identity.tenant_id,
                &identity.client_id,
                action,
                &input,
            )?;
            Some(ticket.to_string())
        } else {
            None
        };
        let mut execution_guard = claimed_ticket
            .as_deref()
            .map(|ticket| TicketExecutionGuard::new(&self.approvals, ticket, identity));
        if let Err(error) = self.approvals.audit(
            approval_subject(identity),
            action,
            &input,
            claimed_ticket.as_deref(),
            "started",
            None,
        ) {
            if let Some(guard) = execution_guard.take() {
                guard.finish("failed")?;
            }
            return Err(error);
        }
        let BuiltRequest {
            path,
            body,
            mut headers,
        } = match build_request(action, &input) {
            Ok(request) => request,
            Err(error) => {
                if let Some(guard) = execution_guard.take() {
                    guard.finish("failed")?;
                }
                self.approvals.audit(
                    approval_subject(identity),
                    action,
                    &input,
                    claimed_ticket.as_deref(),
                    "failed",
                    Some(error_code(&error)),
                )?;
                return Err(error);
            }
        };
        if let (Some(header), Some(ticket)) =
            (&action.spec.constraints.idempotency_header, approval_ticket)
        {
            headers.push((header.clone(), ticket.into()));
        }
        let result = self
            .api_app
            .call_with_options(
                &action.spec.executor.provider,
                &action.spec.executor.method,
                &path,
                body,
                ApiRequestOptions {
                    timeout: Duration::from_millis(action.spec.constraints.timeout_ms),
                    max_response_bytes: action.spec.constraints.max_response_bytes,
                    headers,
                    principal_id: identity.principal_id.clone(),
                    tenant_id: identity.tenant_id.clone(),
                },
            )
            .await;
        let mut output = match result {
            Ok(output) => output,
            Err(error) => {
                let outcome = if !action.spec.risk.is_read_only()
                    && matches!(
                        &error,
                        CliError::RequestTimeout { .. }
                            | CliError::ResponseTooLarge { .. }
                            | CliError::UpstreamResultUnknown
                    ) {
                    "unknown"
                } else {
                    "failed"
                };
                if let Some(guard) = execution_guard.take() {
                    guard.finish(outcome)?;
                }
                self.approvals.audit(
                    approval_subject(identity),
                    action,
                    &input,
                    claimed_ticket.as_deref(),
                    outcome,
                    Some(error_code(&error)),
                )?;
                return Err(error);
            }
        };
        apply_response_masks(&mut output, &action.spec.constraints.response_mask);
        if let Some(schema) = &action.spec.output_schema {
            if let Err(error) = validate_instance(schema, &output, "output") {
                let outcome = if action.spec.risk.is_read_only() {
                    "failed"
                } else {
                    "unknown"
                };
                if let Some(guard) = execution_guard.take() {
                    guard.finish(outcome)?;
                }
                self.approvals.audit(
                    approval_subject(identity),
                    action,
                    &input,
                    claimed_ticket.as_deref(),
                    outcome,
                    Some("output_schema"),
                )?;
                return Err(error);
            }
        }
        if let Some(guard) = execution_guard.take() {
            guard.finish("succeeded")?;
        }
        self.approvals.audit(
            approval_subject(identity),
            action,
            &input,
            claimed_ticket.as_deref(),
            "succeeded",
            None,
        )?;
        Ok(output)
    }
}

fn approval_subject(identity: &ExecutionIdentity) -> ApprovalSubject<'_> {
    ApprovalSubject {
        principal_id: &identity.principal_id,
        tenant_id: &identity.tenant_id,
        client_id: &identity.client_id,
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionIdentity {
    pub principal_id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub scopes: BTreeSet<String>,
}

impl ExecutionIdentity {
    pub fn local() -> Self {
        Self::local_with_client("local-cli")
    }

    pub fn local_mcp() -> Self {
        Self::local_with_client("local-mcp")
    }

    fn local_with_client(client_id: &str) -> Self {
        Self {
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
            client_id: client_id.into(),
            scopes: BTreeSet::from(["*".into()]),
        }
    }
}

fn authorize(identity: &ExecutionIdentity, action: &ActionDefinition) -> Result<()> {
    if identity.scopes.contains("*")
        || action
            .spec
            .broker_scopes
            .iter()
            .all(|scope| identity.scopes.contains(scope))
    {
        Ok(())
    } else {
        Err(CliError::AuthorizationDenied(format!(
            "missing scopes for {}",
            action.metadata.name
        )))
    }
}

fn error_code(error: &CliError) -> &'static str {
    match error {
        CliError::RequestTimeout { .. } => "timeout",
        CliError::ResponseTooLarge { .. } => "response_too_large",
        CliError::RequestTooLarge { .. } => "request_too_large",
        CliError::UpstreamError { .. } => "upstream",
        CliError::UpstreamResultUnknown => "upstream_unknown",
        CliError::BlockedUrl(_) => "blocked_url",
        CliError::SchemaValidation { .. } => "schema_validation",
        CliError::AuthRequired | CliError::AuthExpired => "authentication",
        _ => "execution",
    }
}

fn validate_schema_references(
    value: &Value,
    root: &Value,
    depth: usize,
    action_name: &str,
) -> Result<()> {
    if depth > 64 {
        return Err(CliError::InvalidAction(format!(
            "{action_name}: schema nesting exceeds 64 levels"
        )));
    }
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                if !reference.starts_with("#/") {
                    return Err(CliError::InvalidAction(format!(
                        "{action_name}: external schema reference is forbidden: {reference}"
                    )));
                }
                if root.pointer(&reference[1..]).is_none() {
                    return Err(CliError::InvalidAction(format!(
                        "{action_name}: unresolved schema reference: {reference}"
                    )));
                }
            }
            for child in object.values() {
                validate_schema_references(child, root, depth + 1, action_name)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                validate_schema_references(child, root, depth + 1, action_name)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_instance(schema: &Value, instance: &Value, label: &str) -> Result<()> {
    let validator = jsonschema::validator_for(schema)
        .map_err(|error| CliError::InvalidAction(format!("invalid {label} schema: {error}")))?;
    if let Err(error) = validator.validate(instance) {
        return Err(CliError::SchemaValidation {
            target: label.into(),
            message: if label == "output" {
                "upstream response did not match the declared output schema".into()
            } else {
                error.to_string()
            },
        });
    }
    Ok(())
}

struct BuiltRequest {
    path: String,
    body: Option<Value>,
    headers: Vec<(String, String)>,
}

fn build_request(action: &ActionDefinition, input: &Value) -> Result<BuiltRequest> {
    let object = input
        .as_object()
        .ok_or_else(|| CliError::SchemaValidation {
            target: "input".into(),
            message: "top-level input must be an object".into(),
        })?;
    let mut consumed = BTreeSet::new();
    let mut path = action.spec.executor.path.clone();
    for (key, value) in object {
        let placeholder = format!("{{{key}}}");
        if path.contains(&placeholder) {
            let text = scalar_to_string(value).ok_or_else(|| CliError::SchemaValidation {
                target: "input".into(),
                message: format!("path parameter {key} must be a scalar"),
            })?;
            path = path.replace(&placeholder, &url_encode_component(&text));
            consumed.insert(key.clone());
        }
    }
    if path.contains('{') {
        return Err(CliError::SchemaValidation {
            target: "input".into(),
            message: format!("not all path parameters were supplied for {path}"),
        });
    }
    let mut headers = Vec::new();
    if let Some(argument) = &action.spec.constraints.if_match_argument {
        let value = object
            .get(argument)
            .and_then(scalar_to_string)
            .ok_or_else(|| CliError::SchemaValidation {
                target: "input".into(),
                message: format!("If-Match argument {argument} must be a scalar"),
            })?;
        headers.push(("if-match".into(), value));
        consumed.insert(argument.clone());
    }

    let mut query = Map::new();
    let mut body_values = Map::new();
    for (key, value) in object.iter().filter(|(key, _)| !consumed.contains(*key)) {
        let location = action.spec.executor.parameters.get(key).copied().unwrap_or(
            if action.spec.executor.method.eq_ignore_ascii_case("GET") {
                ParameterLocation::Query
            } else {
                ParameterLocation::Body
            },
        );
        match location {
            ParameterLocation::Path => {}
            ParameterLocation::Query => {
                query.insert(key.clone(), value.clone());
            }
            ParameterLocation::Body => {
                body_values.insert(key.clone(), value.clone());
            }
        }
    }
    let mut request_target = path;
    if !query.is_empty() {
        let mut url = url::Url::parse(&format!("https://action.invalid{request_target}"))
            .map_err(|error| CliError::InvalidAction(error.to_string()))?;
        for (key, value) in query {
            let text = scalar_to_string(&value).ok_or_else(|| CliError::SchemaValidation {
                target: "input".into(),
                message: format!("query parameter {key} must be a scalar"),
            })?;
            url.query_pairs_mut().append_pair(&key, &text);
        }
        request_target = url.path().to_string();
        if let Some(query) = url.query() {
            request_target.push('?');
            request_target.push_str(query);
        }
    }
    if body_values.is_empty() {
        Ok(BuiltRequest {
            path: request_target,
            body: None,
            headers,
        })
    } else {
        let body = if body_values.len() == 1 && body_values.contains_key("body") {
            body_values.get("body").cloned()
        } else {
            Some(Value::Object(body_values))
        };
        Ok(BuiltRequest {
            path: request_target,
            body,
            headers,
        })
    }
}

fn scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn url_encode_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn remove_json_pointer(value: &mut Value, pointer: &str) {
    let mut tokens = pointer_tokens(pointer);
    let Some(last) = tokens.pop() else {
        return;
    };
    let mut current = value;
    for token in tokens {
        match current {
            Value::Object(object) => {
                let Some(next) = object.get_mut(&token) else {
                    return;
                };
                current = next;
            }
            Value::Array(array) => {
                let Ok(index) = token.parse::<usize>() else {
                    return;
                };
                let Some(next) = array.get_mut(index) else {
                    return;
                };
                current = next;
            }
            _ => return,
        }
    }
    match current {
        Value::Object(object) => {
            object.remove(&last);
        }
        Value::Array(array) => {
            if let Ok(index) = last.parse::<usize>() {
                if index < array.len() {
                    array.remove(index);
                }
            }
        }
        _ => {}
    }
}

fn apply_response_masks(value: &mut Value, pointers: &[String]) {
    let mut ordered = pointers.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        let left_tokens = pointer_tokens(left);
        let right_tokens = pointer_tokens(right);
        right_tokens.len().cmp(&left_tokens.len()).then_with(|| {
            if left_tokens[..left_tokens.len().saturating_sub(1)]
                == right_tokens[..right_tokens.len().saturating_sub(1)]
            {
                match (
                    left_tokens
                        .last()
                        .and_then(|token| token.parse::<usize>().ok()),
                    right_tokens
                        .last()
                        .and_then(|token| token.parse::<usize>().ok()),
                ) {
                    (Some(left_index), Some(right_index)) => right_index.cmp(&left_index),
                    _ => right.cmp(left),
                }
            } else {
                right.cmp(left)
            }
        })
    });
    for pointer in ordered {
        remove_json_pointer(value, pointer);
    }
}

fn pointer_tokens(pointer: &str) -> Vec<String> {
    pointer
        .split('/')
        .skip(1)
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::auth::AuthApp;
    use crate::domain::action::{
        ActionConstraints, ActionMetadata, ActionSpec, HttpExecutorDefinition, RiskLevel,
    };
    use crate::domain::provider::{AuthType, CredentialPlacement, ProviderConfig};
    use crate::infra::crypto::VaultCrypto;
    use crate::infra::db::{MetadataDb, VaultDb};
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn action(method: &str, risk: RiskLevel, approval: ApprovalMode) -> ActionDefinition {
        ActionDefinition {
            api_version: "apicli.dev/v1alpha1".into(),
            kind: "Action".into(),
            metadata: ActionMetadata {
                name: "customer.get".into(),
                version: 1,
                description: "Get customer".into(),
                enabled: true,
            },
            spec: ActionSpec {
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"customer_id": {"type": "string"}},
                    "required": ["customer_id"],
                    "additionalProperties": false
                }),
                output_schema: None,
                executor: HttpExecutorDefinition {
                    kind: "openapi".into(),
                    provider: "crm".into(),
                    operation_id: "getCustomer".into(),
                    method: method.into(),
                    path: "/customers/{customer_id}".into(),
                    parameters: BTreeMap::from([("customer_id".into(), ParameterLocation::Path)]),
                },
                risk,
                approval,
                broker_scopes: vec![],
                upstream_scopes: vec![],
                constraints: ActionConstraints::default(),
            },
        }
    }

    #[test]
    fn rejects_write_without_approval() {
        let error = ActionRegistry::from_actions(vec![action(
            "POST",
            RiskLevel::ReversibleWrite,
            ApprovalMode::Never,
        )])
        .expect_err("must reject");
        assert!(matches!(error, CliError::InvalidAction(_)));
    }

    #[test]
    fn rejects_ambiguous_executor_and_path_definitions() {
        let mut unsupported = action("GET", RiskLevel::Read, ApprovalMode::Never);
        unsupported.spec.executor.kind = "shell".into();
        assert!(ActionRegistry::from_actions(vec![unsupported]).is_err());

        let mut unmapped = action("GET", RiskLevel::Read, ApprovalMode::Never);
        unmapped.spec.executor.parameters.clear();
        assert!(ActionRegistry::from_actions(vec![unmapped]).is_err());

        let mut optional = action("GET", RiskLevel::Read, ApprovalMode::Never);
        optional.spec.input_schema["required"] = serde_json::json!([]);
        assert!(ActionRegistry::from_actions(vec![optional]).is_err());

        let mut malformed_mask = action("GET", RiskLevel::Read, ApprovalMode::Never);
        malformed_mask.spec.constraints.response_mask = vec!["/customer/~2secret".into()];
        assert!(ActionRegistry::from_actions(vec![malformed_mask]).is_err());

        let mut duplicate_mask = action("GET", RiskLevel::Read, ApprovalMode::Never);
        duplicate_mask.spec.constraints.response_mask = vec!["/secret".into(), "/secret".into()];
        assert!(ActionRegistry::from_actions(vec![duplicate_mask]).is_err());

        let mut encoded_traversal = action("GET", RiskLevel::Read, ApprovalMode::Never);
        encoded_traversal.spec.executor.path = "/customers/%2e%2e/{customer_id}".into();
        assert!(ActionRegistry::from_actions(vec![encoded_traversal]).is_err());

        let policy = action("PATCH", RiskLevel::ReversibleWrite, ApprovalMode::Policy);
        assert!(ActionRegistry::from_actions(vec![policy]).is_err());

        let mut excessive_scopes = action("GET", RiskLevel::Read, ApprovalMode::Never);
        excessive_scopes.spec.broker_scopes =
            (0..257).map(|index| format!("scope:{index}")).collect();
        assert!(ActionRegistry::from_actions(vec![excessive_scopes]).is_err());

        let mut get_with_body = action("GET", RiskLevel::Read, ApprovalMode::Never);
        get_with_body
            .spec
            .executor
            .parameters
            .insert("customer_id".into(), ParameterLocation::Body);
        get_with_body.spec.executor.path = "/customers".into();
        assert!(ActionRegistry::from_actions(vec![get_with_body]).is_err());

        let mut hop_header = action("PATCH", RiskLevel::ReversibleWrite, ApprovalMode::Always);
        hop_header.spec.constraints.idempotency_header = Some("keep-alive".into());
        assert!(ActionRegistry::from_actions(vec![hop_header]).is_err());
    }

    #[test]
    fn rejects_open_input_objects_and_external_schema_references() {
        let mut open = action("GET", RiskLevel::Read, ApprovalMode::Never);
        open.spec.input_schema = serde_json::json!({"type": "object"});
        assert!(ActionRegistry::from_actions(vec![open]).is_err());

        let mut external = action("GET", RiskLevel::Read, ApprovalMode::Never);
        external.spec.input_schema = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "customer_id": {"$ref": "https://attacker.example/schema.json"}
            }
        });
        assert!(ActionRegistry::from_actions(vec![external]).is_err());
    }

    #[test]
    fn expands_path_and_query_without_allowing_arbitrary_path() {
        let action = action("GET", RiskLevel::Read, ApprovalMode::Never);
        let BuiltRequest {
            path,
            body,
            headers,
        } = build_request(
            &action,
            &serde_json::json!({"customer_id": "a/b", "expand": true}),
        )
        .expect("build request");
        assert_eq!(path, "/customers/a%2Fb?expand=true");
        assert!(body.is_none());
        assert!(headers.is_empty());
    }

    #[test]
    fn response_mask_removes_nested_value() {
        let mut value = serde_json::json!({"customer": {"email": "secret", "name": "A"}});
        remove_json_pointer(&mut value, "/customer/email");
        assert_eq!(value, serde_json::json!({"customer": {"name": "A"}}));
    }

    #[test]
    fn response_masks_remove_array_indexes_without_shift_errors() {
        let mut value = serde_json::json!({"items": ["keep", "secret-1", "secret-2", "keep-2"]});
        apply_response_masks(
            &mut value,
            &["/items/1".to_string(), "/items/2".to_string()],
        );
        assert_eq!(value, serde_json::json!({"items": ["keep", "keep-2"]}));
    }

    #[test]
    fn bundled_action_example_is_valid_but_disabled() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/actions/customer.get.yaml");
        let action = ActionRegistry::validate_file(&path).expect("validate example");
        assert_eq!(action.metadata.name, "customer.get");
        assert!(!action.metadata.enabled);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn approved_write_binds_etag_and_idempotency_and_cannot_replay() {
        use axum::{extract::Request, routing::patch, Json, Router};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let router = Router::new().route(
            "/customers/c1",
            patch(|request: Request| async move {
                let if_match = request
                    .headers()
                    .get("if-match")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let idempotency = request
                    .headers()
                    .get("idempotency-key")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let bytes = axum::body::to_bytes(request.into_body(), 1024)
                    .await
                    .expect("body");
                Json(serde_json::json!({
                    "if_match": if_match,
                    "idempotency": idempotency,
                    "body": serde_json::from_slice::<Value>(&bytes).expect("JSON"),
                    "secret": "masked"
                }))
            }),
        );
        let server_task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let metadata =
            MetadataDb::new(Connection::open_in_memory().expect("metadata")).expect("metadata");
        let vault = VaultDb::new(Connection::open_in_memory().expect("vault")).expect("vault");
        let directory = tempdir().expect("tempdir");
        let crypto = VaultCrypto::load_or_create(&directory.path().join("key")).expect("crypto");
        metadata
            .insert_provider(&ProviderConfig {
                id: "crm".into(),
                base_url: format!("http://{address}"),
                auth_type: AuthType::ApiKey,
                scopes: vec![],
                client_id: None,
                auth_url: None,
                token_url: None,
                credential_placement: CredentialPlacement::Bearer,
                oauth_redirect_port: None,
                allow_private_network: true,
            })
            .expect("provider");
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        auth.login_api_key("crm", Some("secret")).expect("login");
        let api = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let mut write = action("PATCH", RiskLevel::ReversibleWrite, ApprovalMode::Always);
        write.metadata.name = "customer.update".into();
        write.spec.input_schema = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "customer_id": {"type": "string"},
                "status": {"type": "string"},
                "version": {"type": "string"}
            },
            "required": ["customer_id", "status", "version"]
        });
        write.spec.output_schema = Some(serde_json::json!({
            "type": "object",
            "required": ["body"],
            "not": {"required": ["secret"]}
        }));
        write.spec.constraints.idempotency_header = Some("Idempotency-Key".into());
        write.spec.constraints.if_match_argument = Some("version".into());
        write.spec.constraints.response_mask = vec!["/secret".into()];
        let mut uncertain = write.clone();
        uncertain.metadata.name = "customer.update.invalid-output".into();
        uncertain.spec.output_schema = Some(serde_json::json!({
            "type": "object",
            "required": ["receipt"]
        }));
        let app = ActionApp::new(
            ActionRegistry::from_actions(vec![write, uncertain]).expect("registry"),
            &api,
            &metadata,
        );
        let identity = ExecutionIdentity::local();
        let input =
            serde_json::json!({"customer_id": "c1", "status": "suspended", "version": "v7"});
        let ticket = app
            .prepare(&identity, "customer.update", &input)
            .expect("prepare");
        app.approve(&identity, &ticket).expect("approve");
        let output = app
            .run_for(&identity, "customer.update", input.clone(), Some(&ticket))
            .await
            .expect("run");
        assert_eq!(output["if_match"], "v7");
        assert_eq!(output["idempotency"], ticket);
        assert_eq!(output["body"], serde_json::json!({"status": "suspended"}));
        assert!(output.get("secret").is_none());
        assert_eq!(
            metadata.approval_status(&ticket).expect("ticket status"),
            Some("succeeded".into())
        );
        assert_eq!(
            metadata
                .audit_approval_ticket_ids()
                .expect("audit ticket IDs"),
            vec![Some(ticket.clone()), Some(ticket.clone())]
        );
        assert!(app
            .run_for(&identity, "customer.update", input.clone(), Some(&ticket))
            .await
            .is_err());

        let uncertain_ticket = app
            .prepare(&identity, "customer.update.invalid-output", &input)
            .expect("prepare uncertain");
        app.approve(&identity, &uncertain_ticket)
            .expect("approve uncertain");
        assert!(matches!(
            app.run_for(
                &identity,
                "customer.update.invalid-output",
                input,
                Some(&uncertain_ticket)
            )
            .await,
            Err(CliError::SchemaValidation { target, .. }) if target == "output"
        ));
        assert_eq!(
            metadata
                .approval_status(&uncertain_ticket)
                .expect("uncertain ticket status"),
            Some("unknown".into())
        );
        server_task.abort();
    }
}
