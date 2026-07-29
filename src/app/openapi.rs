use crate::app::action::ActionRegistry;
use crate::domain::action::{
    ActionConstraints, ActionDefinition, ActionMetadata, ActionSpec, ApprovalMode,
    HttpExecutorDefinition, ParameterLocation, RiskLevel,
};
use crate::error::{CliError, Result};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const METHODS: [&str; 5] = ["get", "post", "put", "patch", "delete"];

pub fn validate_document(path: &Path) -> Result<usize> {
    let operations = parse_operations(path)?;
    let mut names = std::collections::BTreeSet::new();
    for operation in &operations {
        ActionRegistry::validate_definition(operation)?;
        if !names.insert(&operation.metadata.name) {
            return Err(CliError::InvalidAction(format!(
                "duplicate normalized operationId: {}",
                operation.metadata.name
            )));
        }
    }
    Ok(operations.len())
}

pub fn import_document(path: &Path, provider: &str, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut operations = parse_operations(path)?;
    fs::create_dir_all(output_dir)?;
    let output_metadata = fs::symlink_metadata(output_dir)?;
    if !output_metadata.file_type().is_dir() || output_metadata.file_type().is_symlink() {
        return Err(CliError::InvalidAction(format!(
            "{} must be a regular output directory, not a symlink",
            output_dir.display()
        )));
    }
    let mut targets = std::collections::BTreeSet::new();
    for action in &mut operations {
        action.spec.executor.provider = provider.into();
        ActionRegistry::validate_definition(action)?;
        let safe_name = action.metadata.name.replace('.', "_");
        let target = output_dir.join(format!("{safe_name}.yaml"));
        if !targets.insert(target.clone()) {
            return Err(CliError::InvalidAction(format!(
                "multiple operations map to {}",
                target.display()
            )));
        }
        if target.exists() {
            return Err(CliError::InvalidAction(format!(
                "refusing to overwrite {}",
                target.display()
            )));
        }
    }
    let mut serialized = Vec::new();
    for action in operations {
        let safe_name = action.metadata.name.replace('.', "_");
        let target = output_dir.join(format!("{safe_name}.yaml"));
        let bytes = serde_yaml::to_string(&action)
            .map_err(|error| CliError::InvalidAction(error.to_string()))?;
        serialized.push((target, bytes));
    }
    let mut output = Vec::new();
    for (target, bytes) in serialized {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        file.write_all(bytes.as_bytes())?;
        file.sync_all()?;
        output.push(target);
    }
    if output.is_empty() {
        return Err(CliError::InvalidAction(
            "OpenAPI document contains no operations with operationId".into(),
        ));
    }

    Ok(output)
}

fn parse_operations(path: &Path) -> Result<Vec<ActionDefinition>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(CliError::InvalidAction(format!(
            "{} must be a regular OpenAPI file",
            path.display()
        )));
    }
    if metadata.len() > 10 * 1024 * 1024 {
        return Err(CliError::InvalidAction(format!(
            "{} exceeds the 10 MiB OpenAPI limit",
            path.display()
        )));
    }
    let bytes = fs::read(path)?;
    let document: Value = if matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("json")
    ) {
        serde_json::from_slice(&bytes)
            .map_err(|error| CliError::InvalidAction(format!("OpenAPI: {error}")))?
    } else {
        serde_yaml::from_slice(&bytes)
            .map_err(|error| CliError::InvalidAction(format!("OpenAPI: {error}")))?
    };
    let version = document
        .get("openapi")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::InvalidAction("OpenAPI version is missing".into()))?;
    if !version.starts_with("3.") {
        return Err(CliError::InvalidAction(format!(
            "only OpenAPI 3.x is supported, found {version}"
        )));
    }
    if document
        .get("webhooks")
        .and_then(Value::as_object)
        .is_some_and(|webhooks| !webhooks.is_empty())
    {
        return Err(CliError::InvalidAction(
            "OpenAPI webhooks are not supported".into(),
        ));
    }
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::InvalidAction("OpenAPI paths object is missing".into()))?;
    let mut actions = Vec::new();
    for (path_name, path_item) in paths {
        let path_item = resolve_ref(path_item, &document)?;
        let Some(path_object) = path_item.as_object() else {
            return Err(CliError::InvalidAction(format!(
                "OpenAPI path item {path_name} must be an object"
            )));
        };
        for method in METHODS {
            let Some(operation) = path_object.get(method).and_then(Value::as_object) else {
                continue;
            };
            let Some(operation_id) = operation.get("operationId").and_then(Value::as_str) else {
                tracing::warn!(
                    method,
                    path = path_name,
                    "Skipping operation without operationId"
                );
                continue;
            };
            if operation
                .get("callbacks")
                .and_then(Value::as_object)
                .is_some_and(|callbacks| !callbacks.is_empty())
            {
                return Err(CliError::InvalidAction(format!(
                    "{operation_id}: OpenAPI callbacks are not supported"
                )));
            }
            let name = normalize_action_name(operation_id);
            let description = operation
                .get("description")
                .or_else(|| operation.get("summary"))
                .and_then(Value::as_str)
                .unwrap_or(operation_id)
                .to_string();
            let (input_schema, parameters) = build_input_schema(path_object, operation, &document)?;
            let output_schema = build_output_schema(operation, &document)?;
            let risk = if method == "get" {
                RiskLevel::Read
            } else if method == "delete" {
                RiskLevel::Destructive
            } else {
                RiskLevel::ReversibleWrite
            };
            actions.push(ActionDefinition {
                api_version: "apicli.dev/v1alpha1".into(),
                kind: "Action".into(),
                metadata: ActionMetadata {
                    name,
                    version: 1,
                    description,
                    // Imports are drafts: an operator must review and enable them.
                    enabled: false,
                },
                spec: ActionSpec {
                    input_schema,
                    output_schema,
                    executor: HttpExecutorDefinition {
                        kind: "openapi".into(),
                        provider: "__REVIEW_REQUIRED__".into(),
                        operation_id: operation_id.into(),
                        method: method.to_ascii_uppercase(),
                        path: path_name.clone(),
                        parameters,
                    },
                    risk,
                    approval: if risk == RiskLevel::Read {
                        ApprovalMode::Never
                    } else {
                        ApprovalMode::Always
                    },
                    broker_scopes: vec![],
                    upstream_scopes: collect_security_scopes(operation, &document),
                    constraints: ActionConstraints::default(),
                },
            });
        }
    }
    Ok(actions)
}

fn build_input_schema(
    path_item: &Map<String, Value>,
    operation: &Map<String, Value>,
    document: &Value,
) -> Result<(Value, BTreeMap<String, ParameterLocation>)> {
    let mut properties = Map::new();
    let mut required = Vec::new();
    let mut locations = BTreeMap::new();
    let parameters = path_item
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            operation
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        );
    for parameter in parameters {
        let parameter = resolve_ref(parameter, document)?;
        let Some(object) = parameter.as_object() else {
            continue;
        };
        let Some(name) = object.get("name").and_then(Value::as_str) else {
            continue;
        };
        let location = match object.get("in").and_then(Value::as_str) {
            Some("path") => ParameterLocation::Path,
            Some("query") => ParameterLocation::Query,
            Some(other) => {
                return Err(CliError::InvalidAction(format!(
                    "unsupported OpenAPI parameter location {other} for {name}"
                )));
            }
            None => {
                return Err(CliError::InvalidAction(format!(
                    "OpenAPI parameter {name} is missing 'in'"
                )));
            }
        };
        let schema = object.get("schema").cloned().unwrap_or_else(|| json!({}));
        if properties.contains_key(name) {
            return Err(CliError::InvalidAction(format!(
                "duplicate or ambiguous OpenAPI parameter name {name}"
            )));
        }
        locations.insert(name.into(), location);
        properties.insert(name.into(), dereference_schema(&schema, document)?);
        if object
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || object.get("in").and_then(Value::as_str) == Some("path")
        {
            required.push(Value::String(name.into()));
        }
    }

    if let Some(body) = operation.get("requestBody") {
        let body = resolve_ref(body, document)?;
        let object = body.as_object().ok_or_else(|| {
            CliError::InvalidAction("requestBody must resolve to an object".into())
        })?;
        let Some(schema) = media_schema(object) else {
            return Err(CliError::InvalidAction(
                "OpenAPI requestBody requires a JSON media type with a schema".into(),
            ));
        };
        let mut schema = dereference_schema(schema, document)?;
        close_imported_input_objects(&mut schema)?;
        if properties.contains_key("body") {
            return Err(CliError::InvalidAction(
                "request body conflicts with an OpenAPI parameter named body".into(),
            ));
        }
        properties.insert("body".into(), schema);
        locations.insert("body".into(), ParameterLocation::Body);
        if object
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            required.push(Value::String("body".into()));
        }
    }
    required.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    required.dedup();
    Ok((
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": properties,
            "required": required,
        }),
        locations,
    ))
}

fn collect_security_scopes(operation: &Map<String, Value>, document: &Value) -> Vec<String> {
    let security = operation
        .get("security")
        .or_else(|| document.get("security"));
    let mut scopes = security
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .flat_map(|requirement| requirement.values())
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    scopes.sort();
    scopes.dedup();
    scopes
}

fn build_output_schema(operation: &Map<String, Value>, document: &Value) -> Result<Option<Value>> {
    let Some(responses) = operation.get("responses").and_then(Value::as_object) else {
        return Ok(None);
    };
    let response = ["200", "201", "202", "default"]
        .iter()
        .find_map(|status| responses.get(*status));
    let Some(response) = response else {
        return Ok(None);
    };
    let response = resolve_ref(response, document)?;
    response
        .as_object()
        .and_then(media_schema)
        .map(|schema| dereference_schema(schema, document))
        .transpose()
}

fn media_schema(object: &Map<String, Value>) -> Option<&Value> {
    let content = object.get("content")?.as_object()?;
    content
        .get("application/json")
        .or_else(|| {
            content
                .iter()
                .find(|(media_type, _)| media_type.ends_with("+json"))
                .map(|(_, value)| value)
        })?
        .get("schema")
}

fn resolve_ref<'a>(value: &'a Value, document: &'a Value) -> Result<&'a Value> {
    let mut current = value;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let Some(reference) = current.get("$ref").and_then(Value::as_str) else {
            return Ok(current);
        };
        if !reference.starts_with("#/") {
            return Err(CliError::InvalidAction(format!(
                "external OpenAPI reference is not supported: {reference}"
            )));
        }
        if !seen.insert(reference) {
            return Err(CliError::InvalidAction(format!(
                "recursive OpenAPI reference is not supported: {reference}"
            )));
        }
        current = document.pointer(&reference[1..]).ok_or_else(|| {
            CliError::InvalidAction(format!("unresolved OpenAPI reference: {reference}"))
        })?;
    }
}

fn dereference_schema(schema: &Value, document: &Value) -> Result<Value> {
    let mut cloned = schema.clone();
    inline_refs(
        &mut cloned,
        document,
        0,
        &mut std::collections::BTreeSet::new(),
    )?;
    Ok(cloned)
}

fn inline_refs(
    value: &mut Value,
    document: &Value,
    depth: usize,
    stack: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    if depth > 64 {
        return Err(CliError::InvalidAction(
            "OpenAPI schema reference nesting exceeds 64 levels".into(),
        ));
    }
    if let Some(reference) = value
        .get("$ref")
        .and_then(Value::as_str)
        .map(str::to_string)
    {
        if !reference.starts_with("#/") {
            return Err(CliError::InvalidAction(format!(
                "external OpenAPI reference is not supported: {reference}"
            )));
        }
        if !stack.insert(reference.clone()) {
            return Err(CliError::InvalidAction(format!(
                "recursive OpenAPI schema reference is not supported: {reference}"
            )));
        }
        let resolved = document.pointer(&reference[1..]).ok_or_else(|| {
            CliError::InvalidAction(format!("unresolved OpenAPI reference: {reference}"))
        })?;
        let siblings = value
            .as_object()
            .into_iter()
            .flat_map(|object| object.iter())
            .filter(|(key, _)| key.as_str() != "$ref")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Map<_, _>>();
        *value = if siblings.is_empty() {
            resolved.clone()
        } else {
            json!({
                "allOf": [
                    resolved.clone(),
                    Value::Object(siblings),
                ]
            })
        };
        inline_refs(value, document, depth + 1, stack)?;
        stack.remove(&reference);
        return Ok(());
    }
    match value {
        Value::Object(object) => {
            for child in object.values_mut() {
                inline_refs(child, document, depth + 1, stack)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                inline_refs(child, document, depth + 1, stack)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn normalize_action_name(operation_id: &str) -> String {
    let mut output = String::new();
    for character in operation_id.chars() {
        if character.is_ascii_alphanumeric() || "._-".contains(character) {
            output.push(character.to_ascii_lowercase());
        } else {
            output.push('_');
        }
    }
    output
}

fn close_imported_input_objects(schema: &mut Value) -> Result<()> {
    let Some(object) = schema.as_object_mut() else {
        return Ok(());
    };
    let is_object_schema = object.get("type").and_then(Value::as_str) == Some("object")
        || object.contains_key("properties");
    if is_object_schema {
        match object.get("additionalProperties") {
            Some(Value::Bool(false)) | None => {
                object
                    .entry("additionalProperties")
                    .or_insert(Value::Bool(false));
            }
            Some(_) => {
                return Err(CliError::InvalidAction(
                    "OpenAPI request body maps with dynamic property names are not supported"
                        .into(),
                ));
            }
        }
        if object
            .get("patternProperties")
            .and_then(Value::as_object)
            .is_some_and(|patterns| !patterns.is_empty())
        {
            return Err(CliError::InvalidAction(
                "OpenAPI request body patternProperties are not supported".into(),
            ));
        }
    }
    if let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) {
        for property in properties.values_mut() {
            close_imported_input_objects(property)?;
        }
    }
    for keyword in ["items", "not", "if", "then", "else", "contains"] {
        if let Some(child) = object.get_mut(keyword) {
            close_imported_input_objects(child)?;
        }
    }
    for keyword in ["prefixItems", "allOf", "anyOf", "oneOf"] {
        if let Some(children) = object.get_mut(keyword).and_then(Value::as_array_mut) {
            for child in children {
                close_imported_input_objects(child)?;
            }
        }
    }
    for keyword in ["$defs", "definitions", "dependentSchemas"] {
        if let Some(children) = object.get_mut(keyword).and_then(Value::as_object_mut) {
            for child in children.values_mut() {
                close_imported_input_objects(child)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn imports_disabled_operation_drafts() {
        let directory = tempdir().expect("tempdir");
        let input = directory.path().join("openapi.yaml");
        fs::write(
            &input,
            r##"
openapi: 3.1.0
info: {title: CRM, version: "1"}
security:
  - oauth: [customer:read]
paths:
  /customers/{customer_id}:
    get:
      operationId: getCustomer
      summary: Get a customer
      parameters:
        - in: path
          name: customer_id
          required: true
          schema: {type: string}
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  customer:
                    $ref: "#/components/schemas/Customer"
                    required: [customer_id]
components:
  schemas:
    Customer:
      type: object
      properties:
        customer_id: {type: string}
"##,
        )
        .expect("write fixture");
        let output_dir = directory.path().join("actions");
        let outputs = import_document(&input, "crm", &output_dir).expect("import");
        assert_eq!(outputs.len(), 1);
        let action = ActionRegistry::read_definition(&outputs[0]).expect("read action");
        assert!(!action.metadata.enabled);
        assert_eq!(action.spec.executor.provider, "crm");
        assert_eq!(action.spec.executor.path, "/customers/{customer_id}");
        assert_eq!(action.spec.upstream_scopes, vec!["customer:read"]);
        assert!(action
            .spec
            .output_schema
            .as_ref()
            .and_then(|schema| {
                schema.pointer("/properties/customer/allOf/0/properties/customer_id/type")
            })
            .is_some_and(|value| value == "string"));
        assert_eq!(
            action
                .spec
                .output_schema
                .as_ref()
                .and_then(|schema| schema.pointer("/properties/customer/allOf/1/required/0")),
            Some(&Value::String("customer_id".into()))
        );
        assert!(!serde_json::to_string(&action.spec.output_schema)
            .expect("serialize")
            .contains("$ref"));
    }

    #[test]
    fn preserves_request_body_as_a_distinct_schema() {
        let directory = tempdir().expect("tempdir");
        let input = directory.path().join("openapi.yaml");
        fs::write(
            &input,
            r#"
openapi: 3.1.0
info: {title: CRM, version: "1"}
paths:
  /customers:
    post:
      operationId: updateCustomer
      parameters:
        - in: query
          name: status
          schema: {type: string}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                status: {type: string}
      responses:
        "200": {description: ok}
"#,
        )
        .expect("OpenAPI fixture");

        let output = directory.path().join("actions");
        let files = import_document(&input, "crm", &output).expect("import");
        let action = ActionRegistry::read_definition(&files[0]).expect("action");
        assert_eq!(
            action.spec.input_schema.pointer("/properties/status/type"),
            Some(&Value::String("string".into()))
        );
        assert_eq!(
            action
                .spec
                .input_schema
                .pointer("/properties/body/properties/status/type"),
            Some(&Value::String("string".into()))
        );
        assert_eq!(
            action
                .spec
                .input_schema
                .pointer("/properties/body/additionalProperties"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            action.spec.executor.parameters.get("status"),
            Some(&ParameterLocation::Query)
        );
        assert_eq!(
            action.spec.executor.parameters.get("body"),
            Some(&ParameterLocation::Body)
        );
    }
}
