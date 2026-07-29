use crate::domain::action::ActionDefinition;
use crate::error::{CliError, Result};
use crate::infra::db::metadata::{ApprovalTicketBinding, ApprovalTicketRecord, AuditEventRecord};
use crate::infra::db::MetadataDb;
use chrono::{Duration, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const POLICY_VERSION: &str = "v1";
const TICKET_TTL_MINUTES: i64 = 5;

#[derive(Clone)]
pub struct ApprovalApp {
    metadata_db: MetadataDb,
}

#[derive(Clone, Copy)]
pub struct ApprovalSubject<'a> {
    pub principal_id: &'a str,
    pub tenant_id: &'a str,
    pub client_id: &'a str,
}

impl ApprovalApp {
    pub fn new(metadata_db: &MetadataDb) -> Self {
        Self {
            metadata_db: metadata_db.clone(),
        }
    }

    pub fn prepare(
        &self,
        principal_id: &str,
        tenant_id: &str,
        client_id: &str,
        action: &ActionDefinition,
        arguments: &Value,
    ) -> Result<String> {
        let ticket_id = Uuid::new_v4().to_string();
        self.metadata_db
            .create_approval_ticket(&ApprovalTicketRecord {
                ticket_id: ticket_id.clone(),
                principal_id: principal_id.into(),
                tenant_id: tenant_id.into(),
                client_id: client_id.into(),
                action_name: action.metadata.name.clone(),
                action_version: action.metadata.version,
                definition_hash: definition_hash(action),
                provider_id: action.spec.executor.provider.clone(),
                arguments_hash: arguments_hash(arguments),
                policy_version: POLICY_VERSION.into(),
                expires_at: (Utc::now() + Duration::minutes(TICKET_TTL_MINUTES)).to_rfc3339(),
            })?;
        Ok(ticket_id)
    }

    pub fn approve(
        &self,
        ticket_id: &str,
        principal_id: &str,
        tenant_id: &str,
        client_id: &str,
    ) -> Result<()> {
        if self
            .metadata_db
            .approve_ticket(ticket_id, principal_id, tenant_id, client_id)?
        {
            Ok(())
        } else {
            Err(CliError::InvalidApproval)
        }
    }

    pub fn consume(
        &self,
        ticket_id: &str,
        principal_id: &str,
        tenant_id: &str,
        client_id: &str,
        action: &ActionDefinition,
        arguments: &Value,
    ) -> Result<()> {
        let arguments_hash = arguments_hash(arguments);
        if self.metadata_db.consume_ticket(&ApprovalTicketBinding {
            ticket_id,
            principal_id,
            tenant_id,
            client_id,
            action_name: &action.metadata.name,
            action_version: action.metadata.version,
            definition_hash: &definition_hash(action),
            provider_id: &action.spec.executor.provider,
            arguments_hash: &arguments_hash,
            policy_version: POLICY_VERSION,
        })? {
            Ok(())
        } else {
            Err(CliError::InvalidApproval)
        }
    }

    pub fn deny(
        &self,
        ticket_id: &str,
        principal_id: &str,
        tenant_id: &str,
        client_id: &str,
    ) -> Result<()> {
        if self
            .metadata_db
            .deny_ticket(ticket_id, principal_id, tenant_id, client_id)?
        {
            Ok(())
        } else {
            Err(CliError::InvalidApproval)
        }
    }

    pub fn finish(
        &self,
        ticket_id: &str,
        principal_id: &str,
        tenant_id: &str,
        client_id: &str,
        outcome: &str,
    ) -> Result<()> {
        if self
            .metadata_db
            .finish_ticket(ticket_id, principal_id, tenant_id, client_id, outcome)?
        {
            Ok(())
        } else {
            Err(CliError::InvalidApproval)
        }
    }

    pub fn audit(
        &self,
        subject: ApprovalSubject<'_>,
        action: &ActionDefinition,
        arguments: &Value,
        approval_ticket_id: Option<&str>,
        outcome: &str,
        error_code: Option<&str>,
    ) -> Result<()> {
        self.metadata_db.insert_audit_event(&AuditEventRecord {
            event_id: Uuid::new_v4().to_string(),
            principal_id: subject.principal_id.into(),
            tenant_id: subject.tenant_id.into(),
            client_id: subject.client_id.into(),
            approval_ticket_id: approval_ticket_id.map(Into::into),
            action_name: action.metadata.name.clone(),
            action_version: action.metadata.version,
            definition_hash: definition_hash(action),
            provider_id: action.spec.executor.provider.clone(),
            arguments_hash: arguments_hash(arguments),
            risk: format!("{:?}", action.spec.risk),
            outcome: outcome.into(),
            error_code: error_code.map(Into::into),
        })
    }
}

pub fn arguments_hash(arguments: &Value) -> String {
    let bytes = serde_jcs::to_vec(arguments).expect("JSON Value is always JCS serializable");
    hex::encode(Sha256::digest(bytes))
}

pub fn definition_hash(action: &ActionDefinition) -> String {
    let value = serde_json::to_value(action).expect("ActionDefinition is always serializable");
    arguments_hash(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::action::{
        ActionConstraints, ActionMetadata, ActionSpec, ApprovalMode, HttpExecutorDefinition,
        RiskLevel,
    };
    use rusqlite::Connection;

    fn action() -> ActionDefinition {
        ActionDefinition {
            api_version: "apicli.dev/v1alpha1".into(),
            kind: "Action".into(),
            metadata: ActionMetadata {
                name: "customer.update".into(),
                version: 1,
                description: "Update customer".into(),
                enabled: true,
            },
            spec: ActionSpec {
                input_schema: serde_json::json!({
                    "type": "object",
                    "additionalProperties": false
                }),
                output_schema: None,
                executor: HttpExecutorDefinition {
                    kind: "openapi".into(),
                    provider: "crm".into(),
                    operation_id: "updateCustomer".into(),
                    method: "PATCH".into(),
                    path: "/customers/{id}".into(),
                    parameters: Default::default(),
                },
                risk: RiskLevel::ReversibleWrite,
                approval: ApprovalMode::Always,
                broker_scopes: vec![],
                upstream_scopes: vec![],
                constraints: ActionConstraints::default(),
            },
        }
    }

    #[test]
    fn canonical_hash_ignores_object_key_order() {
        assert_eq!(
            arguments_hash(&serde_json::json!({"a": 1, "b": 2})),
            arguments_hash(&serde_json::json!({"b": 2, "a": 1}))
        );
        assert_eq!(
            arguments_hash(&serde_json::from_str("1.0").expect("number")),
            arguments_hash(&serde_json::from_str("1").expect("number"))
        );
    }

    #[test]
    fn ticket_is_one_time_and_bound_to_every_argument() {
        let db = MetadataDb::new(Connection::open_in_memory().expect("connection")).expect("db");
        let approvals = ApprovalApp::new(&db);
        let action = action();
        let arguments = serde_json::json!({"id": "c1", "status": "suspended"});
        let ticket = approvals
            .prepare("user-1", "tenant-1", "client-1", &action, &arguments)
            .expect("prepare");
        assert!(approvals
            .approve(&ticket, "user-1", "tenant-1", "other-client")
            .is_err());
        approvals
            .approve(&ticket, "user-1", "tenant-1", "client-1")
            .expect("approve");
        assert!(approvals
            .consume(
                &ticket,
                "user-1",
                "tenant-1",
                "client-1",
                &action,
                &serde_json::json!({"id": "c1", "status": "active"})
            )
            .is_err());
        let mut changed_action = action.clone();
        changed_action.metadata.version = 2;
        assert!(approvals
            .consume(
                &ticket,
                "user-1",
                "tenant-1",
                "client-1",
                &changed_action,
                &arguments,
            )
            .is_err());
        approvals
            .consume(
                &ticket, "user-1", "tenant-1", "client-1", &action, &arguments,
            )
            .expect("consume");
        assert!(approvals
            .consume(&ticket, "user-1", "tenant-1", "client-1", &action, &arguments,)
            .is_err());

        let denied = approvals
            .prepare("user-1", "tenant-1", "client-1", &action, &arguments)
            .expect("prepare denied ticket");
        approvals
            .deny(&denied, "user-1", "tenant-1", "client-1")
            .expect("deny");
        assert!(approvals
            .approve(&denied, "user-1", "tenant-1", "client-1")
            .is_err());
    }
}
