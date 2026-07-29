mod app;
mod cli;
mod domain;
mod error;
mod infra;
mod mcp;

use clap::Parser;
use cli::{
    ActionCommands, ApiCommands, AuthCommands, Cli, Commands, McpCommands, OpenapiCommands,
    ProviderCommands,
};
use infra::config;
use infra::crypto::VaultCrypto;
use infra::db::{MetadataDb, VaultDb};
use rusqlite::Connection;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli_args = Cli::parse();

    // ログレベル設定
    let log_level = if cli_args.verbose { "debug" } else { "info" };

    // ログ出力を常に stderr に向けることで、stdoutのJSON-RPCの混入を防ぐ
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(log_level))
        .with_writer(std::io::stderr)
        .init();

    match &cli_args.command {
        Commands::Action {
            cmd: ActionCommands::Validate { file },
        } => {
            let action = app::action::ActionRegistry::validate_file(file)?;
            println!("Valid ActionDefinition: {}", action.metadata.name);
            return Ok(());
        }
        Commands::Openapi {
            cmd: OpenapiCommands::Validate { file },
        } => {
            let operations = app::openapi::validate_document(file)?;
            println!("Valid OpenAPI 3 document: {operations} importable operations");
            return Ok(());
        }
        Commands::Openapi {
            cmd:
                OpenapiCommands::Import {
                    file,
                    provider,
                    output_dir,
                },
        } => {
            let output_dir = match output_dir {
                Some(path) => path.clone(),
                None => config::get_actions_dir()?,
            };
            let outputs = app::openapi::import_document(file, provider, &output_dir)?;
            for path in outputs {
                println!("{}", path.display());
            }
            return Ok(());
        }
        _ => {}
    }

    // DB関連 初期化
    let meta_conn = Connection::open(config::get_metadata_db_path()?)?;
    let metadata_db = MetadataDb::new(meta_conn)?;

    let vault_conn = Connection::open(config::get_vault_db_path()?)?;
    let vault_db = VaultDb::new(vault_conn)?;

    let vault_crypto = VaultCrypto::load_or_create(&config::get_vault_key_path()?)?;

    // アプリケーション層 初期化
    let provider_app = app::provider::ProviderApp::new(&metadata_db, &vault_db);
    let auth_app = app::auth::AuthApp::try_new(&metadata_db, &vault_db, &vault_crypto)?;
    let api_app = app::api::ApiApp::try_new(&metadata_db, &vault_db, &vault_crypto, &auth_app)?;
    let load_action_app = || -> crate::error::Result<app::action::ActionApp> {
        let registry = app::action::ActionRegistry::load(&config::get_actions_dir()?)?;
        Ok(app::action::ActionApp::new(
            registry,
            &api_app,
            &metadata_db,
        ))
    };

    // ルーティング
    match cli_args.command {
        Commands::Provider { cmd } => {
            match cmd {
                ProviderCommands::Add {
                    id,
                    base_url,
                    auth_type,
                    scopes,
                    client_id,
                    auth_url,
                    token_url,
                    api_key_header,
                    oauth_redirect_port,
                    allow_private_network,
                } => {
                    let auth_t = match auth_type.as_str() {
                        "api-key" => domain::provider::AuthType::ApiKey,
                        "oauth-pkce" => domain::provider::AuthType::OauthPkce,
                        other => {
                            return Err(crate::error::CliError::Internal(format!(
                                "unsupported auth type {other}; use api-key or oauth-pkce"
                            ))
                            .into());
                        }
                    };
                    let config = domain::provider::ProviderConfig {
                        id: id.clone(),
                        base_url,
                        auth_type: auth_t,
                        scopes: scopes
                            .map(|s| s.split(',').map(str::trim).map(str::to_string).collect())
                            .unwrap_or_default(),
                        client_id,
                        auth_url,
                        token_url,
                        credential_placement: api_key_header
                            .map(|name| domain::provider::CredentialPlacement::Header { name })
                            .unwrap_or_default(),
                        oauth_redirect_port,
                        allow_private_network,
                    };
                    provider_app.add_provider(config)?;
                    println!("Provider '{}' added successfully.", id);
                }
                ProviderCommands::List => {
                    let list = provider_app.list_providers()?;
                    if cli_args.json {
                        let json = if cli_args.pretty {
                            serde_json::to_string_pretty(&list)?
                        } else {
                            serde_json::to_string(&list)?
                        };
                        println!("{}", json);
                    } else {
                        // 人間向け簡易表示
                        for p in list {
                            println!("{:<15} [{:?}] {}", p.id, p.auth_type, p.base_url);
                        }
                    }
                }
                ProviderCommands::Remove { id } => {
                    provider_app.remove_provider(&id)?;
                    println!("Provider '{}' removed.", id);
                }
            }
        }
        Commands::Auth { cmd } => match cmd {
            AuthCommands::Login {
                provider_id,
                api_key,
            } => {
                let provider = metadata_db
                    .get_provider(&provider_id)?
                    .ok_or_else(|| crate::error::CliError::ProviderNotFound(provider_id.clone()))?;

                if provider.auth_type == domain::provider::AuthType::ApiKey {
                    auth_app.login_api_key(&provider_id, api_key.as_deref())?;
                    println!("Logged in to '{}' via API Key.", provider_id);
                } else {
                    auth_app.login_oauth_pkce(&provider_id).await?;
                    println!("Logged in to '{}' via OAuth PKCE.", provider_id);
                }
            }
            AuthCommands::Status { provider_id } => {
                if let Some(session) = metadata_db.get_latest_session(&provider_id)? {
                    println!(
                        "Logged in: Session Active (expires: {:?})",
                        session.expires_at
                    );
                } else {
                    println!("Not logged in.");
                }
            }
        },
        Commands::Api { cmd } => {
            match cmd {
                ApiCommands::Call {
                    provider_id,
                    method,
                    path,
                    body,
                } => {
                    let json_body = if let Some(b) = body {
                        Some(serde_json::from_str(&b).map_err(|e| {
                            crate::error::CliError::Internal(format!("Invalid JSON body: {}", e))
                        })?)
                    } else {
                        None
                    };
                    match api_app.call(&provider_id, &method, &path, json_body).await {
                        Ok(res) => {
                            if cli_args.json {
                                let json = if cli_args.pretty {
                                    serde_json::to_string_pretty(&res)?
                                } else {
                                    serde_json::to_string(&res)?
                                };
                                println!("{}", json);
                            } else {
                                // Default to pretty JSON for human view until we have more refined human-friendly output
                                println!("{}", serde_json::to_string_pretty(&res)?);
                            }
                        }
                        Err(e) => {
                            if cli_args.json {
                                let err_json = serde_json::json!({
                                    "ok": false,
                                    "error": e.to_string()
                                });
                                eprintln!("{}", serde_json::to_string(&err_json)?);
                            } else {
                                eprintln!("API execution error: {}", e);
                            }
                            return Err(e.into());
                        }
                    }
                }
            }
        }
        Commands::Mcp { cmd } => {
            let action_app = load_action_app()?;
            match cmd {
                McpCommands::Serve => {
                    let mcp_server = mcp::McpServer::new(&action_app);
                    mcp_server.run().await?;
                }
                McpCommands::ServeHttp(args) => {
                    let client_secret = std::env::var(&args.client_secret_env).map_err(|_| {
                        crate::error::CliError::Internal(format!(
                            "required secret environment variable {} is not set",
                            args.client_secret_env
                        ))
                    })?;
                    mcp::remote::run(
                        &action_app,
                        mcp::remote::RemoteMcpConfig {
                            listen: args.listen,
                            introspection_url: args.introspection_url,
                            audience: args.audience,
                            client_id: args.client_id,
                            client_secret,
                            allowed_hosts: args.allowed_host,
                            allowed_origins: args.allowed_origin,
                            max_concurrency: args.max_concurrency,
                            max_sessions: args.max_sessions,
                            max_request_bytes: args.max_request_bytes,
                            allow_insecure_http: args.allow_insecure_http,
                        },
                    )
                    .await?;
                }
            }
        }
        Commands::Action { cmd } => {
            let action_app = load_action_app()?;
            match cmd {
                ActionCommands::Validate { file } => {
                    unreachable!(
                        "validate handled before registry loading: {}",
                        file.display()
                    );
                }
                ActionCommands::List => {
                    let actions = action_app.registry().list();
                    if cli_args.json {
                        println!(
                            "{}",
                            if cli_args.pretty {
                                serde_json::to_string_pretty(&actions)?
                            } else {
                                serde_json::to_string(&actions)?
                            }
                        );
                    } else {
                        for action in actions {
                            println!(
                                "{:<32} [{:?}] {}",
                                action.metadata.name, action.spec.risk, action.metadata.description
                            );
                        }
                    }
                }
                ActionCommands::Describe { name } => {
                    let action = action_app
                        .registry()
                        .get(&name)
                        .ok_or_else(|| crate::error::CliError::ActionNotFound(name.clone()))?;
                    println!(
                        "{}",
                        if cli_args.json && !cli_args.pretty {
                            serde_json::to_string(action)?
                        } else {
                            serde_json::to_string_pretty(action)?
                        }
                    );
                }
                ActionCommands::Run {
                    name,
                    input,
                    approval_ticket,
                } => {
                    let input = serde_json::from_str(&input).map_err(|error| {
                        crate::error::CliError::SchemaValidation {
                            target: "input".into(),
                            message: error.to_string(),
                        }
                    })?;
                    let output = action_app
                        .run_for(
                            &app::action::ExecutionIdentity::local(),
                            &name,
                            input,
                            approval_ticket.as_deref(),
                        )
                        .await?;
                    println!(
                        "{}",
                        if cli_args.json && !cli_args.pretty {
                            serde_json::to_string(&output)?
                        } else {
                            serde_json::to_string_pretty(&output)?
                        }
                    );
                }
                ActionCommands::Prepare { name, input } => {
                    let input = serde_json::from_str(&input).map_err(|error| {
                        crate::error::CliError::SchemaValidation {
                            target: "input".into(),
                            message: error.to_string(),
                        }
                    })?;
                    let ticket = action_app.prepare(
                        &app::action::ExecutionIdentity::local(),
                        &name,
                        &input,
                    )?;
                    println!("{ticket}");
                }
                ActionCommands::Approve { ticket } => {
                    action_app.approve(&app::action::ExecutionIdentity::local(), &ticket)?;
                    println!("Approved ticket {ticket}");
                }
            }
        }
        Commands::Openapi { .. } => unreachable!("OpenAPI commands are handled before DB setup"),
    }

    Ok(())
}
