use api_cli::{app, cli, domain, infra, mcp};
use clap::Parser;
use cli::{
    ActionCommands, ApiCommands, AuditCommands, AuthCommands, Cli, Commands, McpCommands,
    OpenapiCommands, ProviderCommands,
};
use infra::config;
use infra::crypto::VaultCrypto;
use infra::db::{MetadataDb, VaultDb};
use std::io::Read;
use std::process::ExitCode;

const MAX_STDIN_SECRET_BYTES: u64 = 64 * 1024;

#[tokio::main]
async fn main() -> ExitCode {
    let json_requested = std::env::args_os().any(|argument| argument == "--json");
    let cli_args = match Cli::try_parse() {
        Ok(arguments) => arguments,
        Err(error) => {
            let exit_code = error.exit_code();
            if exit_code == 0 {
                let _ = error.print();
                return ExitCode::SUCCESS;
            } else if json_requested {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "error": { "code": "cli_parse", "message": error.to_string() }
                    })
                );
            } else {
                let _ = error.print();
            }
            return ExitCode::from(u8::try_from(exit_code).unwrap_or(2));
        }
    };
    let json_output = cli_args.json;

    let log_level = if json_output {
        "off"
    } else if cli_args.verbose {
        "debug"
    } else {
        "info"
    };

    // ログ出力を常に stderr に向けることで、stdoutのJSON-RPCの混入を防ぐ
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(log_level))
        .with_writer(std::io::stderr)
        .init();

    match run(cli_args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if json_output {
                let (code, message) = error
                    .downcast_ref::<api_cli::error::CliError>()
                    .map(|error| (error.code(), error.to_string()))
                    .unwrap_or(("internal", error.to_string()));
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "error": { "code": code, "message": message }
                    })
                );
            } else {
                eprintln!("Error: {error}");
            }
            ExitCode::FAILURE
        }
    }
}

fn print_json_success(data: serde_json::Value, pretty: bool) -> anyhow::Result<()> {
    let envelope = serde_json::json!({ "ok": true, "data": data });
    println!(
        "{}",
        if pretty {
            serde_json::to_string_pretty(&envelope)?
        } else {
            serde_json::to_string(&envelope)?
        }
    );
    Ok(())
}

async fn run(cli_args: Cli) -> anyhow::Result<()> {
    if cli_args.json && matches!(&cli_args.command, Commands::Mcp { .. }) {
        return Err(api_cli::error::CliError::InvalidInput(
            "--json is not supported for long-running MCP server commands".into(),
        )
        .into());
    }

    match &cli_args.command {
        Commands::Action {
            cmd: ActionCommands::Validate { file },
        } => {
            let action = app::action::ActionRegistry::validate_file(file)?;
            if cli_args.json {
                print_json_success(
                    serde_json::json!({ "name": action.metadata.name, "valid": true }),
                    cli_args.pretty,
                )?;
            } else {
                println!("Valid ActionDefinition: {}", action.metadata.name);
            }
            return Ok(());
        }
        Commands::Openapi {
            cmd: OpenapiCommands::Validate { file },
        } => {
            let operations = app::openapi::validate_document(file)?;
            if cli_args.json {
                print_json_success(
                    serde_json::json!({ "valid": true, "importable_operations": operations }),
                    cli_args.pretty,
                )?;
            } else {
                println!("Valid OpenAPI 3 document: {operations} importable operations");
            }
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
            if cli_args.json {
                print_json_success(
                    serde_json::json!({
                        "files": outputs.iter().map(|path| path.display().to_string()).collect::<Vec<_>>()
                    }),
                    cli_args.pretty,
                )?;
            } else {
                for path in outputs {
                    println!("{}", path.display());
                }
            }
            return Ok(());
        }
        _ => {}
    }

    // DB関連 初期化
    let metadata_db = MetadataDb::open(&config::get_metadata_db_path()?)?;
    let vault_db = VaultDb::open(&config::get_vault_db_path()?)?;

    let vault_crypto = VaultCrypto::load_or_create_preferred_for_vault(
        &config::get_vault_key_path()?,
        vault_db.has_secrets()?,
    )?;

    // アプリケーション層 初期化
    let provider_app = app::provider::ProviderApp::new(&metadata_db, &vault_db);
    let auth_app = app::auth::AuthApp::try_new(&metadata_db, &vault_db, &vault_crypto)?;
    let api_app = app::api::ApiApp::try_new(&metadata_db, &vault_db, &vault_crypto, &auth_app)?;
    let load_action_app = || -> api_cli::error::Result<app::action::ActionApp> {
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
                            return Err(api_cli::error::CliError::InvalidInput(format!(
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
                    if cli_args.json {
                        print_json_success(
                            serde_json::json!({ "id": id, "added": true }),
                            cli_args.pretty,
                        )?;
                    } else {
                        println!("Provider '{}' added successfully.", id);
                    }
                }
                ProviderCommands::List => {
                    let list = provider_app.list_providers()?;
                    if cli_args.json {
                        print_json_success(serde_json::to_value(&list)?, cli_args.pretty)?;
                    } else {
                        // 人間向け簡易表示
                        for p in list {
                            println!("{:<15} [{:?}] {}", p.id, p.auth_type, p.base_url);
                        }
                    }
                }
                ProviderCommands::Remove { id } => {
                    provider_app.remove_provider(&id)?;
                    if cli_args.json {
                        print_json_success(
                            serde_json::json!({ "id": id, "removed": true }),
                            cli_args.pretty,
                        )?;
                    } else {
                        println!("Provider '{}' removed.", id);
                    }
                }
            }
        }
        Commands::Auth { cmd } => match cmd {
            AuthCommands::Login {
                provider_id,
                api_key_stdin,
                principal_id,
                tenant_id,
            } => {
                let principal_id = principal_id.as_deref().unwrap_or("local-user");
                let tenant_id = tenant_id.as_deref().unwrap_or("local");
                let provider = metadata_db.get_provider(&provider_id)?.ok_or_else(|| {
                    api_cli::error::CliError::ProviderNotFound(provider_id.clone())
                })?;

                if provider.auth_type == domain::provider::AuthType::ApiKey {
                    if cli_args.json && !api_key_stdin {
                        return Err(api_cli::error::CliError::InvalidInput(
                            "JSON mode requires --api-key-stdin for API Key login".into(),
                        )
                        .into());
                    }
                    let supplied_key = if api_key_stdin {
                        let mut value = String::new();
                        std::io::stdin()
                            .take(MAX_STDIN_SECRET_BYTES + 1)
                            .read_to_string(&mut value)?;
                        if value.len() as u64 > MAX_STDIN_SECRET_BYTES {
                            return Err(api_cli::error::CliError::InvalidInput(
                                "API key from standard input exceeds 65536 bytes".into(),
                            )
                            .into());
                        }
                        while matches!(value.chars().last(), Some('\n' | '\r')) {
                            value.pop();
                        }
                        if value.is_empty() {
                            return Err(api_cli::error::CliError::AuthRequired.into());
                        }
                        Some(value)
                    } else {
                        None
                    };
                    auth_app.login_api_key_for(
                        &provider_id,
                        supplied_key.as_deref(),
                        principal_id,
                        tenant_id,
                    )?;
                    if cli_args.json {
                        print_json_success(
                            serde_json::json!({
                                "provider_id": provider_id,
                                "principal_id": principal_id,
                                "tenant_id": tenant_id,
                                "auth_type": "api-key",
                                "authenticated": true
                            }),
                            cli_args.pretty,
                        )?;
                    } else {
                        println!("Logged in to '{}' via API Key.", provider_id);
                    }
                } else {
                    if api_key_stdin {
                        return Err(api_cli::error::CliError::InvalidProvider(
                            "--api-key-stdin is only valid for API Key providers".into(),
                        )
                        .into());
                    }
                    auth_app
                        .login_oauth_pkce_for(&provider_id, principal_id, tenant_id)
                        .await?;
                    if cli_args.json {
                        print_json_success(
                            serde_json::json!({
                                "provider_id": provider_id,
                                "principal_id": principal_id,
                                "tenant_id": tenant_id,
                                "auth_type": "oauth-pkce",
                                "authenticated": true
                            }),
                            cli_args.pretty,
                        )?;
                    } else {
                        println!("Logged in to '{}' via OAuth PKCE.", provider_id);
                    }
                }
            }
            AuthCommands::Status {
                provider_id,
                principal_id,
                tenant_id,
            } => {
                let principal_id = principal_id.as_deref().unwrap_or("local-user");
                let tenant_id = tenant_id.as_deref().unwrap_or("local");
                if let Some(session) =
                    metadata_db.get_latest_session_for(&provider_id, principal_id, tenant_id)?
                {
                    let state = session
                        .authentication_status_at(chrono::Utc::now())
                        .as_str();
                    if cli_args.json {
                        print_json_success(
                            serde_json::json!({
                                "provider_id": provider_id,
                                "principal_id": principal_id,
                                "tenant_id": tenant_id,
                                "status": state,
                                "expires_at": session.expires_at
                            }),
                            cli_args.pretty,
                        )?;
                    } else {
                        println!(
                            "Authentication status: {state} (expires: {:?})",
                            session.expires_at
                        );
                    }
                } else if cli_args.json {
                    print_json_success(
                        serde_json::json!({
                            "provider_id": provider_id,
                            "principal_id": principal_id,
                            "tenant_id": tenant_id,
                            "status": "not_authenticated",
                            "expires_at": null
                        }),
                        cli_args.pretty,
                    )?;
                } else {
                    println!("Not logged in.");
                }
            }
        },
        Commands::Api { cmd } => match cmd {
            ApiCommands::Call {
                provider_id,
                method,
                path,
                body,
            } => {
                let json_body = if let Some(b) = body {
                    Some(serde_json::from_str(&b).map_err(|e| {
                        api_cli::error::CliError::InvalidInput(format!("Invalid JSON body: {e}"))
                    })?)
                } else {
                    None
                };
                let res = api_app
                    .call(&provider_id, &method, &path, json_body)
                    .await?;
                if cli_args.json {
                    print_json_success(res, cli_args.pretty)?;
                } else {
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
            }
        },
        Commands::Mcp { cmd } => {
            let action_app = load_action_app()?;
            match cmd {
                McpCommands::Serve => {
                    let mcp_server = mcp::McpServer::new(&action_app);
                    mcp_server.run().await?;
                }
                McpCommands::ServeHttp(args) => {
                    let client_secret = std::env::var(&args.client_secret_env).map_err(|_| {
                        api_cli::error::CliError::Internal(format!(
                            "required secret environment variable {} is not set",
                            args.client_secret_env
                        ))
                    })?;
                    let redis_url = args
                        .redis_url_env
                        .as_deref()
                        .map(|name| {
                            std::env::var(name).map_err(|_| {
                                api_cli::error::CliError::Internal(format!(
                                    "Redis URL environment variable {name} is not set"
                                ))
                            })
                        })
                        .transpose()?;
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
                            requests_per_minute: args.requests_per_minute,
                            rate_limit_burst: args.rate_limit_burst,
                            redis_url,
                            redis_key_prefix: args.redis_key_prefix,
                            session_ttl_seconds: args.session_ttl_seconds,
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
                        print_json_success(serde_json::to_value(&actions)?, cli_args.pretty)?;
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
                        .ok_or_else(|| api_cli::error::CliError::ActionNotFound(name.clone()))?;
                    if cli_args.json {
                        print_json_success(serde_json::to_value(action)?, cli_args.pretty)?;
                    } else {
                        println!("{}", serde_json::to_string_pretty(action)?);
                    }
                }
                ActionCommands::Run {
                    name,
                    input,
                    approval_ticket,
                } => {
                    let input = serde_json::from_str(&input).map_err(|error| {
                        api_cli::error::CliError::SchemaValidation {
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
                    if cli_args.json {
                        print_json_success(output, cli_args.pretty)?;
                    } else {
                        println!("{}", serde_json::to_string_pretty(&output)?);
                    }
                }
                ActionCommands::Prepare { name, input } => {
                    let input = serde_json::from_str(&input).map_err(|error| {
                        api_cli::error::CliError::SchemaValidation {
                            target: "input".into(),
                            message: error.to_string(),
                        }
                    })?;
                    let ticket = action_app.prepare(
                        &app::action::ExecutionIdentity::local(),
                        &name,
                        &input,
                    )?;
                    if cli_args.json {
                        print_json_success(
                            serde_json::json!({ "ticket": ticket }),
                            cli_args.pretty,
                        )?;
                    } else {
                        println!("{ticket}");
                    }
                }
                ActionCommands::Approve { ticket } => {
                    action_app.approve(&app::action::ExecutionIdentity::local(), &ticket)?;
                    if cli_args.json {
                        print_json_success(
                            serde_json::json!({ "ticket": ticket, "approved": true }),
                            cli_args.pretty,
                        )?;
                    } else {
                        println!("Approved ticket {ticket}");
                    }
                }
            }
        }
        Commands::Openapi { .. } => unreachable!("OpenAPI commands are handled before DB setup"),
        Commands::Audit { cmd } => match cmd {
            AuditCommands::List {
                limit,
                action,
                outcome,
            } => {
                let events = metadata_db.list_audit_events(
                    usize::from(limit),
                    action.as_deref(),
                    outcome.as_deref(),
                )?;
                if cli_args.json {
                    print_json_success(serde_json::to_value(&events)?, cli_args.pretty)?;
                } else {
                    for event in events {
                        println!(
                            "{} {} {} {}",
                            event.created_at, event.outcome, event.action_name, event.event_id
                        );
                    }
                }
            }
            AuditCommands::Show { event_id } => {
                let event = metadata_db.get_audit_event(&event_id)?.ok_or_else(|| {
                    api_cli::error::CliError::AuditEventNotFound(event_id.clone())
                })?;
                if cli_args.json {
                    print_json_success(serde_json::to_value(&event)?, cli_args.pretty)?;
                } else {
                    println!("{}", serde_json::to_string_pretty(&event)?);
                }
            }
        },
    }

    Ok(())
}
