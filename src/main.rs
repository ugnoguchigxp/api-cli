mod app;
mod cli;
mod domain;
mod error;
mod infra;
mod mcp;

use clap::Parser;
use cli::{Cli, Commands, ProviderCommands, AuthCommands, ApiCommands, McpCommands};
use infra::config;
use infra::crypto::VaultCrypto;
use infra::db::{MetadataDb, VaultDb};
use rusqlite::Connection;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli_args = Cli::parse();

    // ログレベル設定
    let log_level = if cli_args.verbose {
        "debug"
    } else {
        "info"
    };

    // ログ出力を常に stderr に向けることで、stdoutのJSON-RPCの混入を防ぐ
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(log_level))
        .with_writer(std::io::stderr)
        .init();

    // DB関連 初期化
    let meta_conn = Connection::open(config::get_metadata_db_path()?)?;
    let metadata_db = MetadataDb::new(meta_conn)?;

    let vault_conn = Connection::open(config::get_vault_db_path()?)?;
    let vault_db = VaultDb::new(vault_conn)?;

    let vault_crypto = VaultCrypto::load_or_create(&config::get_vault_key_path()?)?;

    // アプリケーション層 初期化
    let provider_app = app::provider::ProviderApp::new(&metadata_db);
    let auth_app = app::auth::AuthApp::new(&metadata_db, &vault_db, &vault_crypto);
    let api_app = app::api::ApiApp::new(&metadata_db, &vault_db, &vault_crypto, &auth_app);

    // ルーティング
    match cli_args.command {
        Commands::Provider { cmd } => {
            match cmd {
                ProviderCommands::Add { id, base_url, auth_type, scopes, client_id, auth_url, token_url } => {
                    let auth_t = match auth_type.as_str() {
                        "api-key" => domain::provider::AuthType::ApiKey,
                        _ => domain::provider::AuthType::OauthPkce,
                    };
                    let config = domain::provider::ProviderConfig {
                        id: id.clone(),
                        base_url,
                        auth_type: auth_t,
                        scopes: scopes.map(|s| s.split(',').map(|x| x.to_string()).collect()).unwrap_or_default(),
                        client_id,
                        auth_url,
                        token_url,
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
        Commands::Auth { cmd } => {
            match cmd {
                AuthCommands::Login { provider_id, api_key } => {
                    let provider = metadata_db.get_provider(&provider_id)?
                        .ok_or_else(|| crate::error::CliError::ProviderNotFound(provider_id.clone()))?;

                    if provider.auth_type == domain::provider::AuthType::ApiKey {
                        auth_app.login_api_key(&provider_id, api_key.as_deref())?;
                        println!("Logged in to '{}' via API Key.", provider_id);
                    } else {
                        if let Err(e) = auth_app.login_oauth_pkce(&provider_id).await {
                            eprintln!("Login failed: {}", e);
                        }
                    }
                }
                AuthCommands::Status { provider_id } => {
                    if let Ok(Some(session)) = metadata_db.get_latest_session(&provider_id) {
                        println!("Logged in: Session Active (expires: {:?})", session.expires_at);
                    } else {
                        println!("Not logged in.");
                    }
                }
            }
        }
        Commands::Api { cmd } => {
            match cmd {
                ApiCommands::Call { provider_id, method, path, body } => {
                    let json_body = if let Some(b) = body {
                        Some(serde_json::from_str(&b)
                            .map_err(|e| crate::error::CliError::Internal(format!("Invalid JSON body: {}", e)))?)
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
                        }
                    }
                }
            }
        }
        Commands::Mcp { cmd } => {
            match cmd {
                McpCommands::Serve => {
                    let mcp_server = mcp::McpServer::new(&api_app, &provider_app);
                    if let Err(e) = mcp_server.run().await {
                        tracing::error!("MCP Server error: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}
