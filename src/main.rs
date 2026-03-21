mod app;
mod cli;
mod domain;
mod error;
mod infra;
mod mcp;

use clap::Parser;
use cli::{Cli, Commands, ProviderCommands, AuthCommands, ApiCommands};
use infra::config;
use infra::crypto::VaultCrypto;
use infra::db::{MetadataDb, VaultDb};
use rusqlite::Connection;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ログ出力を常に stderr に向けることで、stdoutのJSON-RPCの混入を防ぐ
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli_args = Cli::parse();

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
                    let json = serde_json::to_string_pretty(&list)?;
                    println!("{}", json);
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
                    if let Some(key) = api_key {
                        auth_app.login_api_key(&provider_id, &key)?;
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
                    let json_body = body.map(|b| serde_json::from_str(&b).unwrap());
                    match api_app.call(&provider_id, &method, &path, json_body).await {
                        Ok(res) => println!("{}", serde_json::to_string_pretty(&res)?),
                        Err(e) => eprintln!("API execution error: {}", e),
                    }
                }
            }
        }
        Commands::Mcp { action } => {
            if action == "serve" {
                let mcp_server = mcp::McpServer::new(&api_app, &provider_app);
                if let Err(e) = mcp_server.run().await {
                    tracing::error!("MCP Server error: {}", e);
                }
            } else {
                eprintln!("Unknown MCP action: {}", action);
            }
        }
    }

    Ok(())
}
