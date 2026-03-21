use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "api-cli", version, about = "API CLI and MCP server")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Provider management
    Provider {
        #[command(subcommand)]
        cmd: ProviderCommands,
    },
    /// Authentication management
    Auth {
        #[command(subcommand)]
        cmd: AuthCommands,
    },
    /// API Interaction
    Api {
        #[command(subcommand)]
        cmd: ApiCommands,
    },
    /// Start MCP server
    Mcp {
        #[arg(long, default_value = "serve")]
        action: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ProviderCommands {
    Add {
        #[arg(long)]
        id: String,
        #[arg(long)]
        base_url: String,
        #[arg(long, default_value = "api-key")]
        auth_type: String,
        #[arg(long)]
        scopes: Option<String>,
        #[arg(long)]
        client_id: Option<String>,
        #[arg(long)]
        auth_url: Option<String>,
        #[arg(long)]
        token_url: Option<String>,
    },
    List,
    Remove {
        id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuthCommands {
    Login {
        provider_id: String,
        #[arg(long)]
        api_key: Option<String>,
    },
    Status {
        provider_id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ApiCommands {
    Call {
        provider_id: String,
        method: String,
        path: String,
        #[arg(long)]
        body: Option<String>,
    },
}
