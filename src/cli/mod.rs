use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "api-cli", version, about = "API CLI and MCP server")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Output in JSON format
    #[arg(long, global = true)]
    pub json: bool,

    /// Pretty print JSON output
    #[arg(long, global = true, requires = "json")]
    pub pretty: bool,

    /// Verboase logging
    #[arg(short, long, global = true)]
    pub verbose: bool,
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
        #[command(subcommand)]
        cmd: McpCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum McpCommands {
    /// Run as a stdio-based MCP server
    Serve,
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_provider_add_command() {
        let cli = Cli::try_parse_from([
            "api-cli",
            "provider",
            "add",
            "--id",
            "openai",
            "--base-url",
            "https://api.example.com",
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
        ])
        .expect("parse provider add");

        match cli.command {
            Commands::Provider { cmd: ProviderCommands::Add { id, base_url, auth_type, scopes, client_id, auth_url, token_url } } => {
                assert_eq!(id, "openai");
                assert_eq!(base_url, "https://api.example.com");
                assert_eq!(auth_type, "oauth-pkce");
                assert_eq!(scopes.as_deref(), Some("read,write"));
                assert_eq!(client_id.as_deref(), Some("client-1"));
                assert_eq!(auth_url.as_deref(), Some("https://id.example.com/auth"));
                assert_eq!(token_url.as_deref(), Some("https://id.example.com/token"));
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn parses_api_call_with_body_and_global_flags() {
        let cli = Cli::try_parse_from([
            "api-cli",
            "--json",
            "--pretty",
            "--verbose",
            "api",
            "call",
            "provider-1",
            "POST",
            "/v1/chat",
            "--body",
            "{\"x\":1}",
        ])
        .expect("parse api call");

        assert!(cli.json);
        assert!(cli.pretty);
        assert!(cli.verbose);

        match cli.command {
            Commands::Api { cmd: ApiCommands::Call { provider_id, method, path, body } } => {
                assert_eq!(provider_id, "provider-1");
                assert_eq!(method, "POST");
                assert_eq!(path, "/v1/chat");
                assert_eq!(body.as_deref(), Some("{\"x\":1}"));
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn pretty_flag_requires_json_flag() {
        let err = Cli::try_parse_from(["api-cli", "--pretty", "provider", "list"])
            .expect_err("pretty without json should fail");
        let err_text = err.to_string();
        assert!(err_text.contains("--json"));
    }

    #[test]
    fn parses_mcp_serve_command() {
        let cli = Cli::try_parse_from(["api-cli", "mcp", "serve"]).expect("parse mcp serve");
        assert!(!cli.json);
        assert!(!cli.pretty);
        assert!(!cli.verbose);

        match cli.command {
            Commands::Mcp { cmd: McpCommands::Serve } => {}
            _ => panic!("unexpected command variant"),
        }
    }
}
