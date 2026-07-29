use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

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

    /// Verbose logging
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
    /// Validate, inspect, and execute allowlisted Actions
    Action {
        #[command(subcommand)]
        cmd: ActionCommands,
    },
    /// Validate or import an OpenAPI 3 document
    Openapi {
        #[command(subcommand)]
        cmd: OpenapiCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum McpCommands {
    /// Run as a stdio-based MCP server
    Serve,
    /// Run an OAuth-protected Streamable HTTP MCP server
    ServeHttp(Box<ServeHttpArgs>),
}

#[derive(Args, Debug)]
pub struct ServeHttpArgs {
    #[arg(long, default_value = "127.0.0.1:3000")]
    pub listen: std::net::SocketAddr,
    #[arg(long)]
    pub introspection_url: String,
    #[arg(long)]
    pub audience: String,
    #[arg(long)]
    pub client_id: String,
    /// Environment variable holding the introspection client secret
    #[arg(long, default_value = "API_CLI_MCP_INTROSPECTION_SECRET")]
    pub client_secret_env: String,
    #[arg(long, required = true)]
    pub allowed_host: Vec<String>,
    #[arg(long)]
    pub allowed_origin: Vec<String>,
    #[arg(long, default_value_t = 64)]
    pub max_concurrency: usize,
    /// Maximum number of simultaneously retained MCP sessions
    #[arg(long, default_value_t = 1024)]
    pub max_sessions: usize,
    /// Maximum size of one Remote MCP HTTP request body
    #[arg(long, default_value_t = 1_048_576)]
    pub max_request_bytes: usize,
    /// Permit cleartext HTTP on a non-loopback listener (normally use a loopback TLS proxy)
    #[arg(long)]
    pub allow_insecure_http: bool,
}

#[derive(Subcommand, Debug)]
pub enum ActionCommands {
    /// Validate one ActionDefinition file
    Validate { file: PathBuf },
    /// List enabled Actions
    List,
    /// Print one enabled ActionDefinition
    Describe { name: String },
    /// Execute an Action through the same guarded executor used by MCP
    Run {
        name: String,
        /// JSON object containing the Action arguments
        #[arg(long)]
        input: String,
        /// One-time approval ticket returned by prepare
        #[arg(long)]
        approval_ticket: Option<String>,
    },
    /// Create a short-lived approval ticket bound to the complete input
    Prepare {
        name: String,
        #[arg(long)]
        input: String,
    },
    /// Approve a pending local ticket
    Approve { ticket: String },
}

#[derive(Subcommand, Debug)]
pub enum OpenapiCommands {
    /// Validate an OpenAPI 3 document and report importable operations
    Validate { file: PathBuf },
    /// Generate disabled ActionDefinition drafts for operations with operationId
    Import {
        file: PathBuf,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        output_dir: Option<PathBuf>,
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
        /// Send API keys in this header instead of as a Bearer token
        #[arg(long)]
        api_key_header: Option<String>,
        /// Fixed loopback port for OAuth providers that do not allow dynamic ports
        #[arg(long)]
        oauth_redirect_port: Option<u16>,
        /// Permit this provider to resolve to private or loopback addresses
        #[arg(long)]
        allow_private_network: bool,
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
            "--oauth-redirect-port",
            "8080",
        ])
        .expect("parse provider add");

        match cli.command {
            Commands::Provider {
                cmd:
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
                    },
            } => {
                assert_eq!(id, "openai");
                assert_eq!(base_url, "https://api.example.com");
                assert_eq!(auth_type, "oauth-pkce");
                assert_eq!(scopes.as_deref(), Some("read,write"));
                assert_eq!(client_id.as_deref(), Some("client-1"));
                assert_eq!(auth_url.as_deref(), Some("https://id.example.com/auth"));
                assert_eq!(token_url.as_deref(), Some("https://id.example.com/token"));
                assert!(api_key_header.is_none());
                assert_eq!(oauth_redirect_port, Some(8080));
                assert!(!allow_private_network);
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
            Commands::Api {
                cmd:
                    ApiCommands::Call {
                        provider_id,
                        method,
                        path,
                        body,
                    },
            } => {
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
            Commands::Mcp {
                cmd: McpCommands::Serve,
            } => {}
            _ => panic!("unexpected command variant"),
        }
    }
}
