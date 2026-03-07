use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "atomic", about = "Identity for AI agents", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize agent identity and start server
    Init {
        /// Domain name for the agent (e.g., fin.acme.com)
        #[arg(long)]
        domain: String,

        /// Port to bind the server to
        #[arg(long, default_value = "443")]
        port: u16,

        /// Disable TLS (for behind-proxy setups)
        #[arg(long)]
        no_tls: bool,

        /// Path to TLS certificate (bring your own)
        #[arg(long)]
        tls_cert: Option<String>,

        /// Path to TLS private key (bring your own)
        #[arg(long)]
        tls_key: Option<String>,

        /// Overwrite existing identity
        #[arg(long)]
        force: bool,
    },

    /// Run the HTTP server (used internally, runs in foreground)
    Serve,

    /// Stop the running server
    Stop,

    /// Show local agent identity
    Whoami,

    /// Show server and vault status
    Status,

    /// Verify a remote agent's identity
    Verify {
        /// Domain of the agent to verify
        domain: String,
    },

    /// Generate a one-time deposit URL
    DepositUrl {
        /// Label for the deposited secret
        #[arg(long)]
        label: String,

        /// Expiry duration (e.g., 10m, 1h)
        #[arg(long, default_value = "10m")]
        expires: String,
    },

    /// Show deposit audit log
    Deposits {
        /// Filter by label
        #[arg(long)]
        label: Option<String>,
    },

    /// Encrypted secret vault
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },

    /// Host a verification code for domain proof
    MagicLink {
        #[command(subcommand)]
        command: MagicLinkCommand,
    },

    /// Sign an outgoing HTTP request
    Sign {
        /// Print modified command without executing
        #[arg(long)]
        dry_run: bool,

        /// The command to wrap (e.g., curl ...)
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Key management
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },

    /// Systemd service management
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
}

#[derive(Subcommand)]
pub enum VaultCommand {
    /// Store a secret
    Set {
        /// Label for the secret
        label: String,
        /// Secret value
        value: String,
    },
    /// Retrieve a secret
    Get {
        /// Label of the secret
        label: String,
    },
    /// List all secret labels
    List,
    /// Delete a secret
    Delete {
        /// Label of the secret to delete
        label: String,
    },
}

#[derive(Subcommand)]
pub enum MagicLinkCommand {
    /// Host a code for a service to verify
    Host {
        /// The verification code to host
        code: String,
        /// How long to host it (e.g., 5m, 10m)
        #[arg(long, default_value = "5m")]
        expires: String,
    },
    /// List active magic links
    List,
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Rotate the agent's keypair
    Rotate,
    /// Emergency revoke the agent's identity
    Revoke,
}

#[derive(Subcommand)]
pub enum ServiceCommand {
    /// Install as systemd service
    Install,
    /// Uninstall systemd service
    Uninstall,
    /// Show service status
    Status,
}
