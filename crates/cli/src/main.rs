use clap::{Parser, Subcommand};

mod cmd;
mod mcp_server;
mod unlock;

#[derive(Parser)]
#[command(name = "yasecret", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Write an environment to a .env file (or stdout)
    Pull(cmd::pull::PullArgs),
    /// Send a local .env or JSON file into an environment
    Push(cmd::push::PushArgs),
    /// Compare a local .env with an environment (key names only); exit 0 same, 1 different, 2 error
    Diff(cmd::diff::DiffArgs),
    /// Keep a local .env up to date as the environment changes
    Dev(cmd::dev::DevArgs),
    /// Run a command with selected variables injected (values masked in its output)
    Run(cmd::run::RunArgs),
    /// Create an invite link for a project and stay online until it's used
    Share(cmd::share::ShareArgs),
    /// Join a shared project from an invite link
    Join(cmd::join::JoinArgs),
    /// Show this device's code for device-bound invites
    Peers(cmd::peers::PeersArgs),
    /// Serve the vault to Claude Code and other MCP clients over stdio
    Mcp(cmd::mcp::McpArgs),
    /// Run an always-on peer that keeps shared projects reachable while their owner is offline
    Relay(cmd::relay::RelayArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result: yasecret_core::Result<()> = match cli.command {
        Commands::Pull(args) => cmd::pull::run(args),
        Commands::Push(args) => cmd::push::run(args),
        // Exit codes follow diff(1): 0 same, 1 different, 2 the comparison failed.
        Commands::Diff(args) => match cmd::diff::run(args) {
            Ok(false) => Ok(()),
            Ok(true) => std::process::exit(1),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        },
        Commands::Dev(args) => cmd::dev::run(args),
        Commands::Run(args) => cmd::run::run(args),
        Commands::Share(args) => cmd::share::run(args).await,
        Commands::Join(args) => cmd::join::run(args).await,
        Commands::Peers(args) => cmd::peers::run(args),
        Commands::Mcp(args) => cmd::mcp::run(args).await,
        Commands::Relay(args) => cmd::relay::run(args).await,
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
