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
    /// Print shell statements that set an environment's variables: eval "$(yasecret env -p app -e dev)"
    Env(cmd::shellenv::EnvArgs),
    /// Write a .env.example listing an environment's keys (no values)
    Example(cmd::example::ExampleArgs),
    /// Check that every key in a .env.example is set; exit 0 ok, 1 missing, 2 error
    Check(cmd::check::CheckArgs),
    /// Make an environment inherit another's variables (or stop, with --none)
    Inherit(cmd::inherit::InheritArgs),
    /// Look for vault secrets in files or git history (names only); exit 0 clean, 1 found, 2 error
    Scan(cmd::scan::ScanArgs),
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
    /// Change the master password, make a recovery key, back up or restore the vault
    Vault(cmd::vault::VaultArgs),
    /// Run an always-on peer that keeps shared projects reachable while their owner is offline
    Relay(cmd::relay::RelayArgs),
}

/// Exit codes for commands meant for CI, like diff(1): 0 fine, 1 found a problem, 2 couldn't check.
fn exit_with(result: yasecret_core::Result<bool>) -> yasecret_core::Result<()> {
    match result {
        Ok(false) => Ok(()),
        Ok(true) => std::process::exit(1),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result: yasecret_core::Result<()> = match cli.command {
        Commands::Pull(args) => cmd::pull::run(args),
        Commands::Push(args) => cmd::push::run(args),
        Commands::Diff(args) => exit_with(cmd::diff::run(args)),
        Commands::Dev(args) => cmd::dev::run(args),
        Commands::Env(args) => cmd::shellenv::run(args),
        Commands::Example(args) => cmd::example::run(args),
        Commands::Check(args) => exit_with(cmd::check::run(args)),
        Commands::Scan(args) => exit_with(cmd::scan::run(args)),
        Commands::Inherit(args) => cmd::inherit::run(args),
        Commands::Run(args) => cmd::run::run(args),
        Commands::Share(args) => cmd::share::run(args).await,
        Commands::Join(args) => cmd::join::run(args).await,
        Commands::Peers(args) => cmd::peers::run(args),
        Commands::Mcp(args) => cmd::mcp::run(args).await,
        Commands::Relay(args) => cmd::relay::run(args).await,
        Commands::Vault(args) => cmd::vault::run(args),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
