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
    /// Compare a local .env with an environment (key names only); exits 1 when they differ
    Diff(cmd::diff::DiffArgs),
    /// Keep a local .env up to date as the environment changes
    Dev(cmd::dev::DevArgs),
    Run(cmd::run::RunArgs),
    Share(cmd::share::ShareArgs),
    Join(cmd::join::JoinArgs),
    Peers(cmd::peers::PeersArgs),
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
        Commands::Diff(args) => match cmd::diff::run(args) {
            Ok(differs) => {
                if differs {
                    std::process::exit(1);
                }
                Ok(())
            }
            Err(e) => Err(e),
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
