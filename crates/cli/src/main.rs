use clap::{Parser, Subcommand};

mod cmd;
mod unlock;

#[derive(Parser)]
#[command(name = "yasecret", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Pull(cmd::pull::PullArgs),
    Run(cmd::run::RunArgs),
    Share(cmd::share::ShareArgs),
    Join(cmd::join::JoinArgs),
    Peers(cmd::peers::PeersArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result: yasecret_core::Result<()> = match cli.command {
        Commands::Pull(args) => cmd::pull::run(args),
        Commands::Run(args) => cmd::run::run(args),
        Commands::Share(args) => cmd::share::run(args).await,
        Commands::Join(args) => cmd::join::run(args).await,
        Commands::Peers(args) => cmd::peers::run(args),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
