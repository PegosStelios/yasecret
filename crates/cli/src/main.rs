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
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Pull(args) => cmd::pull::run(args),
        Commands::Run(args) => cmd::run::run(args),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
