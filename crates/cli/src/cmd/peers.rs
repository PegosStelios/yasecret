use clap::{Args, Subcommand};

#[derive(Args)]
pub struct PeersArgs {
    #[command(subcommand)]
    pub subcmd: PeersSubcmd,
    #[arg(long, global = true, hide = true)]
    pub db: Option<String>,
    #[arg(long, global = true, hide = true)]
    pub password: Option<String>,
}

#[derive(Subcommand)]
pub enum PeersSubcmd {
    #[command(name = "self")]
    Self_,
}

pub fn run(args: PeersArgs) -> yasecret_core::Result<()> {
    let path = crate::unlock::db_path(args.db.as_deref());
    let session = crate::unlock::unlock(&path, args.password.as_deref())?;
    match args.subcmd {
        PeersSubcmd::Self_ => {
            println!("{}", hex::encode(session.identity.x25519_public().as_bytes()));
        }
    }
    Ok(())
}
