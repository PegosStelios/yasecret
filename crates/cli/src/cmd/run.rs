use clap::Args;

#[derive(Args)]
pub struct RunArgs {}

pub fn run(_args: RunArgs) -> yasecret_core::Result<()> {
    Ok(())
}
