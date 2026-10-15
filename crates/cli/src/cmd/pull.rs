use clap::Args;

#[derive(Args)]
pub struct PullArgs {}

pub fn run(_args: PullArgs) -> yasecret_core::Result<()> {
    Ok(())
}
