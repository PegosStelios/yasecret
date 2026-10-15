use clap::Args;

#[derive(Args)]
pub struct McpArgs {
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

pub async fn run(args: McpArgs) -> yasecret_core::Result<()> {
    use rmcp::ServiceExt;

    let path = crate::unlock::db_path(args.db.as_deref());
    let session = crate::unlock::unlock(&path, args.password.as_deref())?;
    let allow_plaintext = std::env::var("YASECRET_MCP_ALLOW_PLAINTEXT")
        .map(|v| v == "1")
        .unwrap_or(false);

    let server = crate::mcp_server::YasecretServer::new(&path, session.password, allow_plaintext);
    let transport = rmcp::transport::io::stdio();
    let running = server
        .serve(transport)
        .await
        .map_err(|e| yasecret_core::YasecretError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
    running
        .waiting()
        .await
        .map_err(|e| yasecret_core::YasecretError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
    Ok(())
}
