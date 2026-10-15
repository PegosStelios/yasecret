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
    use yasecret_core::YasecretError;

    let path = crate::unlock::db_path(args.db.as_deref());
    let session = crate::unlock::unlock(&path, args.password.as_deref())?;

    // TOFU: insert a session token on first run if table is empty.
    {
        let count: i64 = session.db.conn()
            .query_row("SELECT count(*) FROM mcp_session", [], |r| r.get(0))
            .unwrap_or(0);
        if count == 0 {
            let token = uuid::Uuid::new_v4().to_string();
            let now = yasecret_core::models::now();
            session.db.conn().execute(
                "INSERT INTO mcp_session (token, granted_at) VALUES (?1, ?2)",
                rusqlite::params![&token, now],
            ).map_err(YasecretError::Db)?;
            eprintln!("yasecret: MCP access auto-granted (CLI mode).");
        }
    }

    let allow_plaintext = std::env::var("YASECRET_MCP_ALLOW_PLAINTEXT")
        .map(|v| v == "1")
        .unwrap_or(false);

    let server = crate::mcp_server::YasecretServer::new(&path, session.password, allow_plaintext);
    let transport = rmcp::transport::io::stdio();
    let running = server
        .serve(transport)
        .await
        .map_err(|e| YasecretError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
    running
        .waiting()
        .await
        .map_err(|e| YasecretError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
    Ok(())
}
