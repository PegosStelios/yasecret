use yasecret_core::db::Db;

use crate::{node::SyncNode, Result, SyncError};

/// Create an iroh doc for the project and store (project_id, doc_id, ticket) in sync_doc.
/// Returns the ticket string for sharing with invitees.
pub async fn create_project_doc(db: &Db, node: &SyncNode, project_id: &str) -> Result<String> {
    // Return existing ticket if doc already created
    let existing: rusqlite::Result<String> = db.conn().query_row(
        "SELECT doc_id FROM sync_doc WHERE project_id=?1",
        [project_id],
        |r| r.get(0),
    );
    if let Ok(doc_id) = existing {
        return get_ticket_for_doc(node, &doc_id).await;
    }

    let doc = node.client().create().await.map_err(anyhow::Error::from)?;
    let doc_id = doc.id().to_string();
    let ticket = doc
        .share(
            iroh_docs::api::protocol::ShareMode::Write,
            iroh_docs::api::protocol::AddrInfoOptions::RelayAndAddresses,
        )
        .await
        .map_err(anyhow::Error::from)?;
    let ticket_str = ticket.to_string();

    db.conn().execute(
        "INSERT INTO sync_doc (project_id, doc_id, ticket) VALUES (?1,?2,?3)",
        rusqlite::params![project_id, &doc_id, &ticket_str],
    )?;

    Ok(ticket_str)
}

/// Join an existing iroh doc from a DocTicket string.
/// Stores (project_id, doc_id) in sync_doc. Returns doc_id string.
pub async fn join_project_doc(
    db: &Db,
    node: &SyncNode,
    ticket_str: &str,
    project_id: &str,
) -> Result<String> {
    let ticket: iroh_docs::DocTicket = ticket_str
        .parse()
        .map_err(|_| SyncError::InvalidTicket)?;

    let doc = node
        .client()
        .import(ticket)
        .await
        .map_err(anyhow::Error::from)?;
    let doc_id = doc.id().to_string();

    db.conn().execute(
        "INSERT OR REPLACE INTO sync_doc (project_id, doc_id, ticket) VALUES (?1,?2,?3)",
        rusqlite::params![project_id, &doc_id, ticket_str],
    )?;

    Ok(doc_id)
}

/// Re-generate a share ticket for an existing project doc.
pub async fn get_ticket(db: &Db, node: &SyncNode, project_id: &str) -> Result<String> {
    let doc_id = get_doc_id(db, project_id)?;
    get_ticket_for_doc(node, &doc_id).await
}

/// Look up the iroh doc_id for a project (sync, no iroh call).
pub fn get_doc_id(db: &Db, project_id: &str) -> Result<String> {
    db.conn()
        .query_row(
            "SELECT doc_id FROM sync_doc WHERE project_id=?1",
            [project_id],
            |r| r.get(0),
        )
        .map_err(|_| SyncError::NoDoc(project_id.to_string()))
}

async fn get_ticket_for_doc(node: &SyncNode, doc_id_str: &str) -> Result<String> {
    let doc_id: iroh_docs::NamespaceId = doc_id_str
        .parse()
        .map_err(|_| SyncError::NoDoc(doc_id_str.to_string()))?;
    let doc = node
        .client()
        .open(doc_id)
        .await
        .map_err(anyhow::Error::from)?
        .ok_or_else(|| SyncError::NoDoc(doc_id_str.to_string()))?;
    let ticket = doc
        .share(
            iroh_docs::api::protocol::ShareMode::Write,
            iroh_docs::api::protocol::AddrInfoOptions::RelayAndAddresses,
        )
        .await
        .map_err(anyhow::Error::from)?;
    Ok(ticket.to_string())
}
