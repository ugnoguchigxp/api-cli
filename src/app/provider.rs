use crate::domain::provider::ProviderConfig;
use crate::error::Result;
use crate::infra::db::MetadataDb;

pub struct ProviderApp<'a> {
    db: &'a MetadataDb,
}

impl<'a> ProviderApp<'a> {
    pub fn new(db: &'a MetadataDb) -> Self {
        Self { db }
    }

    pub fn add_provider(&self, config: ProviderConfig) -> Result<()> {
        self.db.insert_provider(&config)
    }

    pub fn list_providers(&self) -> Result<Vec<ProviderConfig>> {
        self.db.list_providers()
    }

    #[allow(dead_code)]
    pub fn get_provider(&self, id: &str) -> Result<Option<ProviderConfig>> {
        self.db.get_provider(id)
    }

    pub fn remove_provider(&self, id: &str) -> Result<()> {
        self.db.delete_provider(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::provider::AuthType;
    use crate::infra::db::MetadataDb;
    use rusqlite::Connection;

    fn sample_provider(id: &str) -> ProviderConfig {
        ProviderConfig {
            id: id.to_string(),
            base_url: "https://example.com".to_string(),
            auth_type: AuthType::ApiKey,
            scopes: vec!["read".to_string()],
            client_id: None,
            auth_url: None,
            token_url: None,
        }
    }

    #[test]
    fn add_get_list_remove_provider() {
        let conn = Connection::open_in_memory().expect("in-memory metadata db");
        let db = MetadataDb::new(conn).expect("metadata db init");
        let app = ProviderApp::new(&db);
        let config = sample_provider("p1");

        app.add_provider(config).expect("insert provider");

        let found = app.get_provider("p1").expect("get provider");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "p1");

        let list = app.list_providers().expect("list providers");
        assert_eq!(list.len(), 1);

        app.remove_provider("p1").expect("remove provider");
        assert!(app
            .get_provider("p1")
            .expect("get provider after remove")
            .is_none());
    }
}
