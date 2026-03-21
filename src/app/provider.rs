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
