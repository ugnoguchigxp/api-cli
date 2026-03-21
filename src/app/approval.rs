use std::collections::HashSet;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct ApprovalCache {
    approved_keys: Arc<Mutex<HashSet<String>>>,
}

impl ApprovalCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn make_key(provider_id: &str, method: &str, path: &str) -> String {
        format!("{}:{}:{}", provider_id, method, path)
    }

    pub fn is_approved(&self, provider_id: &str, method: &str, path: &str) -> bool {
        let key = Self::make_key(provider_id, method, path);
        if let Ok(set) = self.approved_keys.lock() {
            set.contains(&key)
        } else {
            false
        }
    }

    #[allow(dead_code)]
    pub fn approve(&self, provider_id: &str, method: &str, path: &str) {
        let key = Self::make_key(provider_id, method, path);
        if let Ok(mut set) = self.approved_keys.lock() {
            set.insert(key);
        }
    }
}
