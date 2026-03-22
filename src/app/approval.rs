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

#[cfg(test)]
mod tests {
    use super::ApprovalCache;

    #[test]
    fn is_approved_returns_false_by_default() {
        let cache = ApprovalCache::new();
        assert!(!cache.is_approved("p1", "GET", "/v1/test"));
    }

    #[test]
    fn approve_marks_endpoint_as_approved() {
        let cache = ApprovalCache::new();
        cache.approve("p1", "GET", "/v1/test");

        assert!(cache.is_approved("p1", "GET", "/v1/test"));
        assert!(!cache.is_approved("p1", "POST", "/v1/test"));
        assert!(!cache.is_approved("p2", "GET", "/v1/test"));
    }
}
