pub mod metadata;
pub mod vault;

pub use metadata::MetadataDb;
pub use vault::VaultDb;

fn run_db<T>(operation: impl FnOnce() -> crate::error::Result<T>) -> crate::error::Result<T> {
    if tokio::runtime::Handle::try_current().is_ok_and(|handle| {
        matches!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        )
    }) {
        tokio::task::block_in_place(operation)
    } else {
        operation()
    }
}
