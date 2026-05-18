//! Signal modules.
//!
//! Each module produces zero or more `Signal` entries from package metadata or
//! external sources. Signals are additive — the composite score is the sum of
//! all signal points.

pub mod age;
pub mod deprecated;
pub mod github;
pub mod lifecycle;
pub mod maintainers;
pub mod osv;
pub mod registry;
pub mod typosquat;

pub use registry::{NpmRegistryClient, PackageMetadata};
