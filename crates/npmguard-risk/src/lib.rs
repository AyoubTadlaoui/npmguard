//! npmguard-risk
//!
//! Risk signal fetchers and composite scoring for npm packages.
//!
//! Surface stability: the public types in this crate are the contract that
//! `npmguard-cache`, `npmguard-mcp`, and `npmguard-cli` build against. Changes
//! here ripple through the workspace.

pub mod closure;
pub mod engine;
pub mod resolver;
pub mod scoring;
pub mod signals;
pub mod types;

pub use closure::{ClosureFinding, ClosureReport};
pub use engine::RiskEngine;
pub use resolver::{ResolveOpts, ResolvedNode};
pub use scoring::{compute_level, Thresholds};
pub use signals::registry::PackageNotFound;
pub use signals::PackageMetadata;
pub use types::{PackageRef, RiskLevel, RiskVerdict, Signal, SignalKind, SignalSetHash};
