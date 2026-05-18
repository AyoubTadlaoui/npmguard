//! npmguard-risk
//!
//! Risk signal fetchers and composite scoring for npm packages.
//!
//! Surface stability: the public types in this crate are the contract that
//! `npmguard-cache`, `npmguard-mcp`, and `npmguard-cli` build against. Changes
//! here ripple through the workspace.

pub mod engine;
pub mod scoring;
pub mod signals;
pub mod types;

pub use engine::RiskEngine;
pub use scoring::{compute_level, Thresholds};
pub use signals::PackageMetadata;
pub use types::{PackageRef, RiskLevel, RiskVerdict, Signal, SignalKind, SignalSetHash};
