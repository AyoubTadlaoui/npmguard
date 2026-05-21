//! npmguard-mcp — MCP server that exposes npmguard's risk evaluation as an
//! `install_package` tool for AI coding assistants (Claude Code, Cursor, Windsurf).
//!
//! Transport: stdio. The host launches this binary and speaks JSON-RPC over
//! stdin/stdout per the Model Context Protocol spec.

use std::sync::Arc;

use std::future::Future;

use anyhow::Result;
use rmcp::{
    handler::server::router::tool::ToolRouter,
    handler::server::tool::Parameters,
    model::{
        CallToolResult, Content, ErrorData, Implementation, ProtocolVersion, ServerCapabilities,
        ServerInfo,
    },
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
    ServerHandler, ServiceExt,
};
use serde::{Deserialize, Serialize};

use npmguard_cache::VerdictCache;
use npmguard_risk::{PackageRef, RiskEngine, RiskLevel};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct InstallPackageArgs {
    /// npm package name. Scoped packages like `@scope/name` are supported.
    name: String,
    /// Optional pinned version. If omitted, the latest version is evaluated.
    #[serde(default)]
    version: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerdictResponse {
    package: String,
    resolved_version: String,
    level: &'static str,
    score: u32,
    /// Human-readable list of triggered signals.
    signals: Vec<SignalResponse>,
    /// Hint for the AI assistant about whether to proceed.
    recommendation: String,
}

#[derive(Debug, Serialize)]
struct SignalResponse {
    kind: String,
    points: u32,
    detail: String,
}

#[derive(Clone)]
struct Server {
    engine: Arc<RiskEngine>,
    cache: Arc<VerdictCache>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl Server {
    fn new(engine: Arc<RiskEngine>, cache: Arc<VerdictCache>) -> Self {
        Self {
            engine,
            cache,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Evaluate the risk of an npm package before installing it. Returns a structured verdict (ok/warn/block) with the signals that triggered. Use this BEFORE calling `npm install` for any package. If level is 'block', do not install without explicit user approval."
    )]
    async fn install_package(
        &self,
        params: Parameters<InstallPackageArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let args = params.0;
        let pkg = PackageRef::new(args.name.clone(), args.version.clone());

        // Cache-aware path: fetch metadata, consult cache, full-evaluate on miss.
        let meta = self.engine.fetch_metadata(&pkg).await.map_err(|e| {
            // A pinned/unknown version (or missing package) is a client input
            // problem, not a server fault — surface it as invalid_params with a
            // clear message instead of an opaque internal error.
            let full = format!("{:#}", e);
            // Both a missing version ("... not found in registry packument") and
            // a missing package (registry "returned 404") are client input
            // problems, not server faults — surface them as invalid_params.
            if full.contains("not found in registry") || full.contains("returned 404") {
                ErrorData::invalid_params(
                    format!(
                        "Package or version not found in the npm registry: {}. Check the package name and version.",
                        pkg.display()
                    ),
                    None,
                )
            } else {
                ErrorData::internal_error(format!("fetch_metadata: {}", full), None)
            }
        })?;
        let signal_hash = self.engine.signal_set_hash();
        let verdict = match self.cache.get(&pkg, &meta.resolved_version, &signal_hash) {
            Ok(Some(cached)) => cached,
            _ => {
                let v = self
                    .engine
                    .evaluate_from_metadata(&pkg, meta)
                    .await
                    .map_err(|e| {
                        ErrorData::internal_error(format!("evaluate failed: {}", e), None)
                    })?;
                let _ = self.cache.put(&v);
                v
            }
        };

        let response = VerdictResponse {
            package: pkg.display(),
            resolved_version: verdict.resolved_version.clone(),
            level: match verdict.level {
                RiskLevel::Ok => "ok",
                RiskLevel::Warn => "warn",
                RiskLevel::Block => "block",
            },
            score: verdict.score,
            signals: verdict
                .signals
                .iter()
                .map(|s| SignalResponse {
                    kind: format!("{:?}", s.kind),
                    points: s.points,
                    detail: s.detail.clone(),
                })
                .collect(),
            recommendation: match verdict.level {
                RiskLevel::Ok if verdict.signals.is_empty() => {
                    "Safe to install. No risk signals detected.".to_string()
                }
                RiskLevel::Ok => format!(
                    "Low risk — {} minor signal(s) detected, below the warning threshold. Likely safe to install; review the signals if this dependency is security-sensitive.",
                    verdict.signals.len()
                ),
                RiskLevel::Warn => "Warn — surface the signals to the user and get explicit approval before running `npm install`.".to_string(),
                RiskLevel::Block => "Block — do NOT install this package without explicit user override. Present the signals and ask the user to confirm.".to_string(),
            },
        };
        let body = serde_json::to_string_pretty(&response)
            .map_err(|e| ErrorData::internal_error(format!("serialize: {}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(body)]))
    }
}

#[tool_handler]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Use the install_package tool to evaluate npm package risk before running `npm install`. Always block on level='block'; surface signals to the user on 'warn'.".into(),
            ),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // stderr-only logging — stdio is reserved for MCP framing.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,npmguard=info")),
        )
        .init();

    let engine = Arc::new(RiskEngine::new()?);
    let cache_path = VerdictCache::default_path()?;
    let cache = Arc::new(VerdictCache::open(&cache_path)?);

    let server = Server::new(engine, cache);
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
