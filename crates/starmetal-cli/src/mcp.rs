use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::transport::stdio;
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt, schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use starmetal_core::error::StarmetalError;
use starmetal_core::package::{ArtifactId, Ecosystem, PackageName};
use starmetal_ops::StarmetalRuntime;

#[derive(Clone)]
pub struct StarmetalMcp {
    runtime: StarmetalRuntime,
    allow_writes: bool,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl StarmetalMcp {
    pub fn new(runtime: StarmetalRuntime, allow_writes: bool) -> Self {
        Self {
            runtime,
            allow_writes,
            tool_router: Self::tool_router(),
        }
    }

    fn write_allowed(&self) -> Result<(), McpError> {
        if self.allow_writes {
            Ok(())
        } else {
            Err(McpError::invalid_request(
                "mutating Starmetal MCP tools require sm mcp serve --allow-writes",
                None,
            ))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
struct EcosystemParams {
    ecosystem: Ecosystem,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
struct PackageParams {
    ecosystem: Ecosystem,
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
struct VersionParams {
    ecosystem: Ecosystem,
    name: String,
    version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
struct ArtifactParams {
    ecosystem: Ecosystem,
    name: String,
    version: String,
    filename: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
struct PublishParams {
    ecosystem: Ecosystem,
    file: String,
    name: String,
    version: String,
    filename: Option<String>,
    license: Option<String>,
}

#[tool_router]
impl StarmetalMcp {
    #[tool(description = "Return the effective redacted Starmetal configuration")]
    async fn config_show(&self) -> Result<CallToolResult, McpError> {
        json_result(self.runtime.config.redacted_value())
    }

    #[tool(description = "Return Starmetal registry, storage, and bind status")]
    async fn registry_status(&self) -> Result<CallToolResult, McpError> {
        json_result(self.runtime.status())
    }

    #[tool(description = "List cached packages for an ecosystem")]
    async fn package_list(
        &self,
        params: Parameters<EcosystemParams>,
    ) -> Result<CallToolResult, McpError> {
        let packages = self
            .runtime
            .list_packages(params.0.ecosystem)
            .await
            .map_err(mcp_error)?;
        json_result(packages)
    }

    #[tool(description = "List versions for a package")]
    async fn package_versions(
        &self,
        params: Parameters<PackageParams>,
    ) -> Result<CallToolResult, McpError> {
        let versions = self
            .runtime
            .versions(params.0.ecosystem, &params.0.name)
            .await
            .map_err(mcp_error)?;
        json_result(versions)
    }

    #[tool(description = "Return metadata for one package version")]
    async fn package_metadata(
        &self,
        params: Parameters<VersionParams>,
    ) -> Result<CallToolResult, McpError> {
        let metadata = self
            .runtime
            .metadata(params.0.ecosystem, &params.0.name, &params.0.version)
            .await
            .map_err(mcp_error)?;
        json_result(metadata)
    }

    #[tool(description = "Fetch an artifact through Starmetal cache integrity checks")]
    async fn package_fetch(
        &self,
        params: Parameters<ArtifactParams>,
    ) -> Result<CallToolResult, McpError> {
        let artifact = artifact_id(params.0);
        let (artifact, data) = self
            .runtime
            .fetch_artifact(artifact)
            .await
            .map_err(mcp_error)?;
        json_result(starmetal_ops::ArtifactFetchResult {
            artifact,
            bytes: data.len(),
        })
    }

    #[tool(description = "Publish one local artifact with explicit package metadata")]
    async fn package_publish(
        &self,
        params: Parameters<PublishParams>,
    ) -> Result<CallToolResult, McpError> {
        self.write_allowed()?;
        let params = params.0;
        let data = std::fs::read(&params.file).map_err(|err| {
            McpError::invalid_request(format!("failed to read artifact file: {err}"), None)
        })?;
        let filename = params.filename.unwrap_or_else(|| {
            std::path::Path::new(&params.file)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("artifact")
                .to_string()
        });
        let result = self
            .runtime
            .publish_artifact(
                params.ecosystem,
                &params.name,
                &params.version,
                filename,
                data.into(),
                params.license,
            )
            .await
            .map_err(mcp_error)?;
        json_result(result)
    }

    #[tool(description = "Mark a package version as yanked")]
    async fn package_yank(
        &self,
        params: Parameters<VersionParams>,
    ) -> Result<CallToolResult, McpError> {
        self.write_allowed()?;
        let metadata = self
            .runtime
            .set_yanked(params.0.ecosystem, &params.0.name, &params.0.version, true)
            .await
            .map_err(mcp_error)?;
        json_result(metadata)
    }

    #[tool(description = "Mark a package version as not yanked")]
    async fn package_unyank(
        &self,
        params: Parameters<VersionParams>,
    ) -> Result<CallToolResult, McpError> {
        self.write_allowed()?;
        let metadata = self
            .runtime
            .set_yanked(params.0.ecosystem, &params.0.name, &params.0.version, false)
            .await
            .map_err(mcp_error)?;
        json_result(metadata)
    }

    #[tool(description = "Delete a cached artifact and its BLAKE3 sidecar")]
    async fn cache_delete_artifact(
        &self,
        params: Parameters<ArtifactParams>,
    ) -> Result<CallToolResult, McpError> {
        self.write_allowed()?;
        let result = self
            .runtime
            .delete_cached_artifact(&artifact_id(params.0))
            .await
            .map_err(mcp_error)?;
        json_result(result)
    }
}

#[tool_handler]
impl ServerHandler for StarmetalMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Starmetal package registry operations. Mutating tools require sm mcp serve --allow-writes.",
        )
    }
}

pub async fn serve(
    runtime: StarmetalRuntime,
    allow_writes: bool,
) -> starmetal_core::error::Result<()> {
    let service = StarmetalMcp::new(runtime, allow_writes)
        .serve(stdio())
        .await
        .map_err(|err| {
            StarmetalError::Config(format!("failed to start MCP stdio server: {err}"))
        })?;
    service
        .waiting()
        .await
        .map(|_| ())
        .map_err(|err| StarmetalError::Config(format!("MCP server error: {err}")))
}

fn json_result(value: impl Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::json(value)?]))
}

fn mcp_error(err: StarmetalError) -> McpError {
    McpError::internal_error(err.to_string(), None)
}

fn artifact_id(params: ArtifactParams) -> ArtifactId {
    let raw = PackageName::new(&params.name);
    ArtifactId {
        ecosystem: params.ecosystem,
        name: PackageName::new(raw.normalized(params.ecosystem).into_owned()),
        version: params.version,
        filename: params.filename,
    }
}
