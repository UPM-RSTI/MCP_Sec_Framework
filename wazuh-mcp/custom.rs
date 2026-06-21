//! Custom tools: get_wazuh_latest_alert and propose_wazuh_rule
//!
//! Add to src/tools/mod.rs:
//!   pub mod custom;
//!
//! Add to src/main.rs (in the tool registration block):
//!   .with_tool(custom_tools.clone())

use rmcp::{
    ErrorData as McpError,
    model::{CallToolResult, Content},
    tool,
};
use std::sync::Arc;
use wazuh_client::WazuhIndexerClient;
use super::ToolModule;

/// Parameters for get_wazuh_latest_alert (no params needed)
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetLatestAlertParams {}

/// Parameters for propose_wazuh_rule
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ProposeWazuhRuleParams {
    #[schemars(description = "Rule ID to assign (100000-999999, custom range)")]
    pub rule_id: u32,

    #[schemars(description = "Full rule XML to propose (will NOT be applied automatically)")]
    pub rule_xml: String,
}

/// Custom tools implementation
#[derive(Clone)]
pub struct CustomTools {
    indexer_client: Arc<WazuhIndexerClient>,
}

impl CustomTools {
    pub fn new(indexer_client: Arc<WazuhIndexerClient>) -> Self {
        Self { indexer_client }
    }

    /// Retrieves the single most recent security alert from Wazuh Indexer.
    #[tool(
        name = "get_wazuh_latest_alert",
        description = "Retrieves the single most recent security alert from the Wazuh Indexer. Returns the latest event with full details including agent, rule level, description, IPs and user."
    )]
    pub async fn get_wazuh_latest_alert(
        &self,
        _params: GetLatestAlertParams,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!("Retrieving latest Wazuh alert");

        match self.indexer_client.get_alerts(Some(1)).await {
            Ok(raw_alerts) => {
                if raw_alerts.is_empty() {
                    return Self::not_found_result("Wazuh alerts");
                }

                let alert_value = &raw_alerts[0];
                let source = alert_value.get("_source").unwrap_or(alert_value);

                let id = source.get("id")
                    .and_then(|v| v.as_str())
                    .or_else(|| alert_value.get("_id").and_then(|v| v.as_str()))
                    .unwrap_or("Unknown ID");

                let timestamp = source.get("timestamp")
                    .and_then(|t| t.as_str())
                    .unwrap_or("Unknown time");

                let agent_name = source.get("agent")
                    .and_then(|a| a.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("Unknown agent");

                let rule_level = source.get("rule")
                    .and_then(|r| r.get("level"))
                    .and_then(|l| l.as_u64())
                    .unwrap_or(0);

                let description = source.get("rule")
                    .and_then(|r| r.get("description"))
                    .and_then(|d| d.as_str())
                    .unwrap_or("No description available");

                let rule_id = source.get("rule")
                    .and_then(|r| r.get("id"))
                    .and_then(|i| i.as_str())
                    .unwrap_or("Unknown rule ID");

                let src_ip = source.get("data")
                    .and_then(|d| d.get("srcip"))
                    .and_then(|ip| ip.as_str())
                    .or_else(|| source.get("data")
                        .and_then(|d| d.get("src_ip"))
                        .and_then(|ip| ip.as_str()))
                    .unwrap_or("");

                let dst_ip = source.get("data")
                    .and_then(|d| d.get("dstip"))
                    .and_then(|ip| ip.as_str())
                    .or_else(|| source.get("data")
                        .and_then(|d| d.get("dst_ip"))
                        .and_then(|ip| ip.as_str()))
                    .unwrap_or("");

                let src_user = source.get("data")
                    .and_then(|d| d.get("srcuser"))
                    .and_then(|u| u.as_str())
                    .or_else(|| source.get("data")
                        .and_then(|d| d.get("dstuser"))
                        .and_then(|u| u.as_str()))
                    .unwrap_or("");

                let mut text = format!(
                    "Latest alert\nAlert ID: {}\nTime: {}\nAgent: {}\nLevel: {}\nDescription: {}\nRule ID: {}",
                    id, timestamp, agent_name, rule_level, description, rule_id
                );
                if !src_ip.is_empty()   { text.push_str(&format!("\nSource IP: {}", src_ip)); }
                if !dst_ip.is_empty()   { text.push_str(&format!("\nDestination IP: {}", dst_ip)); }
                if !src_user.is_empty() { text.push_str(&format!("\nUser: {}", src_user)); }

                Self::success_result(vec![Content::text(text)])
            }
            Err(e) => {
                let msg = Self::format_error("Indexer", "retrieving latest alert", &e);
                tracing::error!("{}", msg);
                Self::error_result(msg)
            }
        }
    }

    /// Proposes a new custom Wazuh detection rule for human review.
    /// Does NOT apply the rule — returns a formatted proposal for analyst approval.
    #[tool(
        name = "propose_wazuh_rule",
        description = "Proposes a new custom Wazuh detection rule for human review. Validates the rule ID (must be 100000-999999) and XML structure. Does NOT apply the rule automatically — returns a formatted proposal for analyst approval."
    )]
    pub async fn propose_wazuh_rule(
        &self,
        params: ProposeWazuhRuleParams,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(rule_id = %params.rule_id, "Proposing Wazuh rule");

        // Validate rule ID is in the custom range
        if params.rule_id < 100_000 || params.rule_id > 999_999 {
            return Self::error_result(format!(
                "Invalid rule_id {}. Custom rules must use IDs in the range 100000-999999.",
                params.rule_id
            ));
        }

        // Basic XML structure validation
        if !params.rule_xml.contains("<rule") || !params.rule_xml.contains("</rule>") {
            return Self::error_result(
                "Invalid rule_xml: must contain <rule ...> and </rule> tags.".to_string()
            );
        }

        // Check the rule XML references the correct rule_id
        let expected_id     = format!("id=\"{}\"", params.rule_id);
        let expected_id_sq  = format!("id='{}'",   params.rule_id);
        if !params.rule_xml.contains(&expected_id) && !params.rule_xml.contains(&expected_id_sq) {
            return Self::error_result(format!(
                "Rule XML does not reference the specified rule_id {}. \
                 Ensure the XML contains id=\"{}\".",
                params.rule_id, params.rule_id
            ));
        }

        let proposal = format!(
            "=== WAZUH RULE PROPOSAL (REQUIRES HUMAN APPROVAL) ===\n\
             Rule ID  : {}\n\n\
             Rule XML:\n{}\n\n\
             --- INSTRUCTIONS FOR ANALYST ---\n\
             1. Review the rule XML above carefully.\n\
             2. If approved, copy the XML to /var/ossec/etc/rules/local_rules.xml\n\
             3. Run: sudo /var/ossec/bin/wazuh-control restart\n\
             4. Verify with: sudo /var/ossec/bin/ossec-logtest\n\
             =====================================================",
            params.rule_id, params.rule_xml
        );

        tracing::info!(rule_id = %params.rule_id, "Rule proposal generated (NOT applied)");
        Self::success_result(vec![Content::text(proposal)])
    }
}

impl ToolModule for CustomTools {}
