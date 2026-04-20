use crate::config::{RuleActionConfig, RuleConfig};

/// Entry point for the rule system.
/// Proxy request and response context is evaluated here.
#[derive(Debug, Clone)]
pub struct RuleEngine {
    rules: Vec<RelayRule>,
}

#[derive(Debug, Clone)]
pub struct RelayRule {
    /// Rule ID for tracing which rule matched.
    pub id: String,
    pub enabled: bool,
    pub description: Option<String>,
    pub matcher: RuleMatcher,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Default)]
pub struct RuleMatcher {
    /// Exact host match, for example `api.example.com`.
    pub host_equals: Option<String>,
    /// URL contains this substring.
    pub url_contains: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RuleAction {
    /// Block the request.
    Block,
    /// Rewrite a request header.
    RewriteHeader { name: String, value: String },
    /// Rewrite the response body.
    RewriteResponseBody { find: String, replace: String },
    /// Route through an upstream proxy.
    UseUpstream { upstream_id: String },
    /// Explicit pass-through.
    PassThrough,
}

#[derive(Debug, Clone, Copy)]
pub enum RulePhase {
    /// Before the request is sent.
    Request,
    /// After the response is received.
    Response,
}

#[derive(Debug, Clone)]
pub struct RuleDecision {
    /// Evaluation phase.
    pub phase: RulePhase,
    /// Matched rule IDs.
    pub matched_rule_ids: Vec<String>,
    /// Effects produced by matched rules.
    pub effects: Vec<RuleEffect>,
}

#[derive(Debug, Clone)]
pub enum RuleEffect {
    /// Block during execution.
    Block,
    RewriteHeader {
        name: String,
        value: String,
    },
    RewriteResponseBody {
        find: String,
        replace: String,
    },
    UseUpstream {
        upstream_id: String,
    },
    PassThrough,
}

#[derive(Debug, Clone)]
pub struct RuleRequestContext {
    /// Request host, usually from the URL or Host header.
    pub host: Option<String>,
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct RuleResponseContext {
    /// URL for the response.
    pub url: String,
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body_preview: Option<String>,
}

impl RuleEngine {
    pub fn from_config(config_rules: &[RuleConfig]) -> Self {
        // Convert config shape into a structure that is easier to use at runtime.
        let rules = config_rules.iter().map(RelayRule::from_config).collect();
        Self { rules }
    }

    pub fn evaluate_request(&self, ctx: &RuleRequestContext) -> RuleDecision {
        // Request phase usually decides:
        // - whether to block
        // - whether to rewrite headers
        // - whether to switch upstreams
        self.evaluate(
            RulePhase::Request,
            |rule| rule.matches_request(ctx),
            |rule| rule.to_effect(),
        )
    }

    pub fn evaluate_response(&self, ctx: &RuleResponseContext) -> RuleDecision {
        // Response phase usually decides:
        // - whether to rewrite the body
        // - whether to add later processing
        self.evaluate(
            RulePhase::Response,
            |rule| rule.matches_response(ctx),
            |rule| rule.to_effect(),
        )
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    fn evaluate<FMatch, FEffect>(
        &self,
        phase: RulePhase,
        matcher: FMatch,
        effect_builder: FEffect,
    ) -> RuleDecision
    where
        FMatch: Fn(&RelayRule) -> bool,
        FEffect: Fn(&RelayRule) -> RuleEffect,
    {
        let mut matched_rule_ids = Vec::new();
        let mut effects = Vec::new();

        // Use a simple linear scan for now.
        // If rule count grows later, revisit optimization and priority design.
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if matcher(rule) {
                matched_rule_ids.push(rule.id.clone());
                effects.push(effect_builder(rule));
            }
        }

        RuleDecision {
            phase,
            matched_rule_ids,
            effects,
        }
    }
}

impl RelayRule {
    fn from_config(config: &RuleConfig) -> Self {
        Self {
            id: config.id.clone(),
            enabled: config.enabled,
            description: config.description.clone(),
            matcher: RuleMatcher {
                host_equals: config.match_host.clone(),
                url_contains: config.url_contains.clone(),
            },
            action: RuleAction::from_config(config),
        }
    }

    fn matches_request(&self, ctx: &RuleRequestContext) -> bool {
        // The first matcher version is simple: host and URL conditions must both match.
        self.matcher.matches_host(ctx.host.as_deref()) && self.matcher.matches_url(&ctx.url)
    }

    fn matches_response(&self, ctx: &RuleResponseContext) -> bool {
        // Response matching only uses the URL for now. Status, header, and body conditions can be added later.
        self.matcher.matches_url(&ctx.url)
    }

    fn to_effect(&self) -> RuleEffect {
        // Convert the high-level action config into an execution-time effect.
        match &self.action {
            RuleAction::Block => RuleEffect::Block,
            RuleAction::RewriteHeader { name, value } => RuleEffect::RewriteHeader {
                name: name.clone(),
                value: value.clone(),
            },
            RuleAction::RewriteResponseBody { find, replace } => RuleEffect::RewriteResponseBody {
                find: find.clone(),
                replace: replace.clone(),
            },
            RuleAction::UseUpstream { upstream_id } => RuleEffect::UseUpstream {
                upstream_id: upstream_id.clone(),
            },
            RuleAction::PassThrough => RuleEffect::PassThrough,
        }
    }
}

impl RuleMatcher {
    fn matches_host(&self, host: Option<&str>) -> bool {
        match &self.host_equals {
            // If a host condition exists, it must match.
            Some(expected) => host
                .map(|value| value.eq_ignore_ascii_case(expected))
                .unwrap_or(false),
            // No host condition means no host restriction.
            None => true,
        }
    }

    fn matches_url(&self, url: &str) -> bool {
        match &self.url_contains {
            // The first version only does a substring match.
            Some(fragment) => url.contains(fragment),
            None => true,
        }
    }
}

impl RuleAction {
    fn from_config(config: &RuleConfig) -> Self {
        // Normalize enum values and fields from config into an easier action shape.
        match config.action {
            RuleActionConfig::Block => Self::Block,
            RuleActionConfig::RewriteHeader => Self::RewriteHeader {
                name: config
                    .header_name
                    .clone()
                    .unwrap_or_else(|| "X-RelayGate-Placeholder".to_string()),
                value: config
                    .header_value
                    .clone()
                    .unwrap_or_else(|| "replace-me".to_string()),
            },
            RuleActionConfig::RewriteResponseBody => Self::RewriteResponseBody {
                find: config.body_find.clone().unwrap_or_default(),
                replace: config.body_replace.clone().unwrap_or_default(),
            },
            RuleActionConfig::UseUpstream => Self::UseUpstream {
                upstream_id: config
                    .upstream_id
                    .clone()
                    .unwrap_or_else(|| "default".to_string()),
            },
            RuleActionConfig::PassThrough => Self::PassThrough,
        }
    }
}
