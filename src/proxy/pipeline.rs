/// Formal names for RelayGate's existing response pipeline branches.
///
/// This is intentionally small: it documents and logs the current stream/buffer
/// split without changing adblock, rewrite, patch, injection, flush, or tunnel behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum PipelineDecision {
    /// Stream bytes through without buffering the full response body.
    FastPath,
    /// Buffer the response body because an existing feature needs body access.
    DeepPath,
    /// Stop the request/response and return an error or close the stream.
    Block,
    /// Return a generated replacement body instead of forwarding upstream bytes.
    Replacement,
    /// Bidirectional tunnel path.
    Tunnel,
}

impl PipelineDecision {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            PipelineDecision::FastPath => "fast_path",
            PipelineDecision::DeepPath => "deep_path",
            PipelineDecision::Block => "block",
            PipelineDecision::Replacement => "replacement",
            PipelineDecision::Tunnel => "tunnel",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PipelineRoute {
    pub(crate) decision: PipelineDecision,
    pub(crate) reason: &'static str,
}

impl PipelineRoute {
    pub(crate) const fn new(decision: PipelineDecision, reason: &'static str) -> Self {
        Self { decision, reason }
    }

    pub(crate) const fn fast_path(reason: &'static str) -> Self {
        Self::new(PipelineDecision::FastPath, reason)
    }

    pub(crate) const fn deep_path(reason: &'static str) -> Self {
        Self::new(PipelineDecision::DeepPath, reason)
    }

    #[allow(dead_code)]
    pub(crate) const fn block(reason: &'static str) -> Self {
        Self::new(PipelineDecision::Block, reason)
    }

    #[allow(dead_code)]
    pub(crate) const fn replacement(reason: &'static str) -> Self {
        Self::new(PipelineDecision::Replacement, reason)
    }

    #[allow(dead_code)]
    pub(crate) const fn tunnel(reason: &'static str) -> Self {
        Self::new(PipelineDecision::Tunnel, reason)
    }

    pub(crate) const fn pipeline_label(self) -> &'static str {
        self.decision.as_str()
    }

    pub(crate) const fn is_fast_path(self) -> bool {
        matches!(self.decision, PipelineDecision::FastPath)
    }
}
