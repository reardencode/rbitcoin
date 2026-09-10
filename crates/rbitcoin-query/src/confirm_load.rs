//! Confirm **load** stage types shared with wire pin / assemble.
//!
//! Parent outs / denserels are pipeline-local ([`crate::BatchParents`]).
//! Spend edges are batch-local ([`SpendEdges`]). Header plans live on
//! [`crate::confirm_parent_cache::ConfirmParentCache`].

use crate::U64Map;

/// Spend-fk → pin-time spend edges (assemble + write).
pub type SpendEdges = U64Map<Vec<crate::SpendEdge>>;
