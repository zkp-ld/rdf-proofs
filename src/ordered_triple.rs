use std::collections::BTreeMap;

use crate::{error::RDFProofsError, vc::VerifiableCredentialView};
use oxrdf::{dataset::GraphView, GraphNameRef, NamedOrBlankNode, NamedOrBlankNodeRef, TermRef};

/// `oxrdf::triple::GraphNameRef` with string-based ordering
#[derive(Eq, PartialEq, Clone)]
pub struct OrderedGraphNameRef<'a>(GraphNameRef<'a>);
impl<'a> OrderedGraphNameRef<'a> {
    pub fn new(graph_name_ref: GraphNameRef<'a>) -> Self {
        Self(graph_name_ref)
    }
}
impl Ord for OrderedGraphNameRef<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_string().cmp(&other.0.to_string())
    }
}
impl PartialOrd for OrderedGraphNameRef<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.to_string().partial_cmp(&other.0.to_string())
    }
}
impl<'a> From<OrderedGraphNameRef<'a>> for GraphNameRef<'a> {
    fn from(value: OrderedGraphNameRef<'a>) -> Self {
        value.0
    }
}
impl<'a> From<&'a OrderedGraphNameRef<'a>> for &'a GraphNameRef<'a> {
    fn from(value: &'a OrderedGraphNameRef<'a>) -> Self {
        &value.0
    }
}
impl<'a> TryFrom<TermRef<'a>> for OrderedGraphNameRef<'a> {
    type Error = RDFProofsError;

    fn try_from(value: TermRef<'a>) -> Result<Self, Self::Error> {
        match value {
            TermRef::NamedNode(n) => Ok(Self(n.into())),
            TermRef::BlankNode(n) => Ok(Self(n.into())),
            _ => Err(RDFProofsError::Other(
                "invalid graph name: graph name must not be literal or triple".to_string(),
            )),
        }
    }
}
impl std::fmt::Display for OrderedGraphNameRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// `oxrdf::triple::NamedOrBlankNode` with string-based ordering
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct OrderedNamedOrBlankNode(NamedOrBlankNode);
impl Ord for OrderedNamedOrBlankNode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_string().cmp(&other.0.to_string())
    }
}
impl PartialOrd for OrderedNamedOrBlankNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.to_string().partial_cmp(&other.0.to_string())
    }
}
impl From<NamedOrBlankNode> for OrderedNamedOrBlankNode {
    fn from(value: NamedOrBlankNode) -> Self {
        Self(value)
    }
}

/// `oxrdf::triple::NameeOrBlankNodeRef` with string-based ordering
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct OrderedNamedOrBlankNodeRef<'a>(NamedOrBlankNodeRef<'a>);
impl Ord for OrderedNamedOrBlankNodeRef<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_string().cmp(&other.0.to_string())
    }
}
impl PartialOrd for OrderedNamedOrBlankNodeRef<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.to_string().partial_cmp(&other.0.to_string())
    }
}
impl<'a> From<NamedOrBlankNodeRef<'a>> for OrderedNamedOrBlankNodeRef<'a> {
    fn from(value: NamedOrBlankNodeRef<'a>) -> Self {
        Self(value)
    }
}

pub type OrderedGraphViews<'a> = BTreeMap<OrderedGraphNameRef<'a>, GraphView<'a>>;

pub type OrderedVerifiableCredentialGraphViews<'a> =
    BTreeMap<OrderedGraphNameRef<'a>, VerifiableCredentialView<'a>>;
