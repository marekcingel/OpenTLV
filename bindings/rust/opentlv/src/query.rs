//! Canonical C Query parsing and resumable matching.
use crate::{Element, Error, Result, Tag, TreeReader, Visit};
use opentlv_native as native;
use std::{ffi::CString, mem::MaybeUninit, ptr};

/// A parsed path owning its tags, independent of the original query string.
#[derive(Clone, Debug)]
pub struct Query {
    pub(crate) raw: native::tlv_query_t,
}

/// Query parse failure with the original text offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryError {
    /// Original C result code.
    pub error: Error,
    /// Byte offset in the query text.
    pub offset: usize,
}
impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at query byte {}", self.error, self.offset)
    }
}
impl std::error::Error for QueryError {}

impl Query {
    /// Parse using C's path grammar; embedded NUL is rejected, never truncated.
    pub fn parse(text: &str) -> std::result::Result<Self, QueryError> {
        let text = CString::new(text).map_err(|error| QueryError {
            error: Error::InvalidArg,
            offset: error.nul_position(),
        })?;
        let mut raw = MaybeUninit::uninit();
        let mut offset = 0;
        // SAFETY: NUL-terminated input and writable outputs.
        let code = unsafe { native::tlv_query_parse(text.as_ptr(), raw.as_mut_ptr(), &mut offset) };
        Error::check(code).map_err(|error| QueryError { error, offset })?;
        // SAFETY: successful C parse initialized all storage.
        Ok(Self {
            raw: unsafe { raw.assume_init() },
        })
    }
    /// Number of path components.
    pub fn len(&self) -> usize {
        self.raw.count
    }
    /// A parsed query is nonempty.
    pub fn is_empty(&self) -> bool {
        self.raw.count == 0
    }
    /// Returns an owned tag at a path step, or None out of bounds.
    pub fn step(&self, index: usize) -> Option<Tag> {
        if index >= self.len() {
            return None;
        }
        // SAFETY: native step borrows self; Tag copies it before returning.
        unsafe { Tag::from_raw(&native::tlv_query_step(&self.raw, index)).ok() }
    }
    /// Start independent matching with an owned, stable copy of this query.
    pub fn matcher(&self) -> Result<QueryMatcher> {
        QueryMatcher::new(self)
    }
}

/// Resumable matcher; owns stable query storage and delegates all matching to C.
pub struct QueryMatcher {
    raw: native::tlv_query_matcher_t,
    _query: Box<native::tlv_query_t>,
}
impl QueryMatcher {
    /// Create a matcher for the start of one preorder traversal.
    pub fn new(query: &Query) -> Result<Self> {
        let owned = Box::new(query.raw);
        let mut raw = MaybeUninit::uninit();
        // SAFETY: stable owned heap query and writable output.
        Error::check(unsafe { native::tlv_query_matcher_init(raw.as_mut_ptr(), &*owned) })?;
        // SAFETY: successful initialization.
        Ok(Self {
            raw: unsafe { raw.assume_init() },
            _query: owned,
        })
    }
    /// Feed every preorder item to the C matcher, including nonmatching ancestors.
    pub fn matches(&mut self, tag: &Tag, depth: usize) -> bool {
        // SAFETY: initialized matcher and valid borrowed tag for the synchronous call.
        unsafe { native::tlv_query_matcher_visit(&mut self.raw, &tag.raw(), depth) != 0 }
    }
    /// Visit matches from a Tree Reader, retaining state across STOP and input replacement.
    /// Do not interleave unmatched pulls. Panics resume after C returns.
    pub fn visit<'a>(
        &mut self,
        reader: &mut TreeReader<'a>,
        callback: impl FnMut(Element<'a>, usize, usize) -> Visit,
    ) -> Result<()> {
        // SAFETY: exclusive reader/matcher, owned frames/query and live 'a input.
        reader.current = None;
        let (result, diagnostic) = unsafe {
            crate::visitor::run(ptr::null_mut(), &mut reader.raw, callback, &mut self.raw)
        };
        reader.diagnostic = diagnostic;
        result
    }
}
