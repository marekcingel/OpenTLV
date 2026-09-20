//! Length schemas and structural schemas for validating TLV data.
//!
//! Both schema types wrap the C library's tables. Validation runs entirely in
//! C; this module only builds the borrowed C tables from owned Rust values and
//! maps the outcome to Rust errors.

use std::error;
use std::fmt;
use std::ptr;

use opentlv_sys as sys;

use crate::emv::Context;
use crate::error::{Error, Result};
use crate::format::Format;
use crate::tag::Tag;

/// Length rule for one tag of a [`LengthSchema`].
///
/// Bounds are inclusive; equal bounds specify an exact length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LengthRule {
    /// Tag the rule describes.
    pub tag: Tag,
    /// Minimum permitted value length in bytes.
    pub min_length: usize,
    /// Maximum permitted value length in bytes; `usize::MAX` is unrestricted.
    pub max_length: usize,
}

impl LengthRule {
    /// Creates a rule permitting lengths from `min_length` to `max_length`.
    pub fn new(tag: Tag, min_length: usize, max_length: usize) -> LengthRule {
        LengthRule {
            tag,
            min_length,
            max_length,
        }
    }

    /// Creates a rule permitting exactly `length` bytes.
    pub fn exact(tag: Tag, length: usize) -> LengthRule {
        LengthRule::new(tag, length, length)
    }

    fn raw(&self) -> sys::tlv_schema_entry_t {
        sys::tlv_schema_entry_t {
            tag: self.tag.raw(),
            min_length: self.min_length,
            max_length: self.max_length,
            flags: 0,
        }
    }

    fn from_raw(raw: &sys::tlv_schema_entry_t) -> Result<LengthRule> {
        Ok(LengthRule {
            tag: Tag::from_raw(&raw.tag)?,
            min_length: raw.min_length,
            max_length: raw.max_length,
        })
    }
}

#[derive(Debug)]
enum Table {
    Owned(Vec<sys::tlv_schema_entry_t>),
    Static(&'static sys::tlv_schema_t),
}

/// A table of per-tag value-length rules.
///
/// Lookup and length checks are done by the C library. Use [`LengthSchema::new`]
/// for your own rules or [`LengthSchema::emv`] for the built-in EMV dictionary.
///
/// ```
/// use opentlv::{LengthRule, LengthSchema, Tag};
///
/// let tag = Tag::from_bytes(&[0x01]).unwrap();
/// let schema = LengthSchema::new([LengthRule::new(tag, 2, 4)]);
/// assert!(schema.validate_length(&tag, 3).is_ok());
/// assert!(schema.validate_length(&tag, 5).is_err());
/// ```
#[derive(Debug)]
pub struct LengthSchema {
    table: Table,
}

// SAFETY: an owned table is plain data; a static table points to an immutable
// static that the C library never writes.
unsafe impl Send for LengthSchema {}
unsafe impl Sync for LengthSchema {}

impl LengthSchema {
    /// Creates a schema from `rules`. Earlier rules win for a repeated tag.
    pub fn new(rules: impl IntoIterator<Item = LengthRule>) -> LengthSchema {
        LengthSchema {
            table: Table::Owned(rules.into_iter().map(|rule| rule.raw()).collect()),
        }
    }

    /// Returns the EMV dictionary length schema of the base context.
    pub fn emv() -> LengthSchema {
        LengthSchema::emv_for(Context::Base)
    }

    /// Returns the EMV dictionary length schema of `context`.
    pub fn emv_for(context: Context) -> LengthSchema {
        // SAFETY: every `Context` is a valid C context, so the call returns a
        // pointer to an immutable static table.
        let table = unsafe { sys::tlv_emv_schema_for(context.raw()).as_ref() }
            .expect("every EMV context has a schema");
        LengthSchema {
            table: Table::Static(table),
        }
    }

    fn with_raw<R>(&self, f: impl FnOnce(&sys::tlv_schema_t) -> R) -> R {
        match &self.table {
            Table::Owned(entries) => f(&sys::tlv_schema_t {
                entries: entries.as_ptr(),
                count: entries.len(),
            }),
            Table::Static(table) => f(table),
        }
    }

    /// Returns the number of rules.
    pub fn len(&self) -> usize {
        self.with_raw(|raw| raw.count)
    }

    /// Returns `true` if the schema has no rules.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn find_raw(&self, tag: &Tag) -> Option<sys::tlv_schema_entry_t> {
        let tag = tag.raw();
        self.with_raw(|schema| {
            // SAFETY: `schema` and `tag` are valid for the call; the returned
            // pointer, if any, points into the table and is copied out
            // before the table can change.
            unsafe { sys::tlv_schema_find(schema, &tag).as_ref().copied() }
        })
    }

    /// Returns the rule for `tag`, or `None` if the schema does not know it.
    pub fn find(&self, tag: &Tag) -> Option<LengthRule> {
        self.find_raw(tag)
            .and_then(|raw| LengthRule::from_raw(&raw).ok())
    }

    /// Checks that a value of `length` bytes is permitted for `tag`.
    ///
    /// # Errors
    ///
    /// [`Error::Schema`] if the schema has no rule for `tag`,
    /// [`Error::InvalidLength`] if the length is out of the rule's bounds.
    pub fn validate_length(&self, tag: &Tag, length: usize) -> Result<()> {
        let entry = self.find_raw(tag).ok_or(Error::Schema)?;
        // SAFETY: `entry` is a valid, initialized entry.
        Error::check(unsafe { sys::tlv_schema_validate_length(&entry, length) })
    }
}

/// Expected form of a value described by a [`StructureRule`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// The element may be primitive or constructed.
    #[default]
    Any,
    /// The element must be primitive.
    Primitive,
    /// The element must be constructed.
    Constructed,
}

impl Kind {
    fn raw(self) -> sys::tlv_schema_kind_t {
        match self {
            Kind::Any => sys::TLV_SCHEMA_ANY,
            Kind::Primitive => sys::TLV_SCHEMA_PRIMITIVE,
            Kind::Constructed => sys::TLV_SCHEMA_CONSTRUCTED,
        }
    }
}

/// Structural rule for one tag within a single parent.
///
/// A new rule is optional (`0..=usize::MAX` occurrences), accepts any length
/// and any [`Kind`], and leaves the children unrestricted. Refine it with the
/// builder methods.
///
/// ```
/// use opentlv::{Kind, StructureRule, Tag};
///
/// let rule = StructureRule::new(Tag::from_bytes(&[0x84]).unwrap())
///     .length(5, 16)
///     .required_once()
///     .kind(Kind::Primitive);
/// ```
#[derive(Debug)]
pub struct StructureRule {
    tag: Tag,
    min_length: usize,
    max_length: usize,
    min_occurs: usize,
    max_occurs: usize,
    kind: Kind,
    children: Option<StructureSchema>,
}

impl StructureRule {
    /// Creates an optional rule for `tag` with no other restriction.
    pub fn new(tag: Tag) -> StructureRule {
        StructureRule {
            tag,
            min_length: 0,
            max_length: usize::MAX,
            min_occurs: 0,
            max_occurs: usize::MAX,
            kind: Kind::Any,
            children: None,
        }
    }

    /// Restricts the value length to `min..=max` bytes.
    pub fn length(mut self, min: usize, max: usize) -> StructureRule {
        self.min_length = min;
        self.max_length = max;
        self
    }

    /// Restricts the number of occurrences within the parent to `min..=max`.
    pub fn occurs(mut self, min: usize, max: usize) -> StructureRule {
        self.min_occurs = min;
        self.max_occurs = max;
        self
    }

    /// Requires exactly one occurrence within the parent.
    pub fn required_once(self) -> StructureRule {
        self.occurs(1, 1)
    }

    /// Requires the value to be primitive or constructed.
    pub fn kind(mut self, kind: Kind) -> StructureRule {
        self.kind = kind;
        self
    }

    /// Validates the value's children against `schema`.
    ///
    /// The C library requires a constructed value for this, so the kind is set
    /// to [`Kind::Constructed`].
    pub fn children(mut self, schema: StructureSchema) -> StructureRule {
        self.kind = Kind::Constructed;
        self.children = Some(schema);
        self
    }
}

/// The C tables behind an owned [`StructureSchema`]. Boxed so that the
/// addresses stored in parent tables stay valid when the schema is moved.
struct Compiled {
    rules: Vec<sys::tlv_structure_rule_t>,
    // Kept alive because `rules` points to their C tables.
    _children: Vec<StructureSchema>,
    raw: sys::tlv_structure_schema_t,
}

enum Backing {
    Owned(Box<Compiled>),
    Static(&'static sys::tlv_structure_schema_t),
}

/// A structural schema: per-tag length, kind, occurrence and membership rules
/// for one parent scope, with optional nested schemas for children.
///
/// [`StructureSchema::validate`] runs the C library's validator. Use
/// [`StructureSchema::new`] for your own rules or [`StructureSchema::emv`] for
/// the built-in EMV schema.
///
/// ```
/// use opentlv::{Format, StructureRule, StructureSchema, Tag, ValidationLimits};
///
/// let tag = Tag::from_bytes(&[0x01]).unwrap();
/// let schema = StructureSchema::new([StructureRule::new(tag).required_once()], false);
/// let limits = ValidationLimits::default();
/// assert!(schema.validate(&[0x01, 0x00], Format::Default, &limits).is_ok());
/// assert!(schema.validate(&[], Format::Default, &limits).is_err());
/// ```
pub struct StructureSchema {
    backing: Backing,
}

// SAFETY: the tables are immutable after construction and only point to heap
// memory owned by the schema or to an immutable static.
unsafe impl Send for StructureSchema {}
unsafe impl Sync for StructureSchema {}

impl fmt::Debug for StructureSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructureSchema")
            .field("rules", &self.as_raw().count)
            .finish_non_exhaustive()
    }
}

impl StructureSchema {
    /// Creates a schema from `rules`. Tags must be unique; a duplicate tag is
    /// reported by [`StructureSchema::validate`] as [`Error::Schema`]. Unknown
    /// tags are rejected unless `allow_unknown` is `true`.
    pub fn new(
        rules: impl IntoIterator<Item = StructureRule>,
        allow_unknown: bool,
    ) -> StructureSchema {
        let mut raw_rules = Vec::new();
        let mut children = Vec::new();
        for rule in rules {
            let child_ptr = match rule.children {
                Some(child) => {
                    let ptr = child.as_raw() as *const sys::tlv_structure_schema_t;
                    children.push(child);
                    ptr
                }
                None => ptr::null(),
            };
            raw_rules.push(sys::tlv_structure_rule_t {
                entry: sys::tlv_schema_entry_t {
                    tag: rule.tag.raw(),
                    min_length: rule.min_length,
                    max_length: rule.max_length,
                    flags: 0,
                },
                min_occurs: rule.min_occurs,
                max_occurs: rule.max_occurs,
                kind: rule.kind.raw(),
                children: child_ptr,
            });
        }
        let mut compiled = Box::new(Compiled {
            raw: sys::tlv_structure_schema_t {
                rules: ptr::null(),
                count: raw_rules.len(),
                allow_unknown: allow_unknown as i32,
            },
            rules: raw_rules,
            _children: children,
        });
        // The vector is never resized again, so its buffer address is stable.
        compiled.raw.rules = compiled.rules.as_ptr();
        StructureSchema {
            backing: Backing::Owned(compiled),
        }
    }

    /// Returns the built-in structural schema of common EMV Book 3 top-level
    /// data objects (FCI, application template, GPO response format 2).
    ///
    /// Validate with [`Format::Ber`].
    pub fn emv() -> StructureSchema {
        // SAFETY: only the address of an immutable static is taken; it lives
        // for the whole program and is never written.
        let raw = unsafe { &*ptr::addr_of!(sys::tlv_emv_structure_schema) };
        StructureSchema {
            backing: Backing::Static(raw),
        }
    }

    fn as_raw(&self) -> &sys::tlv_structure_schema_t {
        match &self.backing {
            Backing::Owned(compiled) => &compiled.raw,
            Backing::Static(raw) => raw,
        }
    }

    /// Validates framing, nesting, lengths, occurrence counts and child
    /// membership of `data` against the schema.
    ///
    /// Values are never decoded. Which tags are constructed is decided by
    /// `format`: BER, CER and DER nest by their constructed bit, while
    /// [`Format::Default`] and [`Format::Fixed1Byte`] have no nesting, so every
    /// value is opaque.
    ///
    /// # Errors
    ///
    /// A [`SchemaError`] carrying the C library's error and the offset of the
    /// failure: [`Error::SchemaMissing`] for an absent required field,
    /// [`Error::Schema`] for other rule violations, [`Error::InvalidLength`]
    /// for a length failure, or a reader error such as [`Error::Limit`].
    pub fn validate(
        &self,
        data: &[u8],
        format: Format,
        limits: &ValidationLimits,
    ) -> std::result::Result<(), SchemaError> {
        let mut offset = 0usize;
        // SAFETY: `data` is a valid slice; the format and schema tables are
        // valid for the call and immutable; `offset` is a writable `usize`.
        let code = unsafe {
            sys::tlv_schema_validate(
                data.as_ptr(),
                data.len(),
                format.reader_raw(),
                format.is_constructed_raw(),
                self.as_raw(),
                limits.max_depth,
                limits.max_elements,
                &mut offset,
            )
        };
        match Error::from_code(code) {
            None => Ok(()),
            Some(error) => Err(SchemaError { error, offset }),
        }
    }
}

/// Resource limits for [`StructureSchema::validate`].
///
/// Both limits are inclusive and zero is a real limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidationLimits {
    /// Maximum nesting depth; the C library accepts at most 64.
    pub max_depth: usize,
    /// Maximum total number of elements.
    pub max_elements: usize,
}

impl Default for ValidationLimits {
    /// A depth of 32 and 100 000 elements, the defaults of the DER and CER
    /// profiles.
    fn default() -> ValidationLimits {
        ValidationLimits {
            max_depth: 32,
            max_elements: 100_000,
        }
    }
}

/// A failed [`StructureSchema::validate`]: the error and where it happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaError {
    /// The error reported by the C library.
    pub error: Error,
    /// Offset of the failure in the input. For [`Error::SchemaMissing`] this
    /// is the end of the parent's value, not an element.
    pub offset: usize,
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at offset {}", self.error, self.offset)
    }
}

impl error::Error for SchemaError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<SchemaError> for Error {
    fn from(err: SchemaError) -> Error {
        err.error
    }
}
