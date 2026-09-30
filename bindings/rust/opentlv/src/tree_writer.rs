//! Bounded tree output through the canonical C Tree Writer.
use crate::{Element, Error, FixedFormat, Format, Result, Tag};
use opentlv_native as native;
use std::{
    any::Any,
    ffi::c_void,
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
};
use std::{ffi::CStr, marker::PhantomData, mem::MaybeUninit, ptr, slice};

/// One semantic preorder record supplied to exact tree measurement.
pub struct TreeWriteItem<'a> {
    /// Semantic content; constructed Values are ignored by C measurement.
    pub element: Element<'a>,
    /// Root-relative depth, starting at zero.
    pub depth: usize,
    /// Whether this record opens a parent, including an empty parent.
    pub constructed: bool,
}

struct MeasureSource<'a, I> {
    items: I,
    retained: Vec<TreeWriteItem<'a>>,
    error: Option<Error>,
    panic: Option<Box<dyn Any + Send>>,
}

unsafe extern "C" fn measure_next<'a, I: Iterator<Item = Result<TreeWriteItem<'a>>>>(
    context: *mut c_void,
    element: *mut native::tlv_element_t,
    depth: *mut usize,
    constructed: *mut i32,
) -> i32 {
    // SAFETY: measure supplies this exact live source and C supplies writable outputs.
    let source = unsafe { &mut *context.cast::<MeasureSource<'a, I>>() };
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let Some(item) = source.items.next() else {
            return Ok(native::TLV_ERR_END_OF_BUFFER);
        };
        let item = item?;
        source
            .retained
            .try_reserve(1)
            .map_err(|_| Error::OutOfMemory)?;
        source.retained.push(item);
        let item = source.retained.last().unwrap();
        // SAFETY: retained Tags own stable heap bytes, even if the record Vec moves.
        // Primitive Values borrow immutable input for the duration of measurement.
        unsafe {
            *element = native::tlv_element_t {
                tag: item.element.tag().raw(),
                value: native::tlv_value_t {
                    data: item.element.value().as_ptr(),
                    size: item.element.value().len() as u64,
                },
            };
            *depth = item.depth;
            *constructed = i32::from(item.constructed);
        }
        Ok(native::TLV_OK)
    }));
    match outcome {
        Ok(Ok(code)) => code,
        Ok(Err(error)) => {
            source.error = Some(error);
            native::TLV_ERR_INVALID_ARG
        }
        Err(panic) => {
            source.panic = Some(panic);
            native::TLV_ERR_INVALID_ARG
        }
    }
}

/// Owned details for a failed Writer operation.
#[derive(Clone, Debug)]
pub struct WriterDiagnostic {
    /// Absolute failing output offset when available.
    pub offset: Option<usize>,
    /// C Writer operation code.
    pub operation: i32,
    /// Tag being encoded, copied before temporary input expires.
    pub tag: Option<Tag>,
    /// Native Value size, when representable.
    pub length: Option<usize>,
    /// Total encoded capacity required.
    pub required: Option<usize>,
    /// Available output bytes.
    pub available: Option<usize>,
    /// Expected description reported by the Format.
    pub expected: Option<String>,
    /// Actual description reported by the Format.
    pub actual: Option<String>,
}

impl WriterDiagnostic {
    /// Copy native details while their borrowed fields remain alive.
    pub(crate) unsafe fn from_raw(diag: &native::tlv_writer_diagnostic_t) -> Self {
        let text = |p: *const std::os::raw::c_char| {
            if p.is_null() {
                None
            } else {
                // SAFETY: C descriptions are live NUL-terminated strings.
                Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
            }
        };
        Self {
            offset: (diag.diagnostic.has_offset != 0).then_some(diag.diagnostic.offset),
            operation: diag.operation,
            // SAFETY: diagnostic tag is copied while its operation inputs remain live.
            tag: if diag.has_tag != 0 {
                unsafe { Tag::from_raw(&diag.tag) }.ok()
            } else {
                None
            },
            length: (diag.has_length != 0).then_some(diag.length),
            required: (diag.has_required != 0).then_some(diag.required),
            available: (diag.has_available != 0).then_some(diag.available),
            expected: text(diag.diagnostic.expected),
            actual: text(diag.diagnostic.actual),
        }
    }
}

/// Tree Writer borrowing output and owning bounded frames, scratch and open tags.
/// Successful begin retains an owned tag until end. Output never grows implicitly.
pub struct TreeWriter<'a> {
    raw: native::tlv_tree_writer_t,
    output: PhantomData<&'a mut [u8]>,
    _frames: Box<[native::tlv_tree_writer_frame_t]>,
    _scratch: Box<[u8]>,
    tags: Vec<Tag>,
    diagnostic: Option<WriterDiagnostic>,
    required_workspace: (usize, usize),
}

impl<'a> TreeWriter<'a> {
    /// Initialize bounded output with explicit frame, scratch, depth and item limits.
    pub fn new(
        output: &'a mut [u8],
        format: Format,
        frame_capacity: usize,
        scratch_capacity: usize,
        max_depth: usize,
        max_elements: usize,
    ) -> Result<Self> {
        // SAFETY: static builtin descriptor.
        unsafe {
            Self::init(
                output,
                format.raw(),
                frame_capacity,
                scratch_capacity,
                max_depth,
                max_elements,
            )
        }
    }
    /// Initialize while borrowing a Fixed descriptor and configuration for `'a`.
    pub fn with_fixed_format(
        output: &'a mut [u8],
        format: &'a FixedFormat<'_>,
        frame_capacity: usize,
        scratch_capacity: usize,
        max_depth: usize,
        max_elements: usize,
    ) -> Result<Self> {
        // SAFETY: signature keeps the descriptor/context alive with the output borrow.
        unsafe {
            Self::init(
                output,
                format.raw(),
                frame_capacity,
                scratch_capacity,
                max_depth,
                max_elements,
            )
        }
    }
    unsafe fn init(
        output: &'a mut [u8],
        format: *const native::tlv_format_t,
        capacity: usize,
        scratch_capacity: usize,
        max_depth: usize,
        max_elements: usize,
    ) -> Result<Self> {
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(capacity)
            .map_err(|_| Error::OutOfMemory)?;
        frames.resize(
            capacity,
            native::tlv_tree_writer_frame_t {
                tag: native::tlv_tag_t {
                    data: ptr::null(),
                    size: 0,
                },
                start: 0,
            },
        );
        let mut frames = frames.into_boxed_slice();
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(scratch_capacity)
            .map_err(|_| Error::OutOfMemory)?;
        scratch.resize(scratch_capacity, 0);
        let mut scratch = scratch.into_boxed_slice();
        let mut tags = Vec::new();
        tags.try_reserve_exact(capacity)
            .map_err(|_| Error::OutOfMemory)?;
        let mut raw = MaybeUninit::uninit();
        // SAFETY: all storage is disjoint and stable; output is exclusively borrowed.
        Error::check(unsafe {
            native::tlv_tree_writer_init(
                raw.as_mut_ptr(),
                output.as_mut_ptr(),
                output.len(),
                format,
                frames.as_mut_ptr(),
                capacity,
                scratch.as_mut_ptr(),
                scratch_capacity,
                max_depth,
                max_elements,
            )
        })?;
        Ok(Self {
            // SAFETY: initialization succeeded.
            raw: unsafe { raw.assume_init() },
            output: PhantomData,
            _frames: frames,
            _scratch: scratch,
            tags,
            diagnostic: None,
            required_workspace: (0, 0),
        })
    }
    fn operation(
        &mut self,
        call: impl FnOnce(*mut native::tlv_tree_writer_t, *mut native::tlv_writer_diagnostic_t) -> i32,
    ) -> Result<()> {
        let mut diag = MaybeUninit::uninit();
        // SAFETY: initializes every field before use by the synchronous operation.
        unsafe { native::tlv_writer_diagnostic_init(diag.as_mut_ptr()) };
        let code = call(&mut self.raw, diag.as_mut_ptr());
        // SAFETY: diagnostic always initialized; caller retains any input tag/value until return.
        let diag = unsafe { diag.assume_init() };
        // SAFETY: input and retained open tags are still alive.
        self.diagnostic =
            (code != native::TLV_OK).then(|| unsafe { WriterDiagnostic::from_raw(&diag) });
        Error::check(code)
    }
    /// Open a constructed item, retaining an owned copy of its tag until successful end.
    pub fn begin(&mut self, tag: &Tag) -> Result<()> {
        let owned = tag.clone();
        // SAFETY: owned tag stays alive through the call and is retained on success.
        self.operation(|writer, diag| unsafe {
            native::tlv_tree_writer_begin_diag(writer, owned.raw(), diag)
        })?;
        self.tags.push(owned);
        Ok(())
    }
    /// Write a primitive or already encoded subtree through the C element writer.
    pub fn write(&mut self, element: &Element<'_>) -> Result<()> {
        let raw = native::tlv_element_t {
            tag: element.tag().raw(),
            value: native::tlv_value_t {
                data: element.value().as_ptr(),
                size: element.value().len() as u64,
            },
        };
        // SAFETY: immutable input cannot alias the exclusively borrowed output buffer.
        self.operation(|writer, diag| unsafe {
            native::tlv_tree_writer_write_element_diag(writer, &raw, diag)
        })
    }
    /// Close the innermost parent; failure retains state and open tag for retry.
    pub fn end(&mut self) -> Result<()> {
        // SAFETY: cursor storage and open tags remain alive.
        self.operation(|writer, diag| unsafe { native::tlv_tree_writer_end_diag(writer, diag) })?;
        self.tags.pop();
        Ok(())
    }
    /// Finalized prefix only; unfinished roots remain provisional.
    pub fn written(&self) -> &[u8] {
        // SAFETY: initialized cursor reports a prefix within the borrowed output.
        let size = unsafe { native::tlv_tree_writer_size(&self.raw) };
        // SAFETY: output was an exclusive non-null Rust slice and remains borrowed by self.
        unsafe { slice::from_raw_parts(self.raw.output.buf, size) }
    }
    /// Require all parents closed and return finalized output without sealing the cursor.
    pub fn finish(&self) -> Result<&[u8]> {
        // SAFETY: initialized cursor, immutable check.
        Error::check(unsafe { native::tlv_tree_writer_finish(&self.raw) })?;
        Ok(self.written())
    }
    /// Structured detail for the most recent failed begin/write/end operation.
    pub fn diagnostic(&self) -> Option<&WriterDiagnostic> {
        self.diagnostic.as_ref()
    }

    /// Consume a preorder source through C and return the exact staged encoding.
    ///
    /// Requires an unused writer. The returned slice length is the measurement;
    /// `written()` remains the sequential finalized prefix, which is still empty.
    /// Source items and their Tags are retained until C returns. Source errors and
    /// panics propagate after the C boundary. Retry needs a fresh source.
    pub fn measure<'s, I>(&mut self, items: I) -> Result<&[u8]>
    where
        I: IntoIterator<Item = Result<TreeWriteItem<'s>>>,
    {
        self.required_workspace = (0, 0);
        self.diagnostic = None;
        if self.raw.count != 0 {
            return Err(Error::InvalidArg);
        }
        let mut source = MeasureSource {
            items: items.into_iter(),
            retained: Vec::new(),
            error: None,
            panic: None,
        };
        let mut workspace = native::tlv_tree_writer_workspace_t {
            frames: self.raw.frames,
            frame_capacity: self.raw.capacity,
            data: self.raw.output.buf,
            data_capacity: self.raw.output.capacity,
            scratch: self.raw.scratch,
            scratch_capacity: self.raw.scratch_capacity,
            required_data: 0,
            required_scratch: 0,
        };
        let mut size = 0;
        let mut diag = MaybeUninit::uninit();
        // SAFETY: exclusive self borrow protects disjoint storage. Format and
        // source bytes remain live through the synchronous call and diagnostic copy.
        let code = unsafe {
            native::tlv_writer_diagnostic_init(diag.as_mut_ptr());
            native::tlv_tree_writer_measure(
                self.raw.output.format,
                Some(measure_next::<I::IntoIter>),
                (&mut source as *mut MeasureSource<'s, I::IntoIter>).cast(),
                &mut workspace,
                self.raw.max_depth,
                self.raw.max_elements,
                &mut size,
                diag.as_mut_ptr(),
            )
        };
        self.required_workspace = (workspace.required_data, workspace.required_scratch);
        // SAFETY: initialized diagnostic; source records still retain every borrowed Tag.
        let diag = unsafe { diag.assume_init() };
        self.diagnostic =
            (code != native::TLV_OK).then(|| unsafe { WriterDiagnostic::from_raw(&diag) });
        if let Some(panic) = source.panic {
            resume_unwind(panic);
        }
        if let Some(error) = source.error {
            return Err(error);
        }
        Error::check(code)?;
        // SAFETY: C returned a valid staged prefix within exclusive output storage.
        Ok(unsafe { slice::from_raw_parts(self.raw.output.buf, size) })
    }

    /// Last measurement's required (output, scratch) capacities on exhaustion.
    /// These are discovered lower bounds; zero means no such storage shortage.
    pub fn required_workspace(&self) -> (usize, usize) {
        self.required_workspace
    }
}
