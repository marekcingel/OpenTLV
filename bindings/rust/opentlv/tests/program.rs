// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
use opentlv::{
    Error, Format, ProgramOptions, QueryBinding, QueryCodecError, QueryConversion, QueryDecoded,
    QueryProgram, QueryProvider, QueryType, QueryValue, TreeReader, Visit,
};
#[test]
fn custom_providers_keep_lifetimes_and_validate_image_requirements() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = calls.clone();
    let provider = QueryProvider::new(QueryConversion::Num, 101, 0, move |value, metadata| {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(metadata.unwrap().offset, 0);
        Ok(QueryDecoded::Integer(i64::from(value[0]) * 10))
    });
    let mut options = ProgramOptions::default();
    options.providers.push(provider);
    let program = QueryProgram::compile("num(//5A)", &options).unwrap();
    assert!(QueryProgram::load(program.image(), &ProgramOptions::default()).is_err());
    let loaded = QueryProgram::load(program.image(), &options).unwrap();
    drop(options);
    drop(program);
    let mut execution = loaded.execution(4, 20, 100000, true).unwrap();
    drop(loaded);
    let input = &[0x5a, 1, 3];
    let mut reader = TreeReader::new(input, Format::Ber, 4, 4, 20, true).unwrap();
    execution.visit(&mut reader, |_| Visit::Continue).unwrap();
    assert_eq!(execution.result().unwrap(), QueryValue::Integer(30));
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    drop(execution);
    assert_eq!(std::sync::Arc::strong_count(&calls), 1);
}

#[test]
fn provider_text_capacity_original_errors_and_panics_are_contained() {
    for (capacity, expected) in [(3, None), (2, Some(2))] {
        let mut options = ProgramOptions::default();
        options.providers.push(QueryProvider::new(
            QueryConversion::Text,
            102,
            capacity,
            |_, _| Ok(QueryDecoded::String("a\0b".into())),
        ));
        let program = QueryProgram::compile("text(//5A)", &options).unwrap();
        let mut execution = program.execution(4, 20, 100000, true).unwrap();
        let mut reader = TreeReader::new(&[0x5a, 0], Format::Ber, 4, 4, 20, true).unwrap();
        let result = execution.visit(&mut reader, |_| Visit::Continue);
        if let Some(codec) = expected {
            assert_eq!(result.unwrap_err().codec, codec);
        } else {
            result.unwrap();
            assert_eq!(execution.result().unwrap(), QueryValue::String("a\0b"));
        }
    }
    for panic in [false, true] {
        let mut options = ProgramOptions::default();
        options.providers.push(QueryProvider::new(
            QueryConversion::Num,
            103,
            0,
            move |_, _| {
                if panic {
                    panic!("provider panic");
                }
                Err(QueryCodecError::Unsupported)
            },
        ));
        let program = QueryProgram::compile("num(//5A)", &options).unwrap();
        let mut execution = program.execution(4, 20, 100000, true).unwrap();
        let mut reader = TreeReader::new(&[0x5a, 0], Format::Ber, 4, 4, 20, true).unwrap();
        assert_eq!(
            execution
                .visit(&mut reader, |_| Visit::Continue)
                .unwrap_err()
                .codec,
            if panic { 3 } else { 4 }
        );
        execution.reset().unwrap();
    }
}
const WIRE: &[u8] = &[0x70, 6, 0x5a, 1, 1, 0x50, 1, 2, 0x5a, 1, 3];
#[test]
fn source_less_feeds_publish_retained_results_and_original_ordinals() {
    use opentlv::QueryEvent;
    let program = QueryProgram::compile("(//5A)[last()]", &ProgramOptions::default()).unwrap();
    let mut execution = program.execution(4, 20, 100000, true).unwrap();
    assert!(execution.next_result().is_err());
    for (offset, value) in [(7, &[1][..]), (11, &[2][..])] {
        assert!(execution
            .feed_event(QueryEvent::Element {
                tag: &[0x5a],
                value,
                depth: 0,
                offset,
            })
            .unwrap()
            .is_none());
    }
    execution.finish().unwrap();
    let (matched, ordinal) = execution.next_result_with_ordinal().unwrap().unwrap();
    assert_eq!(ordinal, 1);
    assert_eq!(matched.element.value(), &[2]);
    assert_eq!(matched.offset, 11);
    assert!(execution.next_result().unwrap().is_none());
    execution.reset().unwrap();
    execution
        .feed_event(QueryEvent::Element {
            tag: &[0x5a],
            value: &[3],
            depth: 0,
            offset: 0,
        })
        .unwrap();
    execution.finish().unwrap();
    assert_eq!(
        execution.next_result().unwrap().unwrap().element.value(),
        &[3]
    );

    let offset_query =
        QueryProgram::compile("//5A[@offset=0]", &ProgramOptions::default()).unwrap();
    let mut execution = offset_query.execution(4, 20, 100000, true).unwrap();
    execution
        .feed_event(QueryEvent::Element {
            tag: &[0x5a],
            value: &[],
            depth: 0,
            offset: 0,
        })
        .unwrap();
    assert_eq!(execution.finish().unwrap_err().error, Error::InvalidValue);
}
#[cfg(feature = "document")]
#[test]
fn completed_selection_edits_are_bounded_and_resolve_ancestors() {
    use opentlv::{Document, QueryEdit, QueryEditOptions};
    let wire = &[0x70, 6, 0x5a, 1, 1, 0x5a, 1, 2, 0x5a, 1, 3];
    let mut document = Document::parse(wire, Format::Ber, 64, 1024).unwrap();
    let program = QueryProgram::compile("//5A", &ProgramOptions::default()).unwrap();
    let mut options = QueryEditOptions {
        target_capacity: Some(2),
        ..QueryEditOptions::default()
    };
    let failure = program
        .edit_document(&mut document, QueryEdit::Replace(&[9]), options)
        .unwrap_err();
    assert_eq!(failure.applied, 0);
    assert_eq!(failure.failure.error, Error::BufferTooShort);
    assert_eq!(document.encode().unwrap(), wire);
    options.target_capacity = Some(3);
    assert_eq!(
        program
            .edit_document(&mut document, QueryEdit::Replace(&[9]), options)
            .unwrap(),
        3
    );
    assert_eq!(
        document.encode().unwrap(),
        &[0x70, 6, 0x5a, 1, 9, 0x5a, 1, 9, 0x5a, 1, 9]
    );
    assert_eq!(
        program
            .edit_document(
                &mut document,
                QueryEdit::InsertAfter {
                    tag: &[0x5b],
                    value: &[4]
                },
                options
            )
            .unwrap(),
        3
    );
    let ancestors = QueryProgram::compile("//70 | //5A", &ProgramOptions::default()).unwrap();
    assert_eq!(
        ancestors
            .edit_document(&mut document, QueryEdit::Remove, options)
            .unwrap_err()
            .applied,
        0
    );
    options.target_capacity = None;
    assert_eq!(
        ancestors
            .edit_document(&mut document, QueryEdit::Remove, options)
            .unwrap(),
        2
    );
    assert_eq!(document.encode().unwrap(), &[0x5b, 1, 4]);
}

#[test]
fn typed_scalar_images_and_independent_executions() {
    let mut options = ProgramOptions::default();
    options
        .variables
        .insert("minimum".into(), QueryType::Integer);
    let program = QueryProgram::compile("count(//5A[@len >= $minimum])", &options).unwrap();
    let loaded = QueryProgram::load(program.image(), &options).unwrap();
    assert_eq!(loaded.format().unwrap(), program.format().unwrap());
    assert!(!loaded.explain().unwrap().is_empty());
    for minimum in [1, 2] {
        let mut execution = loaded.execution(4, 20, 100000, true).unwrap();
        execution
            .bind("minimum", QueryBinding::Integer(minimum))
            .unwrap();
        let mut reader = TreeReader::new(WIRE, Format::Ber, 4, 4, 20, true).unwrap();
        execution.visit(&mut reader, |_| Visit::Continue).unwrap();
        assert_eq!(
            execution.result().unwrap(),
            QueryValue::Integer(if minimum == 1 { 2 } else { 0 })
        );
        assert_eq!(execution.info().unwrap().full_validation, 1);
    }
    assert!(QueryProgram::load(&program.image()[..program.image().len() - 1], &options).is_err());
}

#[test]
fn stopped_incremental_retention_and_borrowed_binding() {
    let program = QueryProgram::compile("(//5A)[last()]", &ProgramOptions::default()).unwrap();
    let mut execution = program.execution(4, 20, 100000, true).unwrap();
    let mut reader = TreeReader::new(&WIRE[..8], Format::Ber, 4, 4, 20, false).unwrap();
    assert_eq!(
        execution
            .visit(&mut reader, |_| Visit::Continue)
            .unwrap_err()
            .error,
        Error::NeedMoreData
    );
    reader.set_input(WIRE, 0, true).unwrap();
    assert_eq!(execution.next(&mut reader).unwrap().unwrap().offset, 8);
    assert!(execution.next(&mut reader).unwrap().is_none());
    execution.reset().unwrap();
    let mut options = ProgramOptions::default();
    options.variables.insert("needle".into(), QueryType::Bytes);
    let program = QueryProgram::compile("//5A[contains(value(), $needle)]", &options).unwrap();
    let mut execution = program.execution(4, 20, 100000, true).unwrap();
    execution.bind("needle", QueryBinding::Bytes(&[3])).unwrap();
    let mut reader = TreeReader::new(WIRE, Format::Ber, 4, 4, 20, true).unwrap();
    assert_eq!(execution.next(&mut reader).unwrap().unwrap().offset, 8);
}

#[test]
fn explicit_workspace_early_coverage_and_panic_does_not_cross_c() {
    let program = QueryProgram::compile("//5A", &ProgramOptions::default()).unwrap();
    let mut short = [0u8; 1];
    assert!(program
        .execution_external(&mut short, 4, 20, 100000, false)
        .is_err());
    let mut execution = program.execution(4, 20, 100000, false).unwrap();
    let mut reader = TreeReader::new(&[0x5a, 0, 0x50, 2], Format::Ber, 4, 4, 20, true).unwrap();
    assert!(execution.exists(&mut reader, true).unwrap());
    assert_eq!(execution.info().unwrap().full_validation, 0);
    assert_eq!(execution.exists(&mut reader, false).unwrap_err().kind, 7);
    execution.reset().unwrap();
    let mut reader = TreeReader::new(WIRE, Format::Ber, 4, 4, 20, true).unwrap();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execution
            .visit(&mut reader, |_| panic!("visitor panic"))
            .unwrap();
    }));
    assert!(panic.is_err());
    assert_eq!(execution.info().unwrap().invalid, 1);
}

#[cfg(feature = "document")]
#[test]
fn document_reverse_axes_context_and_scalar_snapshot() {
    use opentlv::Document;
    let document = Document::parse(WIRE, Format::Ber, 4, 20).unwrap();
    let program =
        QueryProgram::compile("//50[preceding-sibling::5A]", &ProgramOptions::default()).unwrap();
    let mut execution = program.execution(4, 20, 100000, true).unwrap();
    execution.evaluate_document(&document, None, None).unwrap();
    assert_eq!(
        execution.next_document().unwrap().unwrap().tag().as_bytes(),
        &[0x50]
    );
    assert!(execution.next_document().unwrap().is_none());
    let program = QueryProgram::compile("count(//5A)", &ProgramOptions::default()).unwrap();
    let mut execution = program.execution(4, 20, 100000, true).unwrap();
    execution.evaluate_document(&document, None, None).unwrap();
    assert_eq!(execution.result().unwrap(), QueryValue::Integer(2));
    execution.reset().unwrap();
    let program = QueryProgram::compile("value((//5A)[1])", &ProgramOptions::default()).unwrap();
    let mut execution = program.execution(4, 20, 100000, true).unwrap();
    execution.evaluate_document(&document, None, None).unwrap();
    assert_eq!(execution.result().unwrap(), QueryValue::Bytes(&[1]));
}
