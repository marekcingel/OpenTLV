// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
use opentlv::{
    Error, Format, ProgramOptions, QueryBinding, QueryProgram, QueryType, QueryValue, TreeReader,
    Visit,
};
const WIRE: &[u8] = &[0x70, 6, 0x5a, 1, 1, 0x50, 1, 2, 0x5a, 1, 3];

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
