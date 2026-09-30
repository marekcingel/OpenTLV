use opentlv::{Error, Format, Reader, TreeReader};
use opentlv::{Query, Visit};

#[test]
fn incremental_reader_retains_views_and_absolute_diagnostics() {
    let data = [4, 1, 42, 4, 1, 43];
    let mut reader = Reader::incremental(&data[..2], Format::Ber);
    assert_eq!(reader.next().unwrap().unwrap_err(), Error::NeedMoreData);
    assert!(!reader.is_at_end());
    reader.set_input(&data[..4], 0, false).unwrap();
    let first = reader.read_source().unwrap();
    assert_eq!(first.element.value().as_ptr(), data[2..].as_ptr());
    reader.set_input(&data[3..4], 3, false).unwrap();
    assert_eq!(reader.offset(), 3);
    assert_eq!(reader.next().unwrap().unwrap_err(), Error::NeedMoreData);
    assert_eq!(reader.diagnostic().unwrap().offset, Some(4));
    reader.set_input(&data[3..], 0, true).unwrap();
    assert_eq!(reader.next().unwrap().unwrap().value(), &[43]);
    assert!(reader.next().is_none());
    assert_eq!(first.encoded(), &data[..3]);
    assert_eq!(first.layout().value, Some(2..3));
}

#[test]
fn tree_complete_parent_then_skip_after_limit() {
    let data = [0x30, 2, 4, 0, 4, 0];
    let mut tree = TreeReader::new(&data[..3], Format::Ber, 0, 0, 2, false).unwrap();
    assert_eq!(tree.read().unwrap_err(), Error::NeedMoreData);
    assert_eq!(tree.offset(), 0);
    tree.set_input(&data, 0, true).unwrap();
    let parent = tree.read().unwrap();
    assert!(parent.constructed);
    assert_eq!(tree.read().unwrap_err(), Error::Limit);
    tree.skip_subtree().unwrap();
    assert_eq!(tree.read().unwrap().offset, 4);
    assert!(tree.is_at_end());
    assert_eq!(parent.decoded.encoded(), &data[..4]);
}

#[test]
fn preorder_and_resumption_after_discard() {
    let data = [0x30, 4, 4, 0, 4, 0, 4, 1, 42];
    let mut tree = TreeReader::new(&data[..6], Format::Ber, 1, 1, 4, false).unwrap();
    for (offset, depth) in [(0, 0), (2, 1), (4, 1)] {
        let item = tree.next().unwrap().unwrap();
        assert_eq!((item.offset, item.depth), (offset, depth));
    }
    assert_eq!(tree.read().unwrap_err(), Error::NeedMoreData);
    tree.set_input(&data[6..], 6, true).unwrap();
    assert_eq!(tree.read().unwrap().offset, 6);
    assert!(tree.next().is_none());
}

#[test]
fn malformed_child_is_terminal_input_error_not_need_more() {
    let data = [0x30, 2, 4, 1];
    let mut tree = TreeReader::new(&data, Format::Ber, 1, 1, 4, false).unwrap();
    tree.read().unwrap();
    assert_eq!(tree.read().unwrap_err(), Error::BufferTooShort);
    assert_eq!(tree.diagnostic().unwrap().offset, Some(4));
    assert_eq!(tree.offset(), 2);
}

#[test]
fn replacing_undiscarded_bytes_is_rejected_without_state_change() {
    let data = [4, 0];
    let other = [5, 0];
    let mut reader = Reader::incremental(&data, Format::Ber);
    assert_eq!(reader.set_input(&other, 0, true), Err(Error::InvalidArg));
    assert_eq!(reader.offset(), 0);
    assert_eq!(reader.read_source().unwrap().encoded(), &data);
}

#[test]
fn visitors_stop_resume_and_panics_do_not_cross_c() {
    let data = [4, 0, 5, 0];
    let mut reader = Reader::incremental(&data, Format::Ber);
    reader.visit(|_| Visit::Stop).unwrap();
    assert_eq!(reader.offset(), 2);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = reader.visit(|_| panic!("callback panic"));
    }));
    assert!(panic.is_err());
    assert_eq!(reader.offset(), 4);
    assert_eq!(reader.visit(|_| Visit::Continue), Err(Error::NeedMoreData));
    reader.set_input(&[], 4, true).unwrap();
    reader.visit(|_| Visit::Error).unwrap(); // final exhaustion invokes no callback
}

#[test]
fn query_matching_is_resumable_and_owns_its_query() {
    let data = [0x30, 4, 4, 0, 4, 0, 0x30, 2, 4, 0];
    let mut tree = TreeReader::new(&data[..6], Format::Ber, 1, 1, 5, false).unwrap();
    let mut matcher = Query::parse("30/04").unwrap().matcher().unwrap();
    let mut offsets = Vec::new();
    matcher
        .visit(&mut tree, |_, _, offset| {
            offsets.push(offset);
            Visit::Stop
        })
        .unwrap();
    assert_eq!(
        matcher.visit(&mut tree, |_, _, offset| {
            offsets.push(offset);
            Visit::Continue
        }),
        Err(Error::NeedMoreData)
    );
    tree.set_input(&data[6..], 6, true).unwrap();
    matcher
        .visit(&mut tree, |_, _, offset| {
            offsets.push(offset);
            Visit::Continue
        })
        .unwrap();
    assert_eq!(offsets, [2, 4, 8]);
    assert_eq!(Query::parse("30/").unwrap_err().offset, 3);
}

#[test]
fn tree_visitor_stop_allows_subtree_skip() {
    let data = [0x30, 2, 4, 0, 4, 1, 42];
    let mut tree = TreeReader::new(&data, Format::Ber, 1, 1, 3, true).unwrap();
    tree.visit(|_, depth, offset| {
        assert_eq!((depth, offset), (0, 0));
        Visit::Stop
    })
    .unwrap();
    tree.skip_subtree().unwrap();
    assert_eq!(tree.read().unwrap().decoded.element.value(), &[42]);
    assert!(tree.is_at_end());
}
