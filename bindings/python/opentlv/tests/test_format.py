from opentlv import Format


def test_values_match_what_the_native_module_expects():
    # opentlv_native's format IDs are fixed; see module.c's reader_format_for
    # / writer_format_for.
    assert Format.DEFAULT == 0
    assert Format.BER == 1
    assert Format.CER == 2
    assert Format.DER == 3
    assert Format.FIXED_1BYTE == 4
