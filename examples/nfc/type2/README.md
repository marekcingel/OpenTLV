# NFC Type 2 validation corpus

These checked-in binary dumps are hand-authored, synthetic framing vectors,
not captures from physical tags. They follow the TLV framing described in
[NFC Forum Type 2 Tag Operation 1.1, section 2.3](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/nfc/3252/1/NFCForum-Type-2-Tag_1.1%20Specification.pdf).
They are the supported NFC Type 2 format corpus, exercised by C integration
tests and, when built, CLI tests. No RF headers, UID, Capability Container,
lock bytes or reserved memory holes are included. Values remain opaque to
OpenTLV; these vectors do not assert physical tag or NDEF conformance.

## Decode and encode the sample

Build with `OPENTLV_BUILD_CLI=ON` and `OPENTLV_NFC=ON` and put `otlv` on PATH.
From the repository root:

```sh
otlv decode --format nfc-type2 --input examples/nfc/type2/sample.bin
```

Expected structured output:

```json
{"schema":"opentlv.tlv","version":1,"format":"nfc-type2","elements":[{"tag":"00","value":""},{"tag":"03","value":"D101055402656E4869"},{"tag":"FE","value":""}]}
```

`sample.bin` contains `00 03 09 D1 01 05 54 02 65 6E 48 69 FE`: NULL padding,
a nine-byte NDEF Value encoding an English Text record with text `Hi`, and
Terminator. The TLV offsets are 0, 1 and 12. Decode exports raw NDEF bytes.

To reproduce the binary in a POSIX shell:

```sh
otlv decode --format nfc-type2 --input examples/nfc/type2/sample.bin > sample.json
otlv encode --format nfc-type2 --input sample.json --output-encoding binary --output-file sample-roundtrip.bin
cmake -E compare_files examples/nfc/type2/sample.bin sample-roundtrip.bin
```

In Windows PowerShell, save JSON explicitly as UTF-8 without a BOM:

```powershell
$json = otlv decode --format nfc-type2 --input examples/nfc/type2/sample.bin
[IO.File]::WriteAllText((Join-Path $PWD 'sample.json'), $json, [Text.UTF8Encoding]::new($false))
otlv encode --format nfc-type2 --input sample.json --output-encoding binary --output-file sample-roundtrip.bin
cmake -E compare_files examples/nfc/type2/sample.bin sample-roundtrip.bin
```

## Positive vectors

`T:V` below describes the expected semantic Tag and Value in order; `-` is
an empty Value. The files contain raw bytes, without a format-selector prefix.

| File | Complete wire bytes | Expected Elements |
| --- | --- | --- |
| `sample.bin` | `00 03 09 D1 01 05 54 02 65 6E 48 69 FE` | `00:-`, `03:D101055402656E4869`, `FE:-` |
| `empty-ndef.bin` | `03 00 FE` | `03:-`, `FE:-` |
| `controls.bin` | `01 03 A0 10 44 02 03 B0 04 04 03 00 FD 03 00 FE FF FE` | `01:A01044`, `02:B00404`, `03:-`, `FD:00FEFF`, `FE:-` |
| `short-254.bin` | `FD FE` + ramp(254) + `FE` | `FD:ramp(254)`, `FE:-` |
| `extended-255.bin` | `FD FF 00 FF` + ramp(255) + `FE` | `FD:ramp(255)`, `FE:-` |
| `extended-256.bin` | `FD FF 01 00` + ramp(256) + `FE` | `FD:ramp(256)`, `FE:-` |
| `framing-policy.bin` | `00 FE 00 2A 00 FF 01 A5` | `00:-`, `FE:-`, `00:-`, `2A:-`, `FF:A5` |

`ramp(n)` is exactly `n` bytes, byte `i = i mod 256`, starting at zero.
The control Values are illustrative opaque payloads; no physical address
mapping is performed. The three boundary vectors test proprietary payloads
without implying a complete tag image. `framing-policy.bin` deliberately
continues after Terminator: generic Reader exposes every element and leaves
termination policy to the caller. It is not a conforming device data area.

Each positive vector is decoded against independent expected Tags, Values,
offsets and source ranges, encoded from those expected Elements, and round-tripped
through Reader -> Element -> Writer. Equality uses regenerated framing, not raw
source copying. NULL, duplicates and element order are retained.

## Invalid vectors

These files in `invalid/` fail on their first element; no cursor advancement
is expected.

| File | Bytes | Expected result |
| --- | --- | --- |
| `nonminimal-extended.bin` | `03 FF 00 FE` | `TLV_ERR_INVALID_LENGTH` |
| `reserved-length.bin` | `03 FF FF FF` | `TLV_ERR_INVALID_LENGTH` |
| `missing-length.bin` | `03` | `TLV_ERR_BUFFER_TOO_SHORT` |
| `truncated-extended.bin` | `03 FF 01` | `TLV_ERR_BUFFER_TOO_SHORT` |
| `truncated-value.bin` | `03 03 D0 00` | `TLV_ERR_BUFFER_TOO_SHORT` |

## Run validation

Enable `OPENTLV_BUILD_TESTS` and `OPENTLV_BUILD_INTEGRATION_TESTS`, build, then:

```sh
ctest --test-dir build -C Debug -R "NfcType2|Integration_cli|Integration_example_tlv_nfc_type2" --output-on-failure
```

Use the configuration and build directory of your own build. CLI tests require
`OPENTLV_BUILD_CLI_TESTS`; the C example requires `OPENTLV_BUILD_EXAMPLES`.
