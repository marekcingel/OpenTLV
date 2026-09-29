# Playground

Paste hexadecimal TLV data, choose a format and press **Parse** to see the
nested structure as a tree, a hex dump or JSON. Parsing runs in your browser with the
[OpenTLV WebAssembly build](../development/webassembly.md), the same C core as
native applications. Nothing you enter is uploaded.

<!-- markdownlint-disable MD033 -->
<div id="opentlv-playground" class="otlv-pg">
  <noscript>The playground needs JavaScript and WebAssembly.</noscript>
  <p id="otlv-pg-status" class="otlv-pg-status" role="status">Loading the OpenTLV WebAssembly module…</p>
  <div class="otlv-pg-controls">
    <label>Sample
      <select id="otlv-pg-sample" disabled></select>
    </label>
    <label>Format
      <select id="otlv-pg-format" disabled>
        <optgroup label="Generic core formats">
          <option value="fixed">Fixed (TLV / LTV)</option>
        </optgroup>
        <optgroup label="Built-in standards">
          <option value="bluetooth-ltv">Bluetooth LTV (strict)</option>
          <option value="ber">ASN.1 BER-TLV</option>
          <option value="emv">EMV BER-TLV (definite)</option>
          <option value="der">ASN.1 DER-TLV</option>
          <option value="cer">ASN.1 CER-TLV</option>
        </optgroup>
        <optgroup label="Standard containers">
          <option value="bluetooth-ad">Bluetooth Advertising Data</option>
        </optgroup>
      </select>
    </label>
    <label>Annotations
      <select id="otlv-pg-module" disabled>
        <option value="none">None (AD names are automatic)</option>
        <option value="emv">EMV tag names (BER or EMV)</option>
      </select>
    </label>
  </div>
  <div id="otlv-pg-fixed-options" class="otlv-pg-controls" hidden>
    <label>Fixed tag size (bytes)
      <input id="otlv-pg-fixed-tag-size" type="number" min="1" value="1" disabled>
    </label>
    <label>Fixed length size (bytes)
      <input id="otlv-pg-fixed-length-size" type="number" min="1" max="8" value="1" disabled>
    </label>
    <label>Fixed length byte order
      <select id="otlv-pg-fixed-order" disabled>
        <option value="big">Big-endian</option>
        <option value="little">Little-endian</option>
      </select>
    </label>
    <label>Field order
      <select id="otlv-pg-fixed-element-order" disabled>
        <option value="tlv">Tag | Length | Value</option>
        <option value="ltv">Length | Tag | Value</option>
      </select>
    </label>
    <label>Length counts
      <select id="otlv-pg-fixed-length-scope" disabled>
        <option value="value">Value only</option>
        <option value="tag-and-value">Tag + Value</option>
      </select>
    </label>
  </div>
  <p id="otlv-pg-sample-note" class="otlv-pg-sample-note" hidden></p>
  <label for="otlv-pg-input" class="otlv-pg-label">TLV data (hexadecimal, whitespace ignored)</label>
  <textarea id="otlv-pg-input" class="otlv-pg-input" rows="6" spellcheck="false" autocomplete="off" autocapitalize="off" placeholder="6F 0A 84 03 41 42 43 A5 03 50 01 01"></textarea>
  <div class="otlv-pg-actions">
    <button id="otlv-pg-parse" class="md-button md-button--primary" type="button" disabled>Parse</button>
    <span class="otlv-pg-hint">Ctrl+Enter also parses.</span>
  </div>
  <div id="otlv-pg-error" class="otlv-pg-error" role="alert" hidden></div>
  <div id="otlv-pg-output" class="otlv-pg-output" aria-live="polite"></div>
</div>
<!-- markdownlint-enable MD033 -->

## What it shows

The result has three views of one parse. Tree and Hex share the current selection;
JSON shows the complete result and its source ranges.

- **Tree**: the nested elements with tag, length, offset and, for primitive
  elements, the value. Select an element to inspect it.
- **Hex**: a hex dump of the input. The selected element's tag, length and value
  bytes are highlighted in different colors, and clicking a byte selects the
  innermost element that contains it.
- **JSON**: the parse result as JSON, with a **Copy JSON** button.

Choosing **Fixed (TLV / LTV)** reveals tag size, length size (1-8 bytes), length
byte order, field order and length scope controls, matching C `tlv_fixed_format_t`.
The controls default to a one-byte tag, a one-byte length, big-endian, TLV order
and Value-only length. The C++ `tlv::fixed_format` wrapper exposes the
conventional TLV preset of the
[configurable fixed-width format](../formats/fixed/configurable.md).
Fixed is part of the core. Built-in standards and containers are grouped separately.

The inspector lists the selected element's tag, encoded tag and length bytes,
logical value length, offset, complete encoded size, nesting depth and path,
raw value and any trailer (such as BER end-of-contents), with
buttons to copy the tag, the value or the whole encoded element. With the
**EMV tag names** annotations it also shows the tag's name from the
[EMV module](../standards/emv/README.md) and whether its length is permitted.

In [BER-TLV](../formats/asn1/ber.md),
[DER-TLV](../formats/asn1/der.md), [CER-TLV](../formats/asn1/cer.md) and
[EMV BER-TLV](../standards/emv/README.md), wire-constructed elements nest their children; the
[configurable fixed-width](../formats/fixed/configurable.md) and
[Bluetooth LTV](../formats/bluetooth/README.md) formats have opaque values, so
their elements are flat. Bluetooth LTV puts the length byte before the type, so
in the hex view and the element details the length is shown before the tag. The EMV preset requires definite lengths; semantic primitive-bit templates remain opaque.

Invalid or truncated input reports the parser error with its code, message and
input offset, together with every element read before the failure.

## Bluetooth Advertising Data

Choose a Bluetooth sample to explore named AD structures, or compare the same
buffer in **Bluetooth Advertising Data** and **Bluetooth LTV (strict)** modes.
Advertising Data accepts trailing all-zero padding at structure boundaries.
The summary and hex view identify padding separately; nonzero padding reports
its exact source offset. Strict LTV continues to reject a zero length byte.
Both modes use the C AD Type registry for names, including Flags, Local Name,
Service Data and Manufacturer Specific Data. Unknown types remain readable.
Values remain raw; this view does not apply Bluetooth schemas or value codecs.

CER uses the generic reader and tree walker with `tlv_format_cer`: framing and
EOC boundaries are checked. Full CER validation, including string
segmentation rules and semantic value checks, is not applied.

## Limits

The playground only parses and inspects. Editing, re-encoding, schemas, `.otlv`
and shareable sessions are not available. Library functionality
not listed in the controls are not exposed by this playground yet. One parse reads at most 65,536
elements and 64 levels of nesting; see
[WebAssembly build](../development/webassembly.md#use-from-javascript).
