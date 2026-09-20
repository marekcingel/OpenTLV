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
        <option value="default">Default TLV</option>
        <option value="fixed-1byte">Fixed 1-byte TLV</option>
        <option value="ber">BER-TLV</option>
        <option value="der">DER-TLV</option>
      </select>
    </label>
    <label>Profile
      <select id="otlv-pg-profile" disabled>
        <option value="none">None</option>
        <option value="emv">EMV tag names (BER-TLV only)</option>
      </select>
    </label>
  </div>
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

The result has three views of one parse; a selection in any of them is shown
in all of them.

- **Tree**: the nested elements with tag, length, offset and, for primitive
  elements, the value. Select an element to inspect it.
- **Hex**: a hex dump of the input. The selected element's tag, length and value
  bytes are highlighted in different colors, and clicking a byte selects the
  innermost element that contains it.
- **JSON**: the parse result as JSON, with a **Copy JSON** button.

The inspector lists the selected element's tag, encoded tag and length bytes,
length, offset, encoded size, nesting depth and path, and raw value, with
buttons to copy the tag, the value or the whole encoded element. With the
**EMV** profile it also shows the tag's name from the
[EMV profile](../profiles/emv/README.md) and whether its length is permitted.

In [BER-TLV](../formats/asn1/ber.md) and
[DER-TLV](../formats/asn1/der.md) constructed elements nest their children; the
[Default](../formats/default/README.md) and
[Fixed 1-byte](../formats/fixed/README.md) formats have opaque values, so their
elements are flat. EMV data is BER-TLV.

Invalid or truncated input reports the parser error with its code, message and
input offset, together with every element read before the failure.

## Limits

The playground only parses and inspects. Editing, re-encoding, schemas, OTDL
and shareable sessions are not available. One parse reads at most 65,536
elements and 64 levels of nesting; see
[WebAssembly build](../development/webassembly.md#use-from-javascript).
