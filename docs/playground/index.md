# Playground

Paste hexadecimal TLV data, choose a format and press **Parse** to see the
nested structure. Parsing runs in your browser with the
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

Each element lists its tag, length, offset in the input and, for primitive
elements, its value in hexadecimal. In [BER-TLV](../formats/asn1/ber.md) and
[DER-TLV](../formats/asn1/der.md) constructed elements nest their children; the
[Default](../formats/default/README.md) and
[Fixed 1-byte](../formats/fixed/README.md) formats have opaque values, so their
elements are flat. EMV data is BER-TLV, see the [EMV profile](../profiles/emv/README.md).

Invalid or truncated input reports the parser error with its code, message and
input offset, together with every element read before the failure.

## Limits

The playground only parses. Editing, re-encoding, JSON export, schemas, profiles
and OTDL are not available. One parse reads at most 65,536 elements and 64
levels of nesting; see [WebAssembly build](../development/webassembly.md#use-from-javascript).
