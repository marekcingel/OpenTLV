// Interactive TLV playground (docs/playground/index.md). All parsing is done by
// the OpenTLV WebAssembly build in bindings/wasm; this file only reads the
// input, calls opentlv.parse() and renders the returned structure.
const root = document.getElementById("opentlv-playground");

const SAMPLES = [
  {
    name: "EMV: SELECT response (FCI)",
    format: "ber",
    hex: "6F 19 84 07 A0 00 00 00 03 10 10 A5 0E 50 04 56 49 53 41 87 01 01 5F 2D 02 65 6E",
  },
  {
    name: "BER: nested constructed elements",
    format: "ber",
    hex: "6F 0A 84 03 41 42 43 A5 03 50 01 01",
  },
  {
    name: "DER: SEQUENCE of INTEGER and UTF8String",
    format: "der",
    hex: "30 0A 02 01 05 0C 05 48 65 6C 6C 6F",
  },
  {
    name: "Default TLV: flat elements",
    format: "default",
    hex: "01 03 41 42 43 02 02 68 69",
  },
  {
    name: "Fixed 1-byte TLV",
    format: "fixed-1byte",
    hex: "01 03 AA BB CC 04 01 2A",
  },
  {
    name: "Truncated input (parser error)",
    format: "ber",
    hex: "6F 19 84 07 A0 00 00 00 03 10 10 A5 0E 50 04 56",
  },
];

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// Space-separated byte pairs are easier to read than one long hex string.
function spaced(hex) {
  return hex.replace(/(..)(?=.)/g, "$1 ");
}

function renderElement(item) {
  const head = element("span");
  head.append(
    element("span", "otlv-pg-tag", item.tag),
    element(
      "span",
      "otlv-pg-meta",
      ` len ${item.length} @ offset ${item.offset}${item.constructed ? " constructed" : ""}`,
    ),
  );
  if (item.constructed) {
    const details = element("details");
    details.open = true;
    const summary = element("summary");
    summary.append(head);
    details.append(summary);
    const children = element("div", "otlv-pg-children");
    for (const child of item.children ?? []) children.append(renderElement(child));
    details.append(children);
    const node = element("div", "otlv-pg-node");
    node.append(details);
    return node;
  }
  const node = element("div", "otlv-pg-node");
  node.append(head);
  if (item.value) node.append(" ", element("span", "otlv-pg-value", spaced(item.value)));
  return node;
}

async function start() {
  const status = document.getElementById("otlv-pg-status");
  const sampleSelect = document.getElementById("otlv-pg-sample");
  const formatSelect = document.getElementById("otlv-pg-format");
  const input = document.getElementById("otlv-pg-input");
  const parseButton = document.getElementById("otlv-pg-parse");
  const errorBox = document.getElementById("otlv-pg-error");
  const output = document.getElementById("otlv-pg-output");

  let opentlv;
  let hexToBytes;
  try {
    // The WebAssembly files are published next to this script (tools/docs/hooks.py).
    const base = new URL("./wasm/", import.meta.url);
    const module = await import(new URL("opentlv.mjs", base));
    hexToBytes = module.hexToBytes;
    opentlv = await module.loadOpenTLV({ locateFile: (name) => new URL(name, base).href });
  } catch (error) {
    status.textContent =
      "The OpenTLV WebAssembly module could not be loaded, so the playground is unavailable. " +
      "This browser may lack WebAssembly support, or the documentation was built without the module.";
    console.error(error);
    return;
  }

  status.textContent = `OpenTLV ${opentlv.version} loaded. Parsing happens in your browser.`;

  sampleSelect.append(new Option("Choose a sample…", ""));
  SAMPLES.forEach((sample, index) => sampleSelect.append(new Option(sample.name, String(index))));

  function showError(lines) {
    errorBox.replaceChildren(...lines.map((line) => element("div", "", line)));
    errorBox.hidden = false;
  }

  function parse() {
    errorBox.hidden = true;
    output.replaceChildren();
    let bytes;
    try {
      bytes = hexToBytes(input.value);
    } catch (error) {
      showError(["Invalid input: enter an even number of hexadecimal digits (0-9, A-F). Whitespace is ignored."]);
      return;
    }
    const result = opentlv.parse(bytes, { format: formatSelect.value });
    if (result.error) {
      const { code, message, offset } = result.error;
      showError([`Parse error at offset ${offset}: ${message} (code ${code})`]);
    }
    if (result.elements.length > 0) {
      for (const item of result.elements) output.append(renderElement(item));
    } else if (!result.error) {
      output.append(element("div", "otlv-pg-empty", "No elements (empty input)."));
    }
  }

  sampleSelect.addEventListener("change", () => {
    const sample = SAMPLES[Number(sampleSelect.value)];
    if (!sample) return;
    input.value = sample.hex;
    formatSelect.value = sample.format;
    parse();
  });
  parseButton.addEventListener("click", parse);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      parse();
    }
  });

  for (const control of [sampleSelect, formatSelect, parseButton]) control.disabled = false;
}

if (root) start();
