// Interactive TLV playground (docs/playground/index.md). All parsing is done by
// the OpenTLV WebAssembly build in bindings/wasm; this file only reads the
// input, calls opentlv.parse() once and renders that one result in three
// synchronized views (Tree, Hex, JSON) and an inspector for the selected
// element. Nothing is parsed or decoded here: offsets, sizes and names come
// from the parse result, and the JSON view serializes that same result.
const root = document.getElementById("opentlv-playground");

const SAMPLES = [
  {
    name: "EMV: SELECT response (FCI)",
    format: "emv",
    module: "emv",
    hex: "6F 19 84 07 A0 00 00 00 03 10 10 A5 0E 50 04 56 49 53 41 87 01 01 5F 2D 02 65 6E",
  },
  {
    name: "BER: nested constructed elements",
    format: "ber",
    module: "none",
    hex: "6F 0A 84 03 41 42 43 A5 03 50 01 01",
  },
  {
    name: "BER: indefinite SEQUENCE and EOC",
    format: "ber", module: "none",
    hex: "30 80 02 01 05 00 00",
    description: "The final 00 00 is the SEQUENCE trailer (end-of-contents), not its Value and not Bluetooth padding.",
  },
  {
    name: "DER: SEQUENCE of INTEGER and UTF8String",
    format: "der",
    module: "none",
    hex: "30 0A 02 01 05 0C 05 48 65 6C 6C 6F",
  },
  {
    name: "CER: indefinite SEQUENCE and EOC",
    format: "cer", module: "none",
    hex: "30 80 02 01 05 0C 05 48 65 6C 6C 6F 00 00",
    description: "CER constructed framing uses an indefinite length. The final 00 00 is the SEQUENCE trailer. This view checks framing, not the full CER validation.",
  },
  {
    name: "Fixed TLV: flat elements",
    format: "fixed",
    module: "none",
    hex: "01 03 41 42 43 02 02 68 69",
  },
  {
    name: "Fixed: LTV with Tag + Value length",
    fixedElementOrder: "ltv", fixedLengthScope: "tag-and-value",
    format: "fixed",
    module: "none",
    hex: "04 01 AA BB CC 02 04 2A",
    description: "Generic Fixed configured as LTV: the encoded length counts Tag + Value, while each element reports only its logical Value length.",
  },
  {
    name: "Bluetooth: Sensor advertisement + padding",
    format: "bluetooth-ad",
    module: "none",
    hex: "02 01 06 07 09 53 65 6E 73 6F 72 02 0A FC 00 00 00",
    description: "Flags, the name Sensor and Tx Power (-4 dBm), followed by three zero padding bytes. Select an AD structure to inspect its Length | Type | Value bytes.",
  },
  {
    name: "Bluetooth: service and manufacturer data",
    format: "bluetooth-ad", module: "none",
    hex: "03 03 0F 18 05 16 0F 18 64 01 05 FF 4C 00 AA BB",
    description: "A 16-bit Service UUID list, Service Data and Manufacturer Specific Data. Payloads remain raw; names come from the C AD Type registry.",
  },
  {
    name: "Bluetooth: invalid padding",
    format: "bluetooth-ad", module: "none",
    hex: "02 01 06 00 00 01",
    description: "The first structure is valid. A nonzero byte after padding starts is an error at offset 5.",
  },
  {
    name: "Bluetooth LTV: strict framing",
    format: "bluetooth-ltv", module: "none",
    hex: "02 01 06 00 00 00",
    description: "The same padded buffer in strict LTV mode: zero length is invalid. Choose Bluetooth Advertising Data to handle container padding.",
  },
  {
    name: "Truncated input (parser error)",
    format: "emv",
    module: "emv",
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

// Nodes in preorder, which is also the order of their bytes in the input.
// `start`/`end` bound the whole encoded element, `headerEnd` where its value begins.
function flatten(elements) {
  const nodes = [];
  const visit = (item, parent) => {
    const node = {
      id: nodes.length,
      item,
      parent,
      children: [],
      start: item.offset,
      headerEnd: item.source.value.offset,
      valueEnd: item.source.value.offset + item.source.value.length,
      end: item.offset + item.encodedSize,
      tagStart: item.source.tag.offset,
      tagSize: item.source.tag.length,
      lengthStart: item.source.length.offset,
      lengthEnd: item.source.length.offset + item.source.length.length,
      trailerStart: item.source.trailer.offset,
      trailerEnd: item.source.trailer.offset + item.source.trailer.length,
    };
    nodes.push(node);
    if (parent) parent.children.push(node);
    for (const child of item.children ?? []) visit(child, node);
  };
  for (const item of elements) visit(item, null);
  return nodes;
}

const hexOf = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
const hex4 = (n) => `0x${n.toString(16).toUpperCase().padStart(4, "0")}`;

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    // Clipboard API unavailable (insecure context, denied permission): fall back.
    const area = element("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.append(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (ignored) {
      ok = false;
    }
    area.remove();
    return ok;
  }
}

function copyButton(label, getText) {
  const button = element("button", "otlv-pg-copy", label);
  button.type = "button";
  let timer;
  button.addEventListener("click", async () => {
    const ok = await copyText(getText());
    button.textContent = ok ? "Copied" : "Copy failed";
    clearTimeout(timer);
    timer = setTimeout(() => (button.textContent = label), 1500);
  });
  return button;
}

async function start() {
  const status = document.getElementById("otlv-pg-status");
  const sampleSelect = document.getElementById("otlv-pg-sample");
  const formatSelect = document.getElementById("otlv-pg-format");
  const moduleSelect = document.getElementById("otlv-pg-module");
  const fixedOptions = document.getElementById("otlv-pg-fixed-options");
  const fixedTagSize = document.getElementById("otlv-pg-fixed-tag-size");
  const fixedLengthSize = document.getElementById("otlv-pg-fixed-length-size");
  const fixedOrder = document.getElementById("otlv-pg-fixed-order");
  const fixedElementOrder = document.getElementById("otlv-pg-fixed-element-order");
  const fixedLengthScope = document.getElementById("otlv-pg-fixed-length-scope");
  const input = document.getElementById("otlv-pg-input");
  const sampleNote = document.getElementById("otlv-pg-sample-note");
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
  for (const option of formatSelect.options) option.disabled = !opentlv.formats.includes(option.value);
  if (!opentlv.formats.includes(formatSelect.value)) formatSelect.value = opentlv.formats[0];
  SAMPLES.forEach((sample, index) => {
    if (opentlv.formats.includes(sample.format) && opentlv.modules.includes(sample.module)) {
      sampleSelect.append(new Option(sample.name, String(index)));
    }
  });

  function showError(lines) {
    errorBox.replaceChildren(...lines.map((line) => element("div", "", line)));
    errorBox.hidden = false;
  }

  const plural = (count, noun) => `${count} ${noun}${count === 1 ? "" : "s"}`;

  // Everything below the parse is derived from `session`: the bytes that were
  // parsed and the single parse result.
  let session = null;
  let selected = null;
  let treeRows = [];
  let byteCells = [];
  let detail;

  function renderDetail() {
    if (!session) return;
    if (!selected) {
      detail.replaceChildren(element("p", "otlv-pg-empty", "Select an element in the Tree or Hex view to inspect it."));
      return;
    }
    const { bytes, module } = session;
    const { item } = selected;
    const tagBytes = bytes.subarray(selected.tagStart, selected.tagStart + selected.tagSize);
    const lengthBytes = bytes.subarray(selected.lengthStart, selected.lengthEnd);
    const valueBytes = bytes.subarray(selected.headerEnd, selected.valueEnd);
    const encoded = bytes.subarray(selected.start, selected.end);
    const path = [];
    for (let node = selected; node; node = node.parent) path.unshift(node.item.tag);

    const list = element("dl", "otlv-pg-fields");
    const add = (title, text) => {
      const row = element("div", "otlv-pg-field");
      row.append(element("dt", "", title), element("dd", "", text));
      list.append(row);
    };
    if (item.name) add("Name", item.name);
    if (item.symbol) add("Module entry", `${module.toUpperCase()} · ${item.symbol}`);
    const bluetooth = session.result.format.startsWith("bluetooth-");
    add(bluetooth ? "AD Type" : "Tag", item.tag);
    if (bluetooth) add("Wire layout", "Length | Type | Value; wire length counts Type + Value");
    add("Value length", `${item.length}${item.lengthValid === false ? " (outside the range the module permits)" : ""}`);
    const fields = [
      { offset: selected.tagStart, title: "Encoded tag", bytes: tagBytes },
      { offset: selected.lengthStart, title: "Encoded length", bytes: lengthBytes },
    ];
    fields.sort((a, b) => a.offset - b.offset);
    for (const field of fields) add(field.title, `${spaced(hexOf(field.bytes))} (${plural(field.bytes.length, "byte")})`);
    if (item.source.trailer.length) add("Trailer / EOC", spaced(hexOf(bytes.subarray(selected.trailerStart, selected.trailerEnd))));
    add("Offset", `${item.offset} (${hex4(item.offset)})`);
    add("Encoded size", `${plural(selected.end - selected.start, "byte")} (${item.headerSize} header + ${item.length} value + ${item.source.trailer.length} trailer)`);
    add(
      "Nesting",
      `depth ${item.depth}, ${
        item.constructed ? `constructed with ${plural(selected.children.length, "child element")}` : "primitive"
      }, path ${path.join(" › ")}`,
    );
    add(item.constructed ? "Raw value (nested elements)" : "Raw value", valueBytes.length ? spaced(hexOf(valueBytes)) : "(empty)");

    const actions = element("div", "otlv-pg-copy-row");
    actions.append(
      copyButton("Copy tag", () => hexOf(tagBytes)),
      copyButton("Copy value", () => hexOf(valueBytes)),
      copyButton("Copy encoded element", () => hexOf(encoded)),
    );
    detail.replaceChildren(list, actions);
  }

  function selectNode(node) {
    selected = node;
    treeRows.forEach((row, id) => row.classList.toggle("otlv-pg-selected", node !== null && id === node.id));
    byteCells.forEach((cell, index) => {
      const inside = node !== null && index >= node.start && index < node.end;
      cell.classList.toggle("otlv-pg-b-tag", inside && index >= node.tagStart && index < node.tagStart + node.tagSize);
      cell.classList.toggle("otlv-pg-b-len", inside && index >= node.lengthStart && index < node.lengthEnd);
      cell.classList.toggle("otlv-pg-b-val", inside && index >= node.headerEnd && index < node.valueEnd);
      cell.classList.toggle("otlv-pg-b-trailer", inside && index >= node.trailerStart && index < node.trailerEnd);
    });
    renderDetail();
  }

  function renderTree(nodes) {
    const build = (node) => {
      const { item } = node;
      const wrapper = element("div", "otlv-pg-node");
      const row = element("div", "otlv-pg-row");
      const label = element("button", "otlv-pg-select");
      label.type = "button";
      label.append(
        element("span", "otlv-pg-tag", item.tag),
        element("span", "otlv-pg-meta", ` len ${item.length} @ offset ${item.offset}`),
      );
      if (item.name) label.append(element("span", "otlv-pg-name", ` ${item.name}`));
      if (!item.constructed && item.value) label.append(" ", element("span", "otlv-pg-value", spaced(item.value)));
      label.addEventListener("click", () => selectNode(node));
      treeRows[node.id] = row;
      if (node.children.length) {
        const toggle = element("button", "otlv-pg-toggle", "▾");
        toggle.type = "button";
        toggle.setAttribute("aria-expanded", "true");
        toggle.setAttribute("aria-label", `Collapse ${item.tag}`);
        row.append(toggle, label);
        wrapper.append(row);
        const children = element("div", "otlv-pg-children");
        for (const child of node.children) children.append(build(child));
        wrapper.append(children);
        toggle.addEventListener("click", () => {
          const open = children.hidden;
          children.hidden = !open;
          toggle.textContent = open ? "▾" : "▸";
          toggle.setAttribute("aria-expanded", String(open));
          toggle.setAttribute("aria-label", `${open ? "Collapse" : "Expand"} ${item.tag}`);
        });
      } else {
        row.append(element("span", "otlv-pg-toggle"), label);
        wrapper.append(row);
      }
      return wrapper;
    };
    const tree = element("div", "otlv-pg-tree");
    for (const node of nodes) if (node.parent === null) tree.append(build(node));
    return tree;
  }

  function renderHex(bytes, nodes) {
    // A click selects the deepest element that contains the byte.
    const owners = new Array(bytes.length).fill(null);
    for (const node of nodes) for (let i = node.start; i < node.end && i < bytes.length; i += 1) owners[i] = node;
    const dump = element("div", "otlv-pg-dump");
    for (let rowStart = 0; rowStart < bytes.length; rowStart += 16) {
      const line = element("div", "otlv-pg-dump-row");
      line.append(element("span", "otlv-pg-offset", rowStart.toString(16).toUpperCase().padStart(4, "0")));
      const cells = element("span", "otlv-pg-bytes");
      const ascii = element("span", "otlv-pg-ascii");
      for (let i = rowStart; i < Math.min(rowStart + 16, bytes.length); i += 1) {
        const cell = element("span", "otlv-pg-byte", bytes[i].toString(16).toUpperCase().padStart(2, "0"));
        const padding = session.result.padding;
        if (padding && i >= padding.offset && i < padding.offset + padding.length) {
          cell.classList.add("otlv-pg-b-padding");
          cell.title = `Zero padding at offset ${i}`;
        }
        cell.addEventListener("click", () => selectNode(owners[i]));
        byteCells[i] = cell;
        cells.append(cell);
        const printable = bytes[i] >= 0x20 && bytes[i] < 0x7f;
        ascii.append(element("span", "otlv-pg-char", printable ? String.fromCharCode(bytes[i]) : "·"));
      }
      line.append(cells, ascii);
      dump.append(line);
    }
    return dump;
  }

  function renderResult(bytes, result, module) {
    const nodes = flatten(result.elements);
    session = { bytes, result, nodes, module };
    treeRows = [];
    byteCells = [];
    selected = null;

    const tabs = element("div", "otlv-pg-tabs");
    tabs.setAttribute("role", "tablist");
    const jsonText = JSON.stringify(result, null, 2);
    const views = [
      { key: "tree", label: "Tree", panel: element("div", "otlv-pg-panel"), copy: null },
      { key: "hex", label: "Hex", panel: element("div", "otlv-pg-panel"), copy: copyButton("Copy hex", () => hexOf(bytes)) },
      { key: "json", label: "JSON", panel: element("div", "otlv-pg-panel"), copy: copyButton("Copy JSON", () => jsonText) },
    ];
    views[0].panel.append(nodes.length ? renderTree(nodes) : element("div", "otlv-pg-empty", "No elements."));
    const legend = element("div", "otlv-pg-legend");
    for (const [kind, label] of [["tag", "Tag / AD Type"], ["len", "Encoded length"], ["val", "Value"], ["trailer", "Trailer / EOC"], ["padding", "Container padding"]]) {
      legend.append(element("span", `otlv-pg-byte otlv-pg-b-${kind}`, label));
    }
    views[1].panel.append(legend, renderHex(bytes, nodes));
    views[2].panel.append(element("pre", "otlv-pg-json", jsonText));

    const show = (active) => {
      for (const view of views) {
        const on = view === active;
        view.panel.hidden = !on;
        view.button.setAttribute("aria-selected", String(on));
        view.button.tabIndex = on ? 0 : -1;
        if (view.copy) view.copy.hidden = !on;
      }
    };
    views.forEach((view, index) => {
      view.button = element("button", "otlv-pg-tab", view.label);
      view.button.type = "button";
      view.button.setAttribute("role", "tab");
      view.button.id = `otlv-pg-tab-${view.key}`;
      view.panel.id = `otlv-pg-panel-${view.key}`;
      view.button.setAttribute("aria-controls", view.panel.id);
      view.panel.setAttribute("role", "tabpanel");
      view.panel.setAttribute("aria-labelledby", view.button.id);
      view.button.addEventListener("click", () => show(view));
      view.button.addEventListener("keydown", (event) => {
        const step = { ArrowRight: 1, ArrowLeft: -1 }[event.key];
        if (!step) return;
        const next = views[(index + step + views.length) % views.length];
        show(next);
        next.button.focus();
      });
      tabs.append(view.button);
    });
    for (const view of views) if (view.copy) tabs.append(view.copy);

    detail = element("div", "otlv-pg-detail");
    detail.setAttribute("aria-live", "polite");
    output.replaceChildren(tabs, ...views.map((view) => view.panel), element("h3", "otlv-pg-detail-title", "Inspector"), detail);
    if (result.format.startsWith("bluetooth-")) {
      const summary = element("div", "otlv-pg-summary");
      summary.append(element("strong", "", result.format === "bluetooth-ad" ? "Bluetooth Advertising Data" : "Bluetooth LTV ? strict framing"));
      summary.append(element("p", "", `${plural(nodes.length, "AD structure")} ? ${plural(bytes.length, "input byte")}`));
      if (result.padding) {
        summary.append(element("p", "", `${plural(result.padding.length, "padding byte")} from offset ${result.padding.offset}. All remaining bytes are zero; padding is not an AD structure.`));
        views[0].panel.append(element("div", "otlv-pg-padding-note", `End of AD structures ? ${result.padding.length} zero padding bytes @ offset ${result.padding.offset}`));
      }
      summary.append(element("p", "", "Names identify AD Types. Values remain raw; schema and codec validation are not applied."));
      output.prepend(summary);
    }
    show(views[0]);
    selectNode(nodes[0] ?? null);
  }

  function parse() {
    errorBox.hidden = true;
    output.replaceChildren();
    session = null;
    let bytes;
    try {
      bytes = hexToBytes(input.value);
    } catch (error) {
      showError(["Invalid input: enter an even number of hexadecimal digits (0-9, A-F). Whitespace is ignored."]);
      return;
    }
    const module = moduleSelect.value;
    const options = { format: formatSelect.value, module };
    if (formatSelect.value === "fixed") {
      options.fixedTagSize = Number(fixedTagSize.value);
      options.fixedLengthSize = Number(fixedLengthSize.value);
      options.fixedByteOrder = fixedOrder.value;
      options.fixedElementOrder = fixedElementOrder.value;
      options.fixedLengthScope = fixedLengthScope.value;
    }
    let result;
    try {
      result = opentlv.parse(bytes, options);
    } catch (error) {
      showError([error.message || "The parse could not be completed."]);
      return;
    }
    if (result.error) {
      const { code, message, offset } = result.error;
      showError([`Parse error at offset ${offset}: ${message} (code ${code})`]);
    }
    if (bytes.length > 0) {
      renderResult(bytes, result, module);
    } else if (!result.error) {
      output.append(element("div", "otlv-pg-empty", "No elements (empty input)."));
    }
  }

  // The EMV dictionary names BER-TLV tags only.
  function syncModule() {
    const berFormat = ["ber", "emv"].includes(formatSelect.value) && opentlv.modules.includes("emv");
    moduleSelect.querySelector('option[value="emv"]').disabled = !berFormat;
    if (!berFormat) moduleSelect.value = "none";
  }
  formatSelect.addEventListener("change", syncModule);

  // Fixed-width TLV is the only format with runtime-configurable tag/length widths.
  function syncFixedOptions() {
    const fixedFormat = formatSelect.value === "fixed";
    fixedOptions.hidden = !fixedFormat;
    for (const control of [fixedTagSize, fixedLengthSize, fixedOrder, fixedElementOrder, fixedLengthScope]) control.disabled = !fixedFormat;
  }
  formatSelect.addEventListener("change", syncFixedOptions);

  sampleSelect.addEventListener("change", () => {
    const sample = sampleSelect.value === "" ? null : SAMPLES[Number(sampleSelect.value)];
    if (!sample) return;
    sampleNote.textContent = sample.description ?? "";
    sampleNote.hidden = !sample.description;
    input.value = sample.hex;
    formatSelect.value = sample.format;
    syncModule();
    syncFixedOptions();
    moduleSelect.value = sample.module;
    fixedTagSize.value = sample.fixedTagSize ?? 1;
    fixedLengthSize.value = sample.fixedLengthSize ?? 1;
    fixedOrder.value = sample.fixedByteOrder ?? "big";
    fixedElementOrder.value = sample.fixedElementOrder ?? "tlv";
    fixedLengthScope.value = sample.fixedLengthScope ?? "value";
    parse();
  });
  const clearSampleNote = () => {
    sampleNote.hidden = true;
    sampleSelect.value = "";
  };
  input.addEventListener("input", clearSampleNote);
  const markStale = () => {
    clearSampleNote();
    if (session) {
      output.replaceChildren(element("p", "otlv-pg-empty", "Input or settings changed. Press Parse to refresh the result."));
      session = null;
      errorBox.hidden = true;
    }
  };
  for (const control of [input, formatSelect, moduleSelect, fixedTagSize, fixedLengthSize, fixedOrder, fixedElementOrder, fixedLengthScope]) {
    control.addEventListener(control === input || control.tagName === "INPUT" ? "input" : "change", markStale);
  }
  formatSelect.addEventListener("change", clearSampleNote);
  parseButton.addEventListener("click", parse);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      parse();
    }
  });

  syncModule();
  syncFixedOptions();
  for (const control of [sampleSelect, formatSelect, moduleSelect, parseButton]) control.disabled = false;
}

if (root) start();
