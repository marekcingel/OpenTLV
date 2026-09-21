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
    format: "ber",
    profile: "emv",
    hex: "6F 19 84 07 A0 00 00 00 03 10 10 A5 0E 50 04 56 49 53 41 87 01 01 5F 2D 02 65 6E",
  },
  {
    name: "BER: nested constructed elements",
    format: "ber",
    profile: "none",
    hex: "6F 0A 84 03 41 42 43 A5 03 50 01 01",
  },
  {
    name: "DER: SEQUENCE of INTEGER and UTF8String",
    format: "der",
    profile: "none",
    hex: "30 0A 02 01 05 0C 05 48 65 6C 6C 6F",
  },
  {
    name: "Default TLV: flat elements",
    format: "default",
    profile: "none",
    hex: "01 03 41 42 43 02 02 68 69",
  },
  {
    name: "Fixed 1-byte TLV",
    format: "fixed-1byte",
    profile: "none",
    hex: "01 03 AA BB CC 04 01 2A",
  },
  {
    name: "Bluetooth LTV: advertising data",
    format: "bluetooth-ltv",
    profile: "none",
    hex: "02 01 06 03 09 48 69",
  },
  {
    name: "Truncated input (parser error)",
    format: "ber",
    profile: "emv",
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
function flatten(elements, lengthFirst) {
  const nodes = [];
  const visit = (item, parent) => {
    const node = {
      id: nodes.length,
      item,
      parent,
      children: [],
      start: item.offset,
      headerEnd: item.offset + item.headerSize,
      end: item.offset + item.headerSize + item.length,
      tagSize: item.tag.length / 2,
    };
    // Bluetooth LTV encodes the length before the tag; other formats the tag first.
    const tagSize = node.tagSize;
    node.tagStart = lengthFirst ? node.headerEnd - tagSize : node.start;
    node.lengthStart = lengthFirst ? node.start : node.start + tagSize;
    node.lengthEnd = lengthFirst ? node.headerEnd - tagSize : node.headerEnd;
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
  const profileSelect = document.getElementById("otlv-pg-profile");
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
    const { bytes, profile } = session;
    const { item } = selected;
    const tagBytes = bytes.subarray(selected.tagStart, selected.tagStart + selected.tagSize);
    const lengthBytes = bytes.subarray(selected.lengthStart, selected.lengthEnd);
    const valueBytes = bytes.subarray(selected.headerEnd, selected.end);
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
    if (item.symbol) add("Profile entry", `${profile.toUpperCase()} · ${item.symbol}`);
    add("Tag", item.tag);
    add("Encoded tag", `${spaced(hexOf(tagBytes))} (${plural(tagBytes.length, "byte")})`);
    add("Length", `${item.length}${item.lengthValid === false ? " (outside the range the profile permits)" : ""}`);
    add("Encoded length", `${spaced(hexOf(lengthBytes))} (${plural(lengthBytes.length, "byte")})`);
    add("Offset", `${item.offset} (${hex4(item.offset)})`);
    add("Encoded size", `${plural(selected.end - selected.start, "byte")} (${item.headerSize} header + ${item.length} value)`);
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
      cell.classList.toggle("otlv-pg-b-val", inside && index >= node.headerEnd);
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

  function renderResult(bytes, result, profile) {
    const nodes = flatten(result.elements, result.format === "bluetooth-ltv");
    session = { bytes, result, nodes, profile };
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
    views[1].panel.append(renderHex(bytes, nodes));
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
    show(views[0]);
    renderDetail();
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
    const profile = profileSelect.value;
    const result = opentlv.parse(bytes, { format: formatSelect.value, profile });
    if (result.error) {
      const { code, message, offset } = result.error;
      showError([`Parse error at offset ${offset}: ${message} (code ${code})`]);
    }
    if (bytes.length > 0) {
      renderResult(bytes, result, profile);
    } else if (!result.error) {
      output.append(element("div", "otlv-pg-empty", "No elements (empty input)."));
    }
  }

  // The EMV dictionary names BER-TLV tags only.
  function syncProfile() {
    const berFormat = formatSelect.value === "ber";
    profileSelect.querySelector('option[value="emv"]').disabled = !berFormat;
    if (!berFormat) profileSelect.value = "none";
  }
  formatSelect.addEventListener("change", syncProfile);

  sampleSelect.addEventListener("change", () => {
    const sample = SAMPLES[Number(sampleSelect.value)];
    if (!sample) return;
    input.value = sample.hex;
    formatSelect.value = sample.format;
    syncProfile();
    profileSelect.value = sample.profile;
    parse();
  });
  parseButton.addEventListener("click", parse);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      parse();
    }
  });

  syncProfile();
  for (const control of [sampleSelect, formatSelect, profileSelect, parseButton]) control.disabled = false;
}

if (root) start();
