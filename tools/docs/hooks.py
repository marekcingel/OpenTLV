"""MkDocs hooks: adapt relative links and publish the generated API references.

Links that leave docs/ point at the GitHub repository, and links to the GitHub
index docs/README.md point at the site landing page docs/index.md.

The Doxygen HTML for the C and C++ APIs is added to the site as static files
under reference/api/, so it is validated by the strict build like any page.
The WebAssembly module used by the playground is added under playground/wasm/.
"""

import logging
import os
import posixpath
import re

from mkdocs.exceptions import PluginError
from mkdocs.structure.files import File

log = logging.getLogger("mkdocs.hooks.opentlv")

REPO_URL = "https://github.com/marekcingel/OpenTLV"
# Git ref that repository links point at: the release tag for a released
# version, develop for the latest (development) documentation.
REF = os.environ.get("OPENTLV_DOCS_REF", "develop")

# Directory holding the c-api/html and cxx-api/html trees produced by the
# c-api-docs and cxx-api-docs CMake targets. The two trees stay siblings, as
# the C++ reference links to C declarations through a relative path.
API_DIR_ENV = "OPENTLV_API_DOCS_DIR"
API_DIR_DEFAULT = os.path.join("build", "docs", "docs")
API_TREES = ("c-api", "cxx-api")
API_SITE_PREFIX = "reference/api"

# Directory holding the opentlv-wasm artifacts (opentlv.mjs, opentlv-core.js,
# opentlv-core.wasm). They need an Emscripten build, so they are optional
# locally, where the playground then explains it is unavailable; CI sets
# OPENTLV_DOCS_REQUIRE_WASM=1 so a published site always includes them.
WASM_DIR_ENV = "OPENTLV_WASM_DIR"
WASM_DIR_DEFAULT = os.path.join("build-wasm", "bindings", "wasm", "dist")
WASM_REQUIRE_ENV = "OPENTLV_DOCS_REQUIRE_WASM"
WASM_FILES = ("opentlv.mjs", "opentlv-core.js", "opentlv-core.wasm")
WASM_SITE_PREFIX = "playground/wasm"

# Inline Markdown links: [text](target). Image links are left alone.
LINK = re.compile(r"(?<!!)(\[[^\]]*\]\()([^)\s]+)(\))")


def on_config(config):
    config.extra["docs_channel"] = os.environ.get("OPENTLV_DOCS_CHANNEL", config.extra["docs_channel"])
    return config


def on_files(files, config):
    api_dir = os.environ.get(API_DIR_ENV, API_DIR_DEFAULT)
    for tree in API_TREES:
        html_dir = os.path.join(api_dir, tree, "html")
        if not os.path.isfile(os.path.join(html_dir, "index.html")):
            raise PluginError(
                f"generated API reference not found in '{html_dir}'. Generate it first: "
                "cmake -S . -B build/docs -DOPENTLV_BUILD_DOCS=ON -DOPENTLV_BUILD_CXX=OFF "
                "-DOPENTLV_BUILD_TESTS=OFF -DOPENTLV_BUILD_EXAMPLES=OFF && "
                f"cmake --build build/docs --target cxx-api-docs (or set {API_DIR_ENV})"
            )
        for root, _dirs, names in os.walk(html_dir):
            for name in sorted(names):
                rel = os.path.relpath(os.path.join(root, name), html_dir).replace(os.sep, "/")
                files.append(
                    File.generated(
                        config,
                        f"{API_SITE_PREFIX}/{tree}/html/{rel}",
                        abs_src_path=os.path.abspath(os.path.join(root, name)),
                    )
                )
    add_wasm_files(files, config)
    return files


def add_wasm_files(files, config):
    wasm_dir = os.environ.get(WASM_DIR_ENV, WASM_DIR_DEFAULT)
    missing = [name for name in WASM_FILES if not os.path.isfile(os.path.join(wasm_dir, name))]
    if missing:
        message = (
            f"WebAssembly module files {', '.join(missing)} not found in '{wasm_dir}'; the playground "
            "will be unavailable. Build them as described in docs/development/webassembly.md "
            f"(or set {WASM_DIR_ENV})."
        )
        if os.environ.get(WASM_REQUIRE_ENV) == "1":
            raise PluginError(message)
        log.info(message)
        return
    for name in WASM_FILES:
        files.append(
            File.generated(
                config,
                f"{WASM_SITE_PREFIX}/{name}",
                abs_src_path=os.path.abspath(os.path.join(wasm_dir, name)),
            )
        )


def on_page_markdown(markdown, page, config, files):
    page_dir = posixpath.dirname(page.file.src_uri)

    def rewrite(match):
        prefix, target, suffix = match.groups()
        if re.match(r"^([a-z][a-z0-9+.-]*:|#|/)", target, re.IGNORECASE):
            return match.group(0)
        path, sep, fragment = target.partition("#")
        resolved = posixpath.normpath(posixpath.join(page_dir, path))
        if resolved == "README.md":
            return f"{prefix}{posixpath.relpath('index.md', page_dir or '.')}{sep}{fragment}{suffix}"
        if not resolved.startswith(".."):
            return match.group(0)
        repo_path = posixpath.normpath(posixpath.join("docs", resolved))
        if not os.path.exists(repo_path):
            # A warning fails the strict build, like a broken link inside docs/.
            log.warning("%s: link to '%s' does not exist in the repository", page.file.src_uri, target)
        kind = "tree" if os.path.isdir(repo_path) else "blob"
        return f"{prefix}{REPO_URL}/{kind}/{REF}/{repo_path}{sep}{fragment}{suffix}"

    return LINK.sub(rewrite, markdown)
