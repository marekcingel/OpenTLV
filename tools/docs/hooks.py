"""MkDocs hook: adapt relative links for the site.

Links that leave docs/ point at the GitHub repository, and links to the GitHub
index docs/README.md point at the site landing page docs/index.md.
"""

import logging
import os
import posixpath
import re

log = logging.getLogger("mkdocs.hooks.opentlv")

REPO_URL = "https://github.com/marekcingel/OpenTLV"
BRANCH = "main"

# Inline Markdown links: [text](target). Image links are left alone.
LINK = re.compile(r"(?<!!)(\[[^\]]*\]\()([^)\s]+)(\))")


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
        return f"{prefix}{REPO_URL}/{kind}/{BRANCH}/{repo_path}{sep}{fragment}{suffix}"

    return LINK.sub(rewrite, markdown)
