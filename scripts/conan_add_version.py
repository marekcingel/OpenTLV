#!/usr/bin/env python3
"""Add or update one version entry in a ConanCenter recipe's config.yml and
conandata.yml, used by .github/workflows/conan-publish.yml when opening the
conan-center-index pull request for a newly tagged OpenTLV release."""
import argparse
import pathlib

import yaml


def load(path: pathlib.Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def dump(path: pathlib.Path, data: dict) -> None:
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe-dir", required=True, type=pathlib.Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()

    config_path = args.recipe_dir / "config.yml"
    config = load(config_path)
    config.setdefault("versions", {})[args.version] = {"folder": "all"}
    dump(config_path, config)

    conandata_path = args.recipe_dir / "all" / "conandata.yml"
    conandata = load(conandata_path)
    conandata.setdefault("sources", {})[args.version] = {
        "url": args.url,
        "sha256": args.sha256,
    }
    dump(conandata_path, conandata)


if __name__ == "__main__":
    main()
