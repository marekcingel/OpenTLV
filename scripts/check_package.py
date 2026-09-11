"""Generate and verify fresh Release archives against the canonical installation."""

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*args):
    subprocess.run(args, check=True)


def read_cache(build):
    values = {}
    for line in (build / "CMakeCache.txt").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith(("#", "//")) and "=" in line:
            key, value = line.split("=", 1)
            values[key.split(":", 1)[0]] = value
    return values


def compiler_settings(build, cache, language):
    version = ".".join(cache[f"CMAKE_CACHE_{part}_VERSION"] for part in ("MAJOR", "MINOR", "PATCH"))
    path = build / "CMakeFiles" / version / f"CMake{language}Compiler.cmake"
    require(path.is_file(), f"Missing compiler metadata: {path}")
    text = path.read_text(encoding="utf-8")
    result = {}
    for suffix in ("COMPILER", "COMPILER_ARG1", "COMPILER_ID", "COMPILER_VERSION"):
        key = f"CMAKE_{language}_{suffix}"
        match = re.search(r'set\(' + key + r' "([^"\n]*)"\)', text)
        require(match is not None, f"Missing {key} in {path}")
        result[key] = match.group(1)
    return result


def manifest(root):
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*") if path.is_file()
    }


def compare_manifests(expected, actual):
    differences = []
    for label, paths in (
        ("Missing", expected.keys() - actual.keys()),
        ("Unexpected", actual.keys() - expected.keys()),
        ("Different content", {p for p in expected.keys() & actual.keys() if expected[p] != actual[p]}),
    ):
        differences.extend(f"  {label}: {path}" for path in sorted(paths))
    require(not differences, "Archive differs from cmake --install:\n" + "\n".join(differences))


def install_dir(cache, key):
    path = Path(cache[key])
    require(not path.is_absolute() and ".." not in path.parts,
            f"{key} must be relative and stay inside the installation prefix: {path}")
    return path.as_posix()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--cxx", choices=("ON", "OFF"), default="ON")
    args = parser.parse_args()
    build = args.build.resolve()
    cache = read_cache(build)
    languages = ("C", "CXX") if args.cxx == "ON" else ("C",)
    compilers = {lang: compiler_settings(build, cache, lang) for lang in languages}
    includedir = install_dir(cache, "CMAKE_INSTALL_INCLUDEDIR")
    libdir = install_dir(cache, "CMAKE_INSTALL_LIBDIR")
    datarootdir = install_dir(cache, "CMAKE_INSTALL_DATAROOTDIR")
    work = Path(tempfile.mkdtemp(prefix="package-check-", dir=build))
    prefix = work / "installed"
    run("cmake", "--install", str(build), "--config", "Release", "--prefix", str(prefix))
    # Only inspect output from this invocation, never older build/packages files.
    fresh = work / "packages"
    run("cpack", "--config", str(build / "CPackConfig.cmake"), "-C", "Release", "-B", str(fresh))
    archives = sorted(fresh.glob("*.zip")) + sorted(fresh.glob("*.tar.gz"))
    require(archives, f"CPack produced no ZIP/TGZ archives in {fresh}")
    expected = manifest(prefix)
    for index, archive in enumerate(archives):
        extracted = work / f"archive-{index}"
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as package:
                package.extractall(extracted)
        else:
            with tarfile.open(archive) as package:
                package.extractall(extracted, filter="data")
        roots = list(extracted.iterdir())
        require(len(roots) == 1 and roots[0].is_dir(), "Expected one package root")
        root = roots[0]
        files = manifest(root)
        compare_manifests(expected, files)
        package_dir = root / libdir / "cmake/OpenTLV"
        for path in (
            f"{includedir}/tlv/tlv.h", f"{includedir}/tlv/config.h",
            f"{includedir}/tlv/version.h", f"{datarootdir}/doc/OpenTLV/LICENSE",
            f"{libdir}/cmake/OpenTLV/OpenTLVConfig.cmake",
            f"{libdir}/cmake/OpenTLV/OpenTLVConfigVersion.cmake",
            f"{libdir}/cmake/OpenTLV/OpenTLVTargets.cmake",
        ):
            require(path in files, f"Required installed file missing: {path}")
        require(any(p.endswith((".a", ".lib", ".so", ".dll", ".dylib")) for p in files),
                "No library artifact in archive")
        require((f"{includedir}/tlv++/tlv.hpp" in files) == (args.cxx == "ON"),
                f"C++ headers do not match --cxx {args.cxx}")
        unwanted = sorted(p for p in files if "gtest" in p or "benchmark" in p)
        require(not unwanted, "Unexpected test/benchmark files: " + ", ".join(unwanted))
        for path in root.rglob("*.cmake"):
            text = path.read_text(encoding="utf-8").replace("\\", "/")
            for original in (cache["CMAKE_HOME_DIRECTORY"], build.as_posix()):
                require(original.replace("\\", "/") not in text, f"Non-relocatable export: {path}")
        consumer = work / f"consumer-{index}"
        consumer.mkdir()
        (consumer / "main.c").write_text(
            '#include <tlv/tlv.h>\n#include <tlv/version.h>\n'
            'int main(void) { return tlv_version_string() == 0; }\n', encoding="utf-8")
        cmake = '''cmake_minimum_required(VERSION 3.16)
project(package_consumer LANGUAGES @LANGUAGES@)
find_package(OpenTLV CONFIG REQUIRED PATHS "${EXPECTED_PACKAGE_DIR}" NO_DEFAULT_PATH)
get_filename_component(actual_config "${OpenTLV_CONFIG}" REALPATH)
get_filename_component(expected_config "${EXPECTED_PACKAGE_DIR}/OpenTLVConfig.cmake" REALPATH)
if(NOT actual_config STREQUAL expected_config)
    message(FATAL_ERROR "Wrong OpenTLV package: ${actual_config}; expected ${expected_config}")
endif()
enable_testing()
add_executable(consumer main.c)
target_link_libraries(consumer PRIVATE OpenTLV::tlv)
add_test(NAME consumer COMMAND consumer)
'''.replace("@LANGUAGES@", " ".join(languages))
        if args.cxx == "ON":
            (consumer / "main.cpp").write_text(
                '#include <tlv++/tlv.hpp>\n#include <tlv/version.h>\n'
                'int main() { return tlv_version_string() == nullptr; }\n', encoding="utf-8")
            cmake += '''add_executable(consumer_cpp main.cpp)
target_link_libraries(consumer_cpp PRIVATE OpenTLV::tlvpp)
add_test(NAME consumer_cpp COMMAND consumer_cpp)
'''
        else:
            cmake += 'if(TARGET OpenTLV::tlvpp)\nmessage(FATAL_ERROR "Unexpected C++ target")\nendif()\n'
        (consumer / "CMakeLists.txt").write_text(cmake, encoding="utf-8")
        configure = ["cmake", "-S", str(consumer), "-B", str(consumer / "build"),
                     "-G", cache["CMAKE_GENERATOR"], f"-DEXPECTED_PACKAGE_DIR={package_dir.as_posix()}",
                     f"-DOpenTLV_DIR={package_dir.as_posix()}", "-DCMAKE_BUILD_TYPE=Release"]
        for key in ("CMAKE_GENERATOR_PLATFORM", "CMAKE_GENERATOR_TOOLSET", "CMAKE_GENERATOR_INSTANCE",
                    "CMAKE_TOOLCHAIN_FILE", "CMAKE_MAKE_PROGRAM", "CMAKE_SYSROOT", "CMAKE_OSX_ARCHITECTURES"):
            if cache.get(key):
                configure.append(f"-D{key}={cache[key]}")
        for language, settings in compilers.items():
            for suffix in ("COMPILER", "COMPILER_ARG1"):
                key = f"CMAKE_{language}_{suffix}"
                if settings[key]:
                    configure.append(f"-D{key}={settings[key]}")
            target_key = f"CMAKE_{language}_COMPILER_TARGET"
            if cache.get(target_key):
                configure.append(f"-D{target_key}={cache[target_key]}")
        run(*configure)
        consumer_cache = read_cache(consumer / "build")
        for language, settings in compilers.items():
            actual = compiler_settings(consumer / "build", consumer_cache, language)
            require(actual == settings, f"{language} compiler mismatch: expected {settings}, got {actual}")
        run("cmake", "--build", str(consumer / "build"), "--config", "Release")
        run("ctest", "--test-dir", str(consumer / "build"), "-C", "Release", "--output-on-failure")
        print(f"Verified {archive.name}: {len(files)} installed files and standalone consumer", flush=True)
    # Publish only after every freshly generated archive passes verification.
    output = build / "packages"
    output.mkdir(exist_ok=True)
    for archive in archives:
        shutil.copy2(archive, output / archive.name)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"Package verification failed: {error}", file=sys.stderr)
        sys.exit(1)
