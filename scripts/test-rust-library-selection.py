#!/usr/bin/env python3
"""Configure the real extension CMake with offline dependency/build adapters.

No Rust compilation or dependency download occurs. Assertions inspect the real
alias and link targets, not the spelling of the CMake selection branch.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RustLibrarySelection(unittest.TestCase):
    def configure(self, selection):
        with tempfile.TemporaryDirectory(prefix="boilstream-rust-selection-") as directory:
            source = Path(directory)
            modules = source / "modules"
            modules.mkdir()
            # Intercept only external Corrosion discovery. The extension's real
            # CMakeLists and all its conditionals/target_link_libraries still run.
            (modules / "FetchContent.cmake").write_text('''
function(FetchContent_Declare name)
  if(NOT name STREQUAL "Corrosion")
    message(FATAL_ERROR "unexpected external dependency: ${name}")
  endif()
endfunction()
function(FetchContent_MakeAvailable name)
  set_property(GLOBAL APPEND PROPERTY SELECTION_DISCOVERY "${name}")
endfunction()
function(corrosion_import_crate)
  cmake_parse_arguments(COR "LOCKED" "MANIFEST_PATH" "" ${ARGN})
  if(NOT COR_LOCKED OR NOT COR_MANIFEST_PATH STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}/opaque-client/Cargo.toml")
    message(FATAL_ERROR "standalone crate must use its locked client manifest")
  endif()
  set_property(GLOBAL APPEND PROPERTY SELECTION_IMPORTS "opaque-client")
  add_library(opaque_client-static STATIC IMPORTED GLOBAL)
  set_property(TARGET opaque_client-static PROPERTY IMPORTED_LOCATION "${CMAKE_BINARY_DIR}/libopaque_client.a")
endfunction()
''')
            (source / "empty.cpp").write_text("// Configure-only fixture; never compiled.\n")
            setup = ""
            if selection == "external":
                setup = '''
add_library(rust_bridge-static STATIC IMPORTED GLOBAL)
set_property(TARGET rust_bridge-static PROPERTY IMPORTED_LOCATION "${CMAKE_BINARY_DIR}/librust_bridge.a")
set(BOILSTREAM_EXTERNAL_RUST_LIB rust_bridge-static)
'''
            elif selection == "invalid":
                setup = "set(BOILSTREAM_EXTERNAL_RUST_LIB missing-rust-target)\n"
            expected = "rust_bridge-static" if selection == "external" else "opaque_client-static"
            (source / "CMakeLists.txt").write_text(f'''
cmake_minimum_required(VERSION 3.15)
project(rust_selection C CXX)
list(PREPEND CMAKE_MODULE_PATH "{modules.as_posix()}")
set(DUCKDB_EXPORT_SET selection)
set(INSTALL_LIB_DIR lib)
set(FIXTURE_SOURCE "{source.as_posix()}/empty.cpp")
function(build_static_extension name)
  add_library(${{name}}_extension STATIC "${{FIXTURE_SOURCE}}")
endfunction()
function(build_loadable_extension name)
  add_library(${{name}}_loadable_extension MODULE "${{FIXTURE_SOURCE}}")
endfunction()
{setup}
add_subdirectory("{ROOT.as_posix()}" extension)
get_target_property(actual opaque_client_rust ALIASED_TARGET)
if(NOT actual STREQUAL "{expected}")
  message(FATAL_ERROR "Rust target selection: expected {expected}, got '${{actual}}'")
endif()
foreach(target boilstream_extension boilstream_loadable_extension)
  get_target_property(links ${{target}} LINK_LIBRARIES)
  if(NOT "opaque_client_rust" IN_LIST links)
    message(FATAL_ERROR "${{target}} lost its selected Rust library")
  endif()
endforeach()
get_property(imports GLOBAL PROPERTY SELECTION_IMPORTS)
get_property(discovery GLOBAL PROPERTY SELECTION_DISCOVERY)
if("{selection}" STREQUAL "external")
  if(imports OR discovery OR TARGET opaque_client-static)
    message(FATAL_ERROR "external Rust target must skip standalone Corrosion import")
  endif()
else()
  if(NOT imports STREQUAL "opaque-client" OR NOT discovery STREQUAL "Corrosion")
    message(FATAL_ERROR "standalone Rust target must import exactly one locked client crate")
  endif()
endif()
message(STATUS "RUST_SELECTION_PASS {selection}")
''')
            env = os.environ.copy()
            # Host/WASM cross-build settings must not alter this native fixture.
            for key in ("OSX_BUILD_ARCH", "WASM_BUILD_TYPE", "CMAKE_TOOLCHAIN_FILE"):
                env.pop(key, None)
            return subprocess.run(
                ["cmake", "-S", str(source), "-B", str(source / "build")],
                env=env, text=True, capture_output=True, timeout=45,
            )

    def test_external_target_skips_standalone_rust(self):
        result = self.configure("external")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RUST_SELECTION_PASS external", result.stdout)

    def test_standalone_still_imports_locked_client(self):
        result = self.configure("standalone")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RUST_SELECTION_PASS standalone", result.stdout)

    def test_invalid_external_target_fails_instead_of_falling_back(self):
        result = self.configure("invalid")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("missing-rust-target", result.stdout + result.stderr)
        self.assertNotIn("RUST_SELECTION_PASS", result.stdout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=ROOT,
                        help="extension source checkout (for actual-source negative controls)")
    options, remaining = parser.parse_known_args()
    ROOT = options.source.resolve()
    unittest.main(argv=[__file__, *remaining])
