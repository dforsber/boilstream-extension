PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=boilstream
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile

# Community CI invokes make directly, not build-wasm-fixed.sh. The platform and
# Rust std configuration must therefore be identical on both paths.
ifneq ($(filter wasm_eh wasm_threads wasm_mvp,$(MAKECMDGOALS)),)
export WASM_BUILD_TYPE := $(firstword $(filter wasm_eh wasm_threads wasm_mvp,$(MAKECMDGOALS)))
endif
.PHONY: boilstream_wasm_toolchain
wasm_pre_build_step: boilstream_wasm_toolchain
boilstream_wasm_toolchain:
	bash scripts/prepare-wasm-toolchain.sh "$(WASM_BUILD_TYPE)"

# The shared recipe selects src/.*/ and silently misses our flat src/*.cpp.
# Override it with a coverage-checked scan of every extension translation unit.
tidy-check:
	mkdir -p ./build/tidy
	cmake $(GENERATOR) $(BUILD_FLAGS) $(EXT_DEBUG_FLAGS) -DDISABLE_UNITY=1 -DCLANG_TIDY=1 -S $(DUCKDB_SRCDIR) -B build/tidy
	cp duckdb/.clang-tidy build/tidy/.clang-tidy
	python3 scripts/check-tidy.py build/tidy ${TIDY_THREAD_PARAMETER} ${TIDY_BINARY_PARAMETER} ${TIDY_PERFORM_CHECKS}
