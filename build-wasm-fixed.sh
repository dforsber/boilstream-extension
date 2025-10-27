#!/bin/bash
set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Building Boilstream WASM Extension                       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Ensure Emscripten 3.1.71 is active
echo "→ Activating Emscripten 3.1.71..."
source ~/emsdk/emsdk_env.sh
EMCC_VERSION=$(emcc --version | head -1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
if [ "$EMCC_VERSION" != "3.1.71" ]; then
    echo "⚠️  Wrong Emscripten version: $EMCC_VERSION (expected 3.1.71)"
    echo "   Installing correct version..."
    cd ~/emsdk
    ./emsdk install 3.1.71
    ./emsdk activate 3.1.71
    source ~/emsdk/emsdk_env.sh
    cd - > /dev/null
fi
echo "✓ Using Emscripten $EMCC_VERSION"
echo ""

# Clean old build
rm -rf build/wasm_eh
echo "→ Cleaned old build"

# Set build type
export WASM_BUILD_TYPE=wasm_eh
echo "→ Building for: $WASM_BUILD_TYPE"
echo ""

# Build and monitor for the .wasm file creation
echo "→ Running make wasm_eh (will fail at wasm-opt step, but that's OK)..."

# Run make in background and monitor for file creation
(make wasm_eh 2>&1 || true) | while IFS= read -r line; do
    echo "$line"

    # When we see the linking message, check if file exists
    if echo "$line" | grep -q "Linking.*boilstream.duckdb_extension"; then
        sleep 0.5  # Give it a moment to finish writing
        if [ -f "build/wasm_eh/extension/boilstream/boilstream.duckdb_extension.wasm" ]; then
            echo ""
            echo "✓ Extension file created, saving before wasm-opt cleanup..."
            mkdir -p /tmp/boilstream_backup
            cp build/wasm_eh/extension/boilstream/boilstream.duckdb_extension.wasm /tmp/boilstream_backup/
            echo "✓ Saved to /tmp/boilstream_backup/"
        fi
    fi
done

# Restore the file if it was deleted by the failed wasm-opt step
if [ ! -f "build/wasm_eh/extension/boilstream/boilstream.duckdb_extension.wasm" ]; then
    if [ -f "/tmp/boilstream_backup/boilstream.duckdb_extension.wasm" ]; then
        echo ""
        echo "→ Restoring extension file (it was deleted by failed wasm-opt)..."
        mkdir -p build/wasm_eh/extension/boilstream
        cp /tmp/boilstream_backup/boilstream.duckdb_extension.wasm build/wasm_eh/extension/boilstream/
        echo "✓ File restored"
    else
        echo "❌ Build failed - extension file was never created"
        exit 1
    fi
fi

echo ""
echo "→ Appending extension metadata..."

# Make sure we're working with the original file (no previous metadata)
if [ -f "/tmp/boilstream_backup/boilstream.duckdb_extension.wasm" ]; then
    echo "→ Using clean backup file from build..."
    cp /tmp/boilstream_backup/boilstream.duckdb_extension.wasm build/wasm_eh/extension/boilstream/boilstream.duckdb_extension.wasm
fi

# Run from /tmp to avoid CMake cache issues
PROJ_DIR="$(pwd)"
cd /tmp
cmake -DMETA1="4" \
  -DABI_TYPE="CPP" \
  -DEXTENSION="$PROJ_DIR/build/wasm_eh/extension/boilstream/boilstream.duckdb_extension.wasm" \
  -DPLATFORM_FILE="$PROJ_DIR/build/wasm_eh/duckdb_platform_out" \
  -DVERSION_FIELD="v1.4.0" \
  -DEXTENSION_VERSION="ecfbd24" \
  -DNULL_FILE="$PROJ_DIR/duckdb/scripts/null.txt" \
  -P "$PROJ_DIR/duckdb/scripts/append_metadata.cmake"
cd "$PROJ_DIR"

echo "✓ Metadata appended"
echo ""
echo "→ Copying extension to repository location..."

# Ensure repository directory exists
mkdir -p build/wasm_eh/repository/v1.4.0/wasm_eh

# Copy extension
cp build/wasm_eh/extension/boilstream/boilstream.duckdb_extension.wasm \
   build/wasm_eh/repository/v1.4.0/wasm_eh/

# Show file info
echo ""
echo "✓ Extension built successfully:"
ls -lh build/wasm_eh/repository/v1.4.0/wasm_eh/boilstream.duckdb_extension.wasm
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Build Complete                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "To test:"
echo "  cd test/wasm"
echo "  npm run serve"
echo "  Open: http://localhost:8080/test-wasm-browser.html"
echo ""
