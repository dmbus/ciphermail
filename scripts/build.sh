#!/bin/bash

BUILD_DIR="dist"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$BUILD_DIR/background"
mkdir -p "$BUILD_DIR/content"
mkdir -p "$BUILD_DIR/popup"
mkdir -p "$BUILD_DIR/icons"
mkdir -p "$BUILD_DIR/libs"

cp manifest.json "$BUILD_DIR/"
cp -r content/* "$BUILD_DIR/content/"
cp -r popup/* "$BUILD_DIR/popup/"
cp -r libs/* "$BUILD_DIR/libs/"

for size in 16 32 48 128 256; do
    if [ -f "icons/icon-${size}.png" ]; then
        cp "icons/icon-${size}.png" "$BUILD_DIR/icons/"
    fi
done

if [ -f "icons/icon.svg" ]; then
    cp icons/icon.svg "$BUILD_DIR/icons/"
fi

if [ -f "icons/icon-128.png" ]; then
    cp icons/icon-128.png "$BUILD_DIR/icons/icon.png"
fi

cd "$BUILD_DIR"
find . -type f -name "*.js" -exec terser --compress --mangle -o {} {} \;
find . -type f -name "*.html" -exec html-minifier --collapse-whitespace --remove-comments -o {} {} \;

echo "Build complete in $BUILD_DIR/"