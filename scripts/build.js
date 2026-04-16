const fs = require('fs');
const path = require('path');

const BUILD_DIR = path.join(__dirname, '..', 'dist');

function copyFile(from, to) {
    const destDir = path.dirname(to);
    if (!fs.existsSync(destDir)) {
        fs.mkdirSync(destDir, { recursive: true });
    }
    fs.copyFileSync(from, to);
    console.log(`Copied: ${from} -> ${to}`);
}

function copyDir(from, to) {
    if (!fs.existsSync(to)) {
        fs.mkdirSync(to, { recursive: true });
    }
    const entries = fs.readdirSync(from, { withFileTypes: true });
    for (const entry of entries) {
        const srcPath = path.join(from, entry.name);
        const destPath = path.join(to, entry.name);
        if (entry.isDirectory()) {
            copyDir(srcPath, destPath);
        } else {
            copyFile(srcPath, destPath);
        }
    }
}

function buildBackground() {
    const backgroundPath = path.join(BUILD_DIR, 'background', 'background.js');
    const openpgpPath = path.join(BUILD_DIR, 'libs', 'openpgp.min.js');

    let background = fs.readFileSync(backgroundPath, 'utf8');
    const openpgp = fs.readFileSync(openpgpPath, 'utf8');

    background = background.replace(/importScripts\(['"]\.\.\/libs\/openpgp\.min\.js['"]\);?/, `/* OpenPGP.js bundled */\n${openpgp}`);

    fs.writeFileSync(backgroundPath, background);
    console.log('Bundled openpgp into background.js');
}

function build() {
    console.log('Starting CipherMail build...\n');

    if (fs.existsSync(BUILD_DIR)) {
        fs.rmSync(BUILD_DIR, { recursive: true });
    }

    fs.mkdirSync(BUILD_DIR, { recursive: true });
    fs.mkdirSync(path.join(BUILD_DIR, 'background'), { recursive: true });
    fs.mkdirSync(path.join(BUILD_DIR, 'content'), { recursive: true });
    fs.mkdirSync(path.join(BUILD_DIR, 'popup'), { recursive: true });
    fs.mkdirSync(path.join(BUILD_DIR, 'icons'), { recursive: true });
    fs.mkdirSync(path.join(BUILD_DIR, 'libs'), { recursive: true });

    copyFile('manifest.json', path.join(BUILD_DIR, 'manifest.json'));

    copyDir('background', path.join(BUILD_DIR, 'background'));
    copyDir('content', path.join(BUILD_DIR, 'content'));
    copyDir('popup', path.join(BUILD_DIR, 'popup'));
    copyDir('libs', path.join(BUILD_DIR, 'libs'));
    copyDir('icons', path.join(BUILD_DIR, 'icons'));

    buildBackground();

    console.log('\nBuild complete! Output in dist/');
    console.log('To load in Chrome:');
    console.log('1. Go to chrome://extensions/');
    console.log('2. Enable "Developer mode"');
    console.log('3. Click "Load unpacked"');
    console.log('4. Select the "dist" folder');
}

build();