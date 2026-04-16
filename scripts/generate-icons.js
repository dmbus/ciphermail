const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const sizes = [16, 32, 48, 128, 256];
const iconsDir = path.join(__dirname, '..', 'icons');

const svgIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#4285f4"/>
      <stop offset="100%" style="stop-color:#1a73e8"/>
    </linearGradient>
  </defs>
  <rect width="128" height="128" rx="24" fill="url(#bg)"/>
  <g fill="none" stroke="#ffffff" stroke-width="5" stroke-linecap="round" stroke-linejoin="round">
    <rect x="30" y="55" width="68" height="50" rx="5"/>
    <path d="M44 55 V 40 A 20 20 0 0 1 84 40 V 55"/>
    <circle cx="64" cy="80" r="8" fill="#ffffff"/>
    <line x1="64" y1="88" x2="64" y2="100"/>
  </g>
</svg>`;

async function generateIcons() {
    console.log('Generating icons...\n');

    if (!fs.existsSync(iconsDir)) {
        fs.mkdirSync(iconsDir, { recursive: true });
    }

    for (const size of sizes) {
        const outputPath = path.join(iconsDir, `icon-${size}.png`);
        await sharp(Buffer.from(svgIcon))
            .resize(size, size)
            .png()
            .toFile(outputPath);
        console.log(`Generated: icon-${size}.png`);
    }

    const defaultPath = path.join(iconsDir, 'icon.png');
    await sharp(Buffer.from(svgIcon))
        .resize(128, 128)
        .png()
        .toFile(defaultPath);
    console.log('Generated: icon.png (128x128)\n');

    const svgPath = path.join(iconsDir, 'icon.svg');
    fs.writeFileSync(svgPath, svgIcon);
    console.log('Generated: icon.svg\n');

    console.log('Icon generation complete!');
}

generateIcons().catch(console.error);