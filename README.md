# CipherMail

PGP Encryption for Gmail - A Chrome Extension

## Features

- **Encrypt Emails**: Secure your emails with OpenPGP encryption
- **Decrypt Emails**: Read encrypted emails directly in Gmail
- **Sign Messages**: Digitally sign your emails for authenticity
- **Verify Signatures**: Automatically verify signatures on received messages
- **Key Server Lookup**: Search for recipient public keys on HKP servers
- **Key Management**: Generate, export, import, and rotate your PGP keys
- **Secure Storage**: Your private keys are encrypted with AES-256-GCM

## Security

- RSA-4096 bit key generation
- AES-256-GCM encryption for local key storage
- PBKDF2 with 310,000 iterations for key derivation
- Brute-force protection (5 attempts = 30 min lockout)
- Passphrase strength validation
- Automatic clipboard clearing
- Session timeout
- Origin validation on all message handlers
- Message length limits to prevent DoS
- XSS prevention with proper HTML escaping
- Settings input sanitization

## Installation

### From Source

1. Clone the repository
2. Run `npm install`
3. Run `npm run build`
4. Open Chrome and go to `chrome://extensions/`
5. Enable "Developer mode"
6. Click "Load unpacked"
7. Select the `dist` folder

### Development

```bash
npm install
npm run build
npm test
```

## Usage

### Generate Your Keys

1. Click the CipherMail icon in the toolbar
2. Go to the "Keys" tab
3. Click "Generate New Keys"
4. Enter your name, email, and a strong passphrase
5. Save your public key - share it with others

### Import Recipient's Key

1. Click the CipherMail icon
2. Go to the "Keys" tab
3. Paste the recipient's public key OR
4. Use "Key Server Lookup" to search by email

### Encrypt a Message

1. Compose a new email in Gmail
2. Click the "Encrypt" button in the toolbar
3. Enter your passphrase
4. The message will be encrypted

### Decrypt a Message

1. Open an encrypted email
2. Click the "Decrypt" button
3. Enter your passphrase
4. The message will be decrypted and displayed

### Keyboard Shortcuts

- `Ctrl+Shift+E` - Encrypt message
- `Ctrl+Shift+D` - Decrypt message
- `Ctrl+Shift+S` - Sign message

## Settings

### Compose Tab

- **Sign messages by default**: Automatically sign when encrypting
- **Auto-lookup recipient keys**: Automatically search for recipient keys when composing
- **Confirm before encrypting**: Show confirmation dialog

### Security Tab

- **Session timeout**: Auto-lock after inactivity
- **Secure clipboard**: Auto-clear clipboard after copying

## Browser Support

- Google Chrome 109+
- Microsoft Edge 109+
- Mozilla Firefox 109+
- Chromium-based browsers

## Privacy

CipherMail is a client-side only extension. Your private keys and passphrases never leave your browser. All cryptographic operations are performed locally.

## License

MIT

## Contributing

Contributions welcome! Please submit pull requests or open issues on GitHub.