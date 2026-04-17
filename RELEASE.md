# CipherMail v1.1.0 - Security Hardening Release

## What's New

This release focuses on security hardening and addresses several vulnerabilities identified during security audit.

## Security Improvements

### Origin Validation
All message handlers now validate that requests originate from `mail.google.com`. Previously, only sensitive operations (encrypt/decrypt/sign) were validated.

### Message Length Limits
Added validation to prevent denial-of-service attacks via oversized messages:
- Maximum 100KB for plaintext messages
- Maximum 50KB for encrypted PGP blocks

### XSS Prevention
- Algorithm fields in key information display are now properly escaped
- All user-derived data uses `textContent` or `escapeHtml()` before DOM insertion

### Clipboard Security
Clipboard clearing now provides feedback when it fails (e.g., due to browser security restrictions)

### Passphrase Handling
- Added `autocomplete="off"` to prevent browser password manager interference
- Input values cleared immediately after passphrase submission

### Settings Security
`SETTINGS_UPDATED` messages now:
- Validate origin before processing
- Use a whitelist of allowed settings keys to prevent prototype pollution

## Bug Fixes
- Fixed missing `build:watch` script reference in documentation
- Fixed several console errors in content script tests

## Testing
All 56 tests pass, including security-focused tests for:
- Passphrase validation
- AES-GCM encryption with PBKDF2
- XSS prevention patterns
- Origin validation
- TOFU trust model

## Installation

### From Source
```bash
npm install
npm run build
# Load dist/ folder in Chrome (Developer mode)
```

### Update
```bash
git pull
npm install
npm run build
```

## Full Changelog

See [CHANGELOG.md](CHANGELOG.md) for complete release history.