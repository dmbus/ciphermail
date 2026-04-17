# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - Security Hardening Release

### Security
- **Extended origin validation**: All message handlers now validate that requests originate from Gmail. Previously only sensitive operations (encrypt/decrypt/sign) were validated.
- **Message length limits**: Added validation to prevent DoS via oversized messages (100KB max for messages, 50KB max for encrypted blocks)
- **XSS prevention**: Algorithm fields now properly escaped when displaying key information
- **Clipboard error handling**: Failed clipboard clearing now logs warning and notifies user
- **Passphrase input hardening**: Added `autocomplete="off"` to prevent browser password manager caching; input value cleared immediately after submission
- **Settings whitelist**: `SETTINGS_UPDATED` handler now validates origin and only accepts known settings keys to prevent prototype pollution

### Documentation
- Updated security documentation in README
- Added this changelog

## [1.0.0] - Initial Release

### Features
- RSA-4096 bit PGP key generation
- AES-256-GCM encrypted local key storage
- PBKDF2 key derivation (310,000 iterations)
- Encrypt/decrypt emails in Gmail
- Sign and verify messages
- Key server lookup (keys.openpgp.org, keyserver.ubuntu.com, pgpkeys.eu)
- Brute-force protection with exponential backoff
- Session timeout and auto-lock
- Automatic clipboard clearing
- Dark mode support
- Keyboard shortcuts (Ctrl+Shift+E/D/S)
- Firefox support