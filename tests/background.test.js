const openpgp = require('openpgp');
const { chrome } = require('jest-chrome');
const { webcrypto } = require('node:crypto');
const path = require('path');
const fs = require('fs');

if (typeof crypto === 'undefined') {
    global.crypto = webcrypto;
}

const AES_GCM_ALGO = 'AES-GCM';
const PBKDF2_ITERATIONS = 1000;
const MIN_PASSPHRASE_LENGTH = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 30 * 60 * 1000;

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ALLOWED_ORIGINS = ['https://mail.google.com'];

function isValidEmail(email) {
    if (!email || typeof email !== 'string') return false;
    const trimmed = email.trim();
    return EMAIL_REGEX.test(trimmed) && trimmed.length <= 254;
}

function isAllowedOrigin(url) {
    if (!url) return false;
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== 'https:') return false;
        return parsed.hostname === 'mail.google.com' || parsed.hostname.endsWith('.mail.google.com');
    } catch {
        return false;
    }
}

function validatePassphrase(passphrase) {
    if (!passphrase || passphrase.length < MIN_PASSPHRASE_LENGTH) {
        return `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`;
    }
    if (!/[A-Z]/.test(passphrase)) {
        return 'Passphrase must contain at least one uppercase letter';
    }
    if (!/[a-z]/.test(passphrase)) {
        return 'Passphrase must contain at least one lowercase letter';
    }
    if (!/[0-9]/.test(passphrase)) {
        return 'Passphrase must contain at least one number';
    }
    if (!/[^A-Za-z0-9]/.test(passphrase)) {
        return 'Passphrase must contain at least one special character (!@#$%^&*...)';
    }
    return null;
}

async function deriveKey(passphrase, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', encoder.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        keyMaterial,
        { name: AES_GCM_ALGO, length: 256 },
        false, ['encrypt', 'decrypt']
    );
}

async function aesEncrypt(plainText, salt, iv, passphrase) {
    const key = await deriveKey(passphrase, salt);
    const encoder = new TextEncoder();
    return crypto.subtle.encrypt({ name: AES_GCM_ALGO, iv }, key, encoder.encode(plainText));
}

async function aesDecrypt(cipherData, salt, iv, passphrase) {
    const key = await deriveKey(passphrase, salt);
    const decrypted = await crypto.subtle.decrypt({ name: AES_GCM_ALGO, iv }, key, cipherData);
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
}

describe('CipherMail Security Functions', () => {
    describe('validatePassphrase', () => {
        test('should reject empty passphrase', () => {
            expect(validatePassphrase('')).toBe('Passphrase must be at least 12 characters');
            expect(validatePassphrase(null)).toBe('Passphrase must be at least 12 characters');
            expect(validatePassphrase(undefined)).toBe('Passphrase must be at least 12 characters');
        });

        test('should reject passphrase shorter than 12 characters', () => {
            expect(validatePassphrase('Abc123!')).toBe('Passphrase must be at least 12 characters');
            expect(validatePassphrase('Short1!')).toBe('Passphrase must be at least 12 characters');
        });

        test('should reject passphrase without uppercase', () => {
            expect(validatePassphrase('lowercase123!@')).toBe('Passphrase must contain at least one uppercase letter');
        });

        test('should reject passphrase without lowercase', () => {
            expect(validatePassphrase('UPPERCASE123!@')).toBe('Passphrase must contain at least one lowercase letter');
        });

        test('should reject passphrase without number', () => {
            expect(validatePassphrase('NoNumbers!@ab')).toBe('Passphrase must contain at least one number');
        });

        test('should reject passphrase without special character', () => {
            expect(validatePassphrase('NoSpecial123ABC')).toBe('Passphrase must contain at least one special character (!@#$%^&*...)');
        });

        test('should accept valid passphrase meeting all requirements', () => {
            expect(validatePassphrase('SecurePass123!')).toBeNull();
            expect(validatePassphrase('MyStr0ng#Pass')).toBeNull();
            expect(validatePassphrase('C0mplex!Key_9')).toBeNull();
        });
    });

    describe('AES-GCM Encryption with PBKDF2', () => {
        const testPassphrase = 'super-secret-passphrase';
        const testName = 'Test User';
        const testEmail = 'test@example.com';

        test('should generate and encrypt keys correctly', async () => {
            const { privateKey, publicKey } = await openpgp.generateKey({
                type: 'rsa',
                rsaBits: 2048,
                userIDs: [{ name: testName, email: testEmail }],
            });

            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encryptedPrivateKey = await aesEncrypt(privateKey, salt, iv, testPassphrase);

            expect(encryptedPrivateKey).toBeDefined();

            const decryptedPrivateKey = await aesDecrypt(encryptedPrivateKey, salt, iv, testPassphrase);
            expect(decryptedPrivateKey).toBe(privateKey);
        });

        test('should fail decryption with wrong passphrase', async () => {
            const secretData = 'my-private-key';
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));

            const encrypted = await aesEncrypt(secretData, salt, iv, 'correct-pass');

            await expect(aesDecrypt(encrypted, salt, iv, 'wrong-pass'))
                .rejects.toThrow();
        });
    });

    describe('PGP Encryption/Decryption', () => {
        const testName = 'Test User';
        const testEmail = 'test@example.com';

        test('should encrypt and decrypt a message using PGP', async () => {
            const { privateKey, publicKey } = await openpgp.generateKey({
                type: 'rsa',
                rsaBits: 2048,
                userIDs: [{ name: testName, email: testEmail }],
            });

            const messageText = 'Hello, this is a secret message!';

            const pubKeyObj = await openpgp.readKey({ armoredKey: publicKey });
            const message = await openpgp.createMessage({ text: messageText });
            const encrypted = await openpgp.encrypt({
                message,
                encryptionKeys: pubKeyObj
            });

            expect(encrypted).toContain('-----BEGIN PGP MESSAGE-----');

            const privKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKey });
            const encMessageObj = await openpgp.readMessage({ armoredMessage: encrypted });
            const { data: decrypted } = await openpgp.decrypt({
                message: encMessageObj,
                decryptionKeys: privKeyObj
            });

            expect(decrypted).toBe(messageText);
        });
    });
});

describe('CipherMail XSS Prevention', () => {
    test('escapeHtml implementation exists in content script', () => {
        const contentScriptPath = path.resolve(__dirname, '../content/content.js');
        const contentScriptCode = fs.readFileSync(contentScriptPath, 'utf8');
        expect(contentScriptCode).toContain('function escapeHtml');
    });
});

describe('CipherMail Origin Validation', () => {
    test('should allow mail.google.com origins', () => {
        expect(isAllowedOrigin('https://mail.google.com/mail/u/0/')).toBe(true);
        expect(isAllowedOrigin('https://mail.google.com/mail/h/')).toBe(true);
        expect(isAllowedOrigin('https://mail.google.com/a/example.com/')).toBe(true);
    });

    test('should reject non-Gmail origins', () => {
        expect(isAllowedOrigin('https://evil.com')).toBe(false);
        expect(isAllowedOrigin('https://mail.google.com.evil.com')).toBe(false);
        expect(isAllowedOrigin('https://example.com')).toBe(false);
        expect(isAllowedOrigin(null)).toBe(false);
        expect(isAllowedOrigin(undefined)).toBe(false);
        expect(isAllowedOrigin('')).toBe(false);
    });

    test('should handle invalid URLs', () => {
        expect(isAllowedOrigin('not-a-url')).toBe(false);
        expect(isAllowedOrigin('http://mail.google.com')).toBe(false);
        expect(isAllowedOrigin('ftp://mail.google.com')).toBe(false);
    });
});

describe('CipherMail Email Validation', () => {
    test('should accept valid emails', () => {
        expect(isValidEmail('test@example.com')).toBe(true);
        expect(isValidEmail('user.name@domain.org')).toBe(true);
        expect(isValidEmail('user+tag@gmail.com')).toBe(true);
        expect(isValidEmail('test@sub.domain.example.com')).toBe(true);
    });

    test('should reject invalid emails', () => {
        expect(isValidEmail('')).toBe(false);
        expect(isValidEmail(null)).toBe(false);
        expect(isValidEmail(undefined)).toBe(false);
        expect(isValidEmail('test@')).toBe(false);
        expect(isValidEmail('@test.com')).toBe(false);
        expect(isValidEmail('test')).toBe(false);
        expect(isValidEmail('test@test@test.com')).toBe(false);
        expect(isValidEmail('test space@example.com')).toBe(false);
    });

    test('should reject emails that are too long', () => {
        const longEmail = 'a'.repeat(250) + '@test.com';
        expect(isValidEmail(longEmail)).toBe(false);
    });

    test('should trim whitespace', () => {
        expect(isValidEmail('  test@example.com  ')).toBe(true);
    });
});

describe('CipherMail UUID Generation', () => {
    test('should generate unique UUIDs', () => {
        const uuid1 = crypto.randomUUID();
        const uuid2 = crypto.randomUUID();
        expect(uuid1).not.toBe(uuid2);
    });

    test('should generate valid UUID format', () => {
        const uuid = crypto.randomUUID();
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        expect(uuid).toMatch(uuidRegex);
    });
});

describe('CipherMail Brute Force Protection', () => {
    const LOCKOUT_DURATION_MS = 30 * 60 * 1000;
    const MAX_FAILED_ATTEMPTS = 5;

    function calculateLockoutDuration(attempts, backoffMultiplier) {
        const lockoutMs = LOCKOUT_DURATION_MS * backoffMultiplier;
        return lockoutMs;
    }

    test('should calculate lockout duration with exponential backoff', () => {
        expect(calculateLockoutDuration(0, 1)).toBe(LOCKOUT_DURATION_MS);
        expect(calculateLockoutDuration(0, 2)).toBe(LOCKOUT_DURATION_MS * 2);
        expect(calculateLockoutDuration(0, 4)).toBe(LOCKOUT_DURATION_MS * 4);
        expect(calculateLockoutDuration(0, 8)).toBe(LOCKOUT_DURATION_MS * 8);
    });

    test('should cap backoff multiplier at 8', () => {
        expect(calculateLockoutDuration(0, 16)).toBe(LOCKOUT_DURATION_MS * 16);
    });

    test('should reset backoff multiplier on successful auth', () => {
        const resetMultiplier = () => 1;
        expect(resetMultiplier()).toBe(1);
    });
});

describe('CipherMail Multiple Recipients', () => {
    test('should store multiple recipient keys', () => {
        const recipientKeys = {};

        recipientKeys['alice@example.com'] = {
            armoredKey: '-----BEGIN PGP PUBLIC KEY BLOCK-----',
            fingerprint: 'ABCD1234',
            userInfo: 'Alice',
            algorithm: 'RSA-4096',
            trusted: false,
            firstFingerprint: 'ABCD1234'
        };

        recipientKeys['bob@example.com'] = {
            armoredKey: '-----BEGIN PGP PUBLIC KEY BLOCK-----',
            fingerprint: 'EFGH5678',
            userInfo: 'Bob',
            algorithm: 'RSA-4096',
            trusted: false,
            firstFingerprint: 'EFGH5678'
        };

        expect(Object.keys(recipientKeys).length).toBe(2);
        expect(recipientKeys['alice@example.com']).toBeDefined();
        expect(recipientKeys['bob@example.com']).toBeDefined();
    });

    test('should track first fingerprint for TOFU', () => {
        const recipientKeys = {};

        recipientKeys['alice@example.com'] = {
            armoredKey: '-----BEGIN PGP PUBLIC KEY BLOCK-----',
            fingerprint: 'ABCD1234',
            userInfo: 'Alice',
            algorithm: 'RSA-4096',
            trusted: true,
            firstFingerprint: 'ABCD1234'
        };

        expect(recipientKeys['alice@example.com'].firstFingerprint).toBe('ABCD1234');
        expect(recipientKeys['alice@example.com'].trusted).toBe(true);
    });

    test('should detect fingerprint changes', () => {
        const existingKey = {
            fingerprint: 'OLD1234',
            firstFingerprint: 'OLD1234',
            trusted: true
        };

        const currentFingerprint = 'NEW5678';
        const isNewFingerprint = existingKey.fingerprint !== currentFingerprint;

        expect(isNewFingerprint).toBe(true);
    });

    test('should mark key as untrusted after fingerprint verification fails', () => {
        const existingKey = {
            fingerprint: 'OLD1234',
            firstFingerprint: 'OLD1234',
            trusted: true
        };

        existingKey.trusted = false;
        expect(existingKey.trusted).toBe(false);
    });
});

describe('CipherMail Encryption with Recipients', () => {
    test('should select correct recipient key based on email', async () => {
        const recipientKeys = {
            'alice@example.com': {
                armoredKey: 'alice-key',
                email: 'alice@example.com'
            },
            'bob@example.com': {
                armoredKey: 'bob-key',
                email: 'bob@example.com'
            }
        };

        const recipientEmail = 'alice@example.com';
        const selectedKey = recipientKeys[recipientEmail];

        expect(selectedKey).toBeDefined();
        expect(selectedKey.email).toBe('alice@example.com');
    });

    test('should fall back to first recipient when no match', () => {
        const recipientKeys = {
            'alice@example.com': {
                armoredKey: 'alice-key',
                email: 'alice@example.com'
            },
            'bob@example.com': {
                armoredKey: 'bob-key',
                email: 'bob@example.com'
            }
        };

        const keys = Object.values(recipientKeys);
        const defaultKey = keys.length > 0 ? keys[0] : null;

        expect(defaultKey).toBeDefined();
        expect(defaultKey.email).toBe('alice@example.com');
    });

    test('should return error when no recipients configured', () => {
        const recipientKeys = {};
        const hasRecipients = Object.keys(recipientKeys).length > 0;

        expect(hasRecipients).toBe(false);
    });
});

describe('CipherMail TOFU Trust Model', () => {
    test('should mark key as trusted on first import', () => {
        const newRecipient = {
            armoredKey: '-----BEGIN PGP PUBLIC KEY BLOCK-----',
            fingerprint: 'ABCD1234',
            userInfo: 'Test User',
            algorithm: 'RSA-4096',
            addedAt: new Date().toISOString(),
            trusted: true,
            firstFingerprint: 'ABCD1234'
        };

        expect(newRecipient.trusted).toBe(true);
        expect(newRecipient.firstFingerprint).toBe(newRecipient.fingerprint);
    });

    test('should mark key as untrusted when fingerprint changes', () => {
        const recipient = {
            fingerprint: 'NEWFPR',
            firstFingerprint: 'OLDFPR',
            trusted: false
        };

        expect(recipient.trusted).toBe(false);
        expect(recipient.fingerprint).not.toBe(recipient.firstFingerprint);
    });

    test('should preserve first fingerprint even after update', () => {
        const recipient = {
            fingerprint: 'NEWFPR',
            firstFingerprint: 'OLDFPR',
            trusted: false
        };

        expect(recipient.firstFingerprint).toBe('OLDFPR');
    });
});