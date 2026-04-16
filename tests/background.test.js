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