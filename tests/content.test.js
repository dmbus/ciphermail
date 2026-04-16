/**
 * @jest-environment jsdom
 */
const { chrome } = require('jest-chrome');
const fs = require('fs');
const path = require('path');

global.chrome = chrome;

const contentScriptPath = path.resolve(__dirname, '../content/content.js');
const contentScriptCode = fs.readFileSync(contentScriptPath, 'utf8');

describe('CipherMail Content Script DOM Injection', () => {
    let injectEncryptButton, injectDecryptButton, escapeHtml;

    beforeAll(() => {
        const testableCode = contentScriptCode.split('// Observe Gmail')[0];
        const script = new Function(testableCode + '; return { injectEncryptButton, injectDecryptButton, escapeHtml };');
        const exports = script();
        injectEncryptButton = exports.injectEncryptButton;
        injectDecryptButton = exports.injectDecryptButton;
        escapeHtml = exports.escapeHtml;
    });

    beforeEach(() => {
        document.body.innerHTML = `
            <div id="gmail-compose">
                <div class="btC">
                    <div role="dialog">
                        <div role="textbox" aria-label="Message Body">Initial text</div>
                    </div>
                </div>
            </div>
            <div class="a3s aiL">-----BEGIN PGP MESSAGE-----some encrypted data-----END PGP MESSAGE-----</div>
        `;
    });

    test('should inject the Encrypt button into the toolbar', () => {
        const toolbar = document.querySelector('.btC');
        injectEncryptButton(toolbar);

        const encryptBtn = toolbar.querySelector('.ciphermail-encrypt-btn');
        expect(encryptBtn).toBeTruthy();
        expect(encryptBtn.textContent).toContain('Encrypt');
    });

    test('should inject the Decrypt button above PGP messages', () => {
        injectDecryptButton();

        const messageBody = document.querySelector('.a3s.aiL');
        const decryptBtn = messageBody.querySelector('.ciphermail-decrypt-btn');
        expect(decryptBtn).toBeTruthy();
        expect(decryptBtn.textContent).toContain('Decrypt');
    });

    test('should not inject duplicate Encrypt buttons', () => {
        const toolbar = document.querySelector('.btC');
        injectEncryptButton(toolbar);
        injectEncryptButton(toolbar);

        const buttons = toolbar.querySelectorAll('.ciphermail-encrypt-btn');
        expect(buttons.length).toBe(1);
    });
});

describe('CipherMail XSS Prevention', () => {
    let escapeHtml;

    beforeAll(() => {
        const contentScriptPath = path.resolve(__dirname, '../content/content.js');
        const contentScriptCode = fs.readFileSync(contentScriptPath, 'utf8');
        const testableCode = contentScriptCode.split('// Observe Gmail')[0];
        const script = new Function(testableCode + '; return { escapeHtml };');
        const exports = script();
        escapeHtml = exports.escapeHtml;
    });

    test('should escape HTML script tags', () => {
        const malicious = '<script>alert("xss")</script>';
        const escaped = escapeHtml(malicious);
        expect(escaped).not.toContain('<script>');
        expect(escaped).toContain('&lt;script&gt;');
    });

    test('should escape HTML tags to prevent execution', () => {
        const xss = '<img src=x onerror="alert(1)">';
        const escaped = escapeHtml(xss);
        expect(escaped).toContain('&lt;');
        expect(escaped).toContain('&gt;');
        expect(escaped).not.toContain('<img');
    });

    test('should escape HTML tags to prevent execution', () => {
        const xss = '<div onclick="alert(1)">Click</div>';
        const escaped = escapeHtml(xss);
        expect(escaped).toContain('&lt;');
        expect(escaped).toContain('&gt;');
        expect(escaped).not.toContain('<div');
    });

    test('should preserve normal text content', () => {
        const normal = 'Hello, this is a secret message!';
        const escaped = escapeHtml(normal);
        expect(escaped).toBe(normal);
    });

    test('should escape HTML entities', () => {
        const input = 'Test & "quotes" <tags>';
        const escaped = escapeHtml(input);
        expect(escaped).toContain('&amp;');
        expect(escaped).toContain('&lt;');
        expect(escaped).toContain('&gt;');
    });

    test('should handle multi-line content', () => {
        const multiline = 'Line 1\nLine 2\nLine 3';
        const escaped = escapeHtml(multiline);
        expect(escaped).toBe(multiline);
    });
});

describe('CipherMail Passphrase Validation', () => {
    function validatePassphraseUI(passphrase) {
        if (!passphrase || passphrase.length < 12) {
            return { valid: false, message: 'Passphrase must be at least 12 characters' };
        }
        if (!/[A-Z]/.test(passphrase)) {
            return { valid: false, message: 'Passphrase must contain at least one uppercase letter' };
        }
        if (!/[a-z]/.test(passphrase)) {
            return { valid: false, message: 'Passphrase must contain at least one lowercase letter' };
        }
        if (!/[0-9]/.test(passphrase)) {
            return { valid: false, message: 'Passphrase must contain at least one number' };
        }
        if (!/[^A-Za-z0-9]/.test(passphrase)) {
            return { valid: false, message: 'Passphrase must contain at least one special character (!@#$%^&*...)' };
        }
        return { valid: true };
    }

    test('should accept strong passphrase', () => {
        const result = validatePassphraseUI('MyStr0ng#Pass!');
        expect(result.valid).toBe(true);
    });

    test('should reject weak passphrase', () => {
        const result = validatePassphraseUI('weakpass');
        expect(result.valid).toBe(false);
    });

    test('should calculate correct strength', () => {
        const calcStrength = (passphrase) => {
            if (!passphrase) return { text: '', color: 'transparent' };
            let score = 0;
            if (passphrase.length >= 12) score++;
            if (passphrase.length >= 16) score++;
            if (passphrase.length >= 20) score++;
            if (/[A-Z]/.test(passphrase)) score++;
            if (/[a-z]/.test(passphrase)) score++;
            if (/[0-9]/.test(passphrase)) score++;
            if (/[^A-Za-z0-9]/.test(passphrase)) score++;
            if (score < 3) return { text: 'Weak', color: '#d93025' };
            if (score < 5) return { text: 'Fair', color: '#f9a825' };
            if (score < 7) return { text: 'Good', color: '#188038' };
            return { text: 'Strong', color: '#0d652d' };
        };

        expect(calcStrength('abc')).toEqual({ text: 'Weak', color: '#d93025' });
        expect(calcStrength('Abc123!@')).toEqual({ text: 'Fair', color: '#f9a825' });
        expect(calcStrength('MyStr0ng#Pass!')).toEqual({ text: 'Good', color: '#188038' });
        expect(calcStrength('Very$tr0ng&Complex!Key#2024')).toEqual({ text: 'Strong', color: '#0d652d' });
    });
});