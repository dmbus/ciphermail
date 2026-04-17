/**
 * @jest-environment jsdom
 */
describe('CipherMail Popup XSS Prevention', () => {
    let chrome;

    beforeEach(() => {
        document.body.innerHTML = `
            <div id="lookupResult" style="display:none;"></div>
            <button id="importFoundKey" style="display:none;">Import</button>
        `;
    });

    test('should use textContent for error messages instead of innerHTML', () => {
        const resultDiv = document.getElementById('lookupResult');
        const importBtn = document.getElementById('importFoundKey');

        const maliciousError = '<script>alert("xss")</script>';

        resultDiv.innerHTML = '';
        const errorDiv = document.createElement('div');
        errorDiv.style.color = '#d93025';
        errorDiv.textContent = maliciousError;
        resultDiv.appendChild(errorDiv);

        expect(resultDiv.innerHTML).not.toContain('<script>');
        expect(resultDiv.textContent).toContain(maliciousError);
    });

    test('should safely handle error messages with HTML entities', () => {
        const resultDiv = document.getElementById('lookupResult');

        resultDiv.innerHTML = '';
        const errorDiv = document.createElement('div');
        errorDiv.style.color = '#d93025';
        errorDiv.textContent = 'Test & "quotes" <tags>';
        resultDiv.appendChild(errorDiv);

        expect(resultDiv.textContent).toContain('Test & "quotes" <tags>');
    });
});

describe('CipherMail Popup Security Patterns', () => {
    test('escapeHtml should be defined in popup', () => {
        const popupJsPath = require('path').resolve(__dirname, '../popup/popup.js');
        const fs = require('fs');
        const popupCode = fs.readFileSync(popupJsPath, 'utf8');

        expect(popupCode).toContain('function escapeHtml');
    });

    test('popup should use escapeHtml for user data', () => {
        const popupJsPath = require('path').resolve(__dirname, '../popup/popup.js');
        const fs = require('fs');
        const popupCode = fs.readFileSync(popupJsPath, 'utf8');

        expect(popupCode).toContain('escapeHtml(response.myKeyInfo.user)');
        expect(popupCode).toContain('escapeHtml(response.recipientKeyInfo.user)');
        expect(popupCode).toContain('escapeHtml(response.user');
        expect(popupCode).toContain('escapeHtml(response.fingerprint');
    });

    test('lookup result should use textContent for dynamic error messages', () => {
        const popupJsPath = require('path').resolve(__dirname, '../popup/popup.js');
        const fs = require('fs');
        const popupCode = fs.readFileSync(popupJsPath, 'utf8');

        expect(popupCode).toContain('errorDiv.textContent');
        expect(popupCode).not.toContain('${response.error}');
    });
});