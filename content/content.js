let settings = {
    autoSign: true,
    autoLookup: false,
    confirmEncrypt: true
};

const SELECTORS = {
    TOOLBAR: ['.btC', '[role="toolbar"]', '.aC .aCi'],
    COMPOSE_DIALOG: ['div[role="dialog"]', '[data-rooster-compose-dialog]'],
    COMPOSE_TEXTBOX: ['div[role="textbox"]', '[data-gramm="false"]', 'div[contenteditable="true"]'],
    MESSAGE_BODY: ['.a3s.aiL', '[data-message-id]', '.message-body'],
    EMAIL_INPUT: ['input[name="to"]', 'input[type="email"]', 'textarea[name="to"]']
};

function findElement(selectors, context = document) {
    for (const selector of selectors) {
        try {
            const element = context.querySelector(selector);
            if (element) return element;
        } catch (e) {
            continue;
        }
    }
    return null;
}

function findElements(selectors, context = document) {
    const results = [];
    for (const selector of selectors) {
        try {
            const elements = context.querySelectorAll(selector);
            for (const el of elements) {
                results.push(el);
            }
        } catch (e) {
            continue;
        }
    }
    return results;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showToast(message, type = 'info', duration = 4000) {
    const existingToast = document.getElementById('ciphermail-toast');
    if (existingToast) existingToast.remove();

    const toast = document.createElement('div');
    toast.id = 'ciphermail-toast';
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: ${type === 'error' ? '#d93025' : type === 'success' ? '#0f9d58' : '#333'};
        color: white;
        padding: 14px 20px;
        border-radius: 8px;
        font-size: 14px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        z-index: 999999;
        animation: ciphermailToastSlide 0.3s ease;
        max-width: 300px;
    `;
    toast.textContent = message;

    const style = document.createElement('style');
    style.id = 'ciphermail-toast-style';
    style.textContent = `
        @keyframes ciphermailToastSlide {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
    `;
    if (!document.getElementById('ciphermail-toast-style')) {
        document.head.appendChild(style);
    }

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

function setButtonLoading(button, loading) {
    if (loading) {
        button.classList.add('ciphermail-loading');
        button.disabled = true;
    } else {
        button.classList.remove('ciphermail-loading');
        button.disabled = false;
    }
}

let offscreenDocument = null;

async function requestPassphraseFromGmail(purpose) {
    return new Promise((resolve) => {
        const overlay = document.createElement('div');
        overlay.id = 'ciphermail-passphrase-overlay';
        overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:999999;display:flex;align-items:center;justify-content:center;';

        const dialog = document.createElement('div');
        dialog.style.cssText = 'background:white;border-radius:12px;padding:24px;width:360px;max-width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.3);font-family:-apple-system,BlinkMacSystemFont,sans-serif;';
        dialog.innerHTML = `
            <div style="display:flex;align-items:center;margin-bottom:16px;">
                <div style="width:40px;height:40px;background:#1a73e8;border-radius:8px;display:flex;align-items:center;justify-content:center;margin-right:12px;">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2">
                        <rect x="3" y="11" width="18" height="11" rx="2"/>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    </svg>
                </div>
                <div>
                    <h3 style="margin:0;color:#1a73e8;font-size:18px;">CipherMail</h3>
                    <p style="margin:0;font-size:12px;color:#5f6368;">${purpose === 'decrypt' ? 'Decrypt Message' : purpose === 'encrypt-sign' ? 'Encrypt & Sign' : 'Encrypt Message'}</p>
                </div>
            </div>
            <p style="margin:0 0 16px 0;color:#5f6368;font-size:14px;line-height:1.4;">
                ${purpose === 'decrypt' ? 'Enter your passphrase to decrypt:' : 'Enter your passphrase:'}
            </p>
            <input type="password" id="ciphermail-passphrase-input"
                style="width:100%;padding:14px;margin-bottom:8px;border:1px solid #dadce0;border-radius:8px;font-size:14px;box-sizing:border-box;"
                placeholder="Enter passphrase" autofocus>
            <p style="font-size:11px;color:#5f6368;margin:0 0 16px 0;">
                Your passphrase is never sent to any server.
            </p>
            <div style="display:flex;gap:12px;">
                <button id="ciphermail-passphrase-cancel"
                    style="flex:1;padding:12px;background:#f1f3f4;color:#5f6368;border:none;border-radius:8px;cursor:pointer;font-size:14px;font-weight:500;">
                    Cancel
                </button>
                <button id="ciphermail-passphrase-submit"
                    style="flex:1;padding:12px;background:#1a73e8;color:white;border:none;border-radius:8px;cursor:pointer;font-size:14px;font-weight:500;">
                    ${purpose === 'decrypt' ? 'Decrypt' : purpose === 'encrypt-sign' ? 'Encrypt & Sign' : 'Encrypt'}
                </button>
            </div>
        `;

        overlay.appendChild(dialog);
        document.body.appendChild(overlay);

        const input = dialog.querySelector('#ciphermail-passphrase-input');
        const cancelBtn = dialog.querySelector('#ciphermail-passphrase-cancel');
        const submitBtn = dialog.querySelector('#ciphermail-passphrase-submit');

        const cleanup = () => {
            overlay.remove();
            offscreenDocument = null;
        };

        cancelBtn.onclick = () => {
            cleanup();
            resolve(null);
        };

        submitBtn.onclick = () => {
            const passphrase = input.value;
            cleanup();
            resolve(passphrase);
        };

        input.onkeydown = (e) => {
            if (e.key === 'Enter') {
                submitBtn.click();
            } else if (e.key === 'Escape') {
                cancelBtn.click();
            }
        };

        setTimeout(() => input.focus(), 100);
    });
}

async function lookupRecipientKey(email) {
    try {
        const response = await chrome.runtime.sendMessage({
            type: 'LOOKUP_KEY',
            email: email
        });
        return response;
    } catch (err) {
        return null;
    }
}

async function getRecipientEmailFromCompose(composeWindow) {
    const emailInputs = findElements(SELECTORS.EMAIL_INPUT, composeWindow);
    for (const input of emailInputs) {
        if (input.value && input.value.includes('@')) {
            return input.value.trim().toLowerCase();
        }
    }

    const toField = composeWindow.querySelector('textarea[email], input[name="to"]');
    if (toField && toField.value && toField.value.includes('@')) {
        return toField.value.trim().toLowerCase();
    }

    return null;
}

async function handleEncrypt(btn, composeBox, originalContent, sign = false) {
    const originalWindow = btn.closest('div[role="dialog"]') ||
        btn.closest('table') ||
        findElement(SELECTORS.COMPOSE_DIALOG);

    if (!originalWindow) return;

    const passphrase = await requestPassphraseFromGmail(sign ? 'encrypt-sign' : 'encrypt');
    if (!passphrase) {
        setButtonLoading(btn, false);
        return;
    }

    try {
        const storage = await chrome.storage.local.get(['publicKeyArmored', 'defaultRecipient']);

        if (!storage.publicKeyArmored && settings.autoLookup) {
            const email = await getRecipientEmailFromCompose(originalWindow);
            if (email) {
                const keyResponse = await lookupRecipientKey(email);
                if (keyResponse && keyResponse.success) {
                    await chrome.storage.local.set({ publicKeyArmored: keyResponse.key });
                    showToast(`Auto-imported key for ${email}`, 'info');
                }
            }
        }

        let response;
        if (sign) {
            response = await chrome.runtime.sendMessage({
                type: 'ENCRYPT_AND_SIGN',
                text: originalContent,
                passphrase: passphrase
            });
        } else {
            response = await chrome.runtime.sendMessage({
                type: 'ENCRYPT',
                data: originalContent
            });
        }

        if (response && response.success) {
            composeBox.textContent = response.data;
            showToast(sign ? 'Message encrypted and signed!' : 'Message encrypted successfully!', 'success');
        } else {
            showToast(response?.error || 'Encryption failed', 'error');
        }
    } catch (err) {
        showToast('Encryption failed. Please try again.', 'error');
    } finally {
        setButtonLoading(btn, false);
    }
}

function injectEncryptButton(toolbar) {
    if (toolbar.querySelector('.ciphermail-encrypt-btn')) return;

    const btn = document.createElement('button');
    btn.className = 'ciphermail-encrypt-btn';
    btn.innerHTML = `
        <span class="ciphermail-btn-icon">🔐</span>
        <span class="ciphermail-btn-text">Encrypt</span>
        <span class="ciphermail-spinner" style="display:none;width:14px;height:14px;border:2px solid rgba(255,255,255,0.3);border-top-color:white;border-radius:50%;animation:ciphermailSpin 0.8s linear infinite;margin-left:6px;"></span>
    `;
    btn.style.cssText = 'display:flex;align-items:center;background:#4285f4;color:white;border:none;padding:6px 12px;margin-left:10px;border-radius:6px;cursor:pointer;font-weight:bold;font-size:13px;transition:background 0.2s;';
    btn.onmouseover = () => btn.style.background = '#3367d6';
    btn.onmouseout = () => btn.style.background = '#4285f4';

    btn.onclick = async (e) => {
        e.preventDefault();
        const composeWindow = btn.closest('div[role="dialog"]') ||
            btn.closest('table') ||
            findElement(SELECTORS.COMPOSE_DIALOG);

        if (!composeWindow) return;

        const composeBox = findElement(SELECTORS.COMPOSE_TEXTBOX, composeWindow);
        if (!composeBox) return;

        const backupContent = composeBox.textContent;
        setButtonLoading(btn, true);

        if (settings.confirmEncrypt) {
            if (!confirm('Encrypt this message?')) {
                setButtonLoading(btn, false);
                return;
            }
        }

        await handleEncrypt(btn, composeBox, backupContent, settings.autoSign);
    };

    toolbar.appendChild(btn);

    const style = document.createElement('style');
    if (!document.getElementById('ciphermail-btn-style')) {
        style.id = 'ciphermail-btn-style';
        style.textContent = `
            @keyframes ciphermailSpin { to { transform: rotate(360deg); } }
            .ciphermail-encrypt-btn:hover .ciphermail-spinner,
            .ciphermail-decrypt-btn:hover .ciphermail-spinner {
                border-top-color: white;
            }
        `;
        document.head.appendChild(style);
    }
}

function injectDecryptButton() {
    const pgpRegex = /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/g;

    const messageBodies = findElements(SELECTORS.MESSAGE_BODY);

    messageBodies.forEach(body => {
        if (!body || body.querySelector('.ciphermail-decrypt-btn')) return;

        const text = body.textContent || '';
        const matches = text.match(pgpRegex);

        if (!matches || matches.length === 0) return;

        const btn = document.createElement('button');
        btn.className = 'ciphermail-decrypt-btn';
        btn.innerHTML = `
            <span class="ciphermail-btn-icon">🔓</span>
            <span class="ciphermail-btn-text">Decrypt${matches.length > 1 ? ` (${matches.length})` : ''}</span>
            <span class="ciphermail-spinner" style="display:none;width:14px;height:14px;border:2px solid rgba(255,255,255,0.3);border-top-color:white;border-radius:50%;animation:ciphermailSpin 0.8s linear infinite;margin-left:6px;"></span>
        `;
        btn.style.cssText = 'display:flex;align-items:center;background:#0f9d58;color:white;border:none;padding:8px 16px;margin-bottom:12px;border-radius:6px;cursor:pointer;font-weight:bold;font-size:13px;transition:background 0.2s;box-shadow:0 2px 4px rgba(0,0,0,0.1);';
        btn.onmouseover = () => btn.style.background = '#0b8043';
        btn.onmouseout = () => btn.style.background = '#0f9d58';

        btn.onclick = async () => {
            setButtonLoading(btn, true);

            try {
                const lockoutCheck = await chrome.runtime.sendMessage({
                    type: 'CHECK_LOCKOUT'
                });

                if (lockoutCheck && lockoutCheck.locked) {
                    showToast(`Too many failed attempts. Please try again in ${lockoutCheck.remainingMinutes} minutes.`, 'error');
                    setButtonLoading(btn, false);
                    return;
                }
            } catch (e) {
                console.error('Lockout check failed', e);
            }

            const passphrase = await requestPassphraseFromGmail('decrypt');
            if (!passphrase) {
                setButtonLoading(btn, false);
                return;
            }

            let allDecrypted = true;
            let decryptedCount = 0;
            const originalBodyHTML = body.innerHTML;

            for (const pgpBlock of matches) {
                try {
                    const response = await chrome.runtime.sendMessage({
                        type: 'DECRYPT',
                        data: pgpBlock,
                        passphrase: passphrase
                    });

                    if (response && response.success) {
                        const escapedData = escapeHtml(response.data);
                        const placeholder = `__CIPHERMAIL_DECRYPTED_${decryptedCount}__`;
                        body.innerHTML = body.innerHTML.replace(pgpBlock, placeholder);

                        const verifyResponse = await chrome.runtime.sendMessage({
                            type: 'VERIFY_SIGNATURE',
                            message: pgpBlock
                        });

                        let signatureInfo = '';
                        if (verifyResponse && verifyResponse.success) {
                            const signer = escapeHtml(verifyResponse.signer || 'Unknown');
                            const fingerprint = escapeHtml(verifyResponse.fingerprint || 'N/A');
                            if (verifyResponse.signed) {
                                if (verifyResponse.verified) {
                                    signatureInfo = `<div style="background:#e6f4ea;padding:8px 12px;margin-bottom:12px;border-radius:4px;font-size:12px;color:#0f9d58;">
                                        <strong>Verified Signature</strong><br>
                                        Signed by: ${signer}<br>
                                        <span style="font-family:monospace;font-size:10px;">Fingerprint: ${fingerprint}</span>
                                    </div>`;
                                } else {
                                    signatureInfo = `<div style="background:#fef7e0;padding:8px 12px;margin-bottom:12px;border-radius:4px;font-size:12px;color:#f9a825;">
                                        <strong>Unverified Signature</strong><br>
                                        Signed by: ${signer}
                                    </div>`;
                                }
                            } else {
                                signatureInfo = `<div style="background:#f1f3f4;padding:8px 12px;margin-bottom:12px;border-radius:4px;font-size:12px;color:#5f6368;">
                                    <strong>No Signature</strong> - Message is not signed
                                </div>`;
                            }
                        }

                        body.innerHTML = body.innerHTML.replace(
                            placeholder,
                            signatureInfo + `<div style="background:#f8f9fa;padding:16px;border-left:4px solid #0f9d58;font-family:monospace;font-size:14px;line-height:1.6;white-space:pre-wrap;border-radius:4px;margin:8px 0;box-shadow:0 1px 3px rgba(0,0,0,0.1);">${escapedData}</div>`
                        );
                        decryptedCount++;
                    } else {
                        allDecrypted = false;
                    }
                } catch (err) {
                    allDecrypted = false;
                    body.innerHTML = originalBodyHTML;
                    break;
                }
            }

            if (allDecrypted && decryptedCount > 0) {
                btn.remove();
                showToast(`Decrypted ${decryptedCount} message${decryptedCount > 1 ? 's' : ''} successfully!`, 'success');
            } else {
                body.innerHTML = originalBodyHTML;
                showToast(response?.error || 'Decryption failed. Please check your passphrase.', 'error');
            }

            setButtonLoading(btn, false);
        };

        body.prepend(btn);
    });
}

let observer = null;

function initializeObserver() {
    if (observer) return;

    observer = new MutationObserver(() => {
        const toolbars = findElements(SELECTORS.TOOLBAR);
        toolbars.forEach(toolbar => injectEncryptButton(toolbar));
        injectDecryptButton();
    });

    observer.observe(document.body, { childList: true, subtree: true });
}

function cleanupObserver() {
    if (observer) {
        observer.disconnect();
        observer = null;
    }
}

async function loadSettings() {
    try {
        const result = await chrome.storage.local.get(['settings']);
        if (result.settings) {
            settings = { ...settings, ...result.settings };
        }
    } catch (err) {
        console.error('Failed to load settings:', err);
    }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'SETTINGS_UPDATED') {
        settings = { ...settings, ...request.settings };
    }
});

loadSettings();
initializeObserver();

if (typeof window !== 'undefined') {
    window.__ciphermail_cleanup = cleanupObserver;
    window.__ciphermail_handleEncrypt = (btn, composeBox, backupContent, sign) => handleEncrypt(btn, composeBox, backupContent, sign);
}