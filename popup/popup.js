let foundKey = null;
let pendingAction = null;
let autoSign = true;
let autoLookup = false;
let confirmEncrypt = true;
let sessionTimeout = true;
let timeoutMinutes = 15;
let secureClipboard = true;
let clipboardSeconds = 60;
let darkMode = false;
let lastActivity = Date.now();
let activityCheckInterval = null;

function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(20px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

function setButtonLoading(button, loading) {
    if (loading) {
        button.classList.add('loading');
        button.disabled = true;
    } else {
        button.classList.remove('loading');
        button.disabled = false;
    }
}

function setButtonState(button, state) {
    button.classList.remove('loading', 'success', 'error');
    if (state) {
        button.classList.add(state);
        setTimeout(() => button.classList.remove(state), 2000);
    }
}

function resetActivity() {
    lastActivity = Date.now();
}

document.addEventListener('click', resetActivity);
document.addEventListener('keypress', resetActivity);

function checkSessionTimeout() {
    if (!sessionTimeout) return;

    const elapsed = Date.now() - lastActivity;
    const timeoutMs = timeoutMinutes * 60 * 1000;

    if (elapsed > timeoutMs) {
        chrome.storage.local.set({ sessionLocked: true });
        showToast('Session locked due to inactivity', 'info');
        stopActivityMonitor();
    }
}

function startActivityMonitor() {
    if (activityCheckInterval) clearInterval(activityCheckInterval);
    activityCheckInterval = setInterval(checkSessionTimeout, 30000);
}

function stopActivityMonitor() {
    if (activityCheckInterval) {
        clearInterval(activityCheckInterval);
        activityCheckInterval = null;
    }
}

window.addEventListener('unload', stopActivityMonitor);

document.querySelectorAll('.toggle-password').forEach(toggle => {
    toggle.addEventListener('click', () => {
        const input = toggle.closest('.input-wrapper').querySelector('input');
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        toggle.innerHTML = isPassword
            ? `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                <line x1="1" y1="1" x2="23" y2="23"/>
               </svg>`
            : `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                <circle cx="12" cy="12" r="3"/>
               </svg>`;
    });
});

function getCurrentSettings() {
    return { sessionTimeout, timeoutMinutes, secureClipboard, clipboardSeconds, darkMode, autoSign, autoLookup, confirmEncrypt };
}

function saveSettings() {
    chrome.storage.local.set({ settings: getCurrentSettings() });
}

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
    });
});

document.getElementById('sessionTimeout').addEventListener('change', (e) => {
    sessionTimeout = e.target.checked;
    document.getElementById('timeoutSetting').style.display = sessionTimeout ? 'block' : 'none';
    saveSettings();
});

document.getElementById('secureClipboard').addEventListener('change', (e) => {
    secureClipboard = e.target.checked;
    document.getElementById('clipboardTimeoutSetting').style.display = secureClipboard ? 'block' : 'none';
    saveSettings();
});

document.getElementById('darkMode').addEventListener('change', (e) => {
    darkMode = e.target.checked;
    document.body.classList.toggle('dark', darkMode);
    saveSettings();
});

document.getElementById('autoSign').addEventListener('change', (e) => {
    autoSign = e.target.checked;
    saveSettings();
});

document.getElementById('autoLookup').addEventListener('change', (e) => {
    autoLookup = e.target.checked;
    saveSettings();
});

document.getElementById('confirmEncrypt').addEventListener('change', (e) => {
    confirmEncrypt = e.target.checked;
    saveSettings();
});

document.getElementById('timeoutMinutes').addEventListener('change', (e) => {
    timeoutMinutes = parseInt(e.target.value);
    saveSettings();
});

document.getElementById('clipboardSeconds').addEventListener('change', (e) => {
    clipboardSeconds = parseInt(e.target.value);
    saveSettings();
});

async function copyToClipboard(text, showMessage = true) {
    try {
        await navigator.clipboard.writeText(text);
        if (showMessage) showToast('Copied to clipboard!', 'success');

        if (secureClipboard && showMessage) {
            setTimeout(async () => {
                try {
                    await navigator.clipboard.writeText('');
                } catch (e) {
                    console.warn('CipherMail: Failed to clear clipboard:', e);
                    showToast('Warning: Could not clear clipboard', 'error');
                }
            }, clipboardSeconds * 1000);
        }
        return true;
    } catch (err) {
        showToast('Failed to copy to clipboard', 'error');
        return false;
    }
}

document.getElementById('copyPubKey')?.addEventListener('click', async () => {
    const pubKey = document.getElementById('myPubKey').value;
    const btn = document.getElementById('copyPubKey');

    if (!pubKey) {
        showToast('No public key to copy', 'error');
        return;
    }

    if (await copyToClipboard(pubKey)) {
        setButtonState(btn, 'success');
    } else {
        setButtonState(btn, 'error');
    }
});

document.getElementById('showQRCode')?.addEventListener('click', () => {
    const pubKey = document.getElementById('myPubKey').value;
    if (!pubKey) {
        showToast('No public key to display', 'error');
        return;
    }

    if (confirm('This will open a modal where you can copy your public key.\nFor sharing via QR codes, consider using a dedicated QR code application.')) {
        const modal = document.getElementById('qrModal');
        const canvas = document.getElementById('qrCanvas');
        const ctx = canvas.getContext('2d');

        canvas.width = 200;
        canvas.height = 200;
        ctx.fillStyle = '#f8f9fa';
        ctx.fillRect(0, 0, 200, 200);

        ctx.fillStyle = '#5f6368';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('Public Key', 100, 80);
        ctx.font = '11px monospace';
        ctx.fillText('Copy below', 100, 100);
        ctx.fillText('or use', 100, 130);
        ctx.font = '12px sans-serif';
        ctx.fillText('Copy Public Key', 100, 155);
        ctx.fillText('button instead', 100, 172);

        modal.style.display = 'flex';
    }
});

document.querySelectorAll('.modal-close').forEach(btn => {
    btn.addEventListener('click', () => {
        btn.closest('.modal').style.display = 'none';
    });
});

document.getElementById('modalCancel')?.addEventListener('click', () => {
    document.getElementById('passphraseModal').style.display = 'none';
    pendingAction = null;
});

document.getElementById('modalConfirm')?.addEventListener('click', async () => {
    const passphrase = document.getElementById('modalPassphrase').value;
    document.getElementById('modalPassphrase').value = '';
    document.getElementById('passphraseModal').style.display = 'none';

    if (pendingAction) {
        await pendingAction.callback(passphrase);
        pendingAction = null;
    }
});

function showPassphraseModal(description, callback) {
    document.getElementById('passphraseModalDesc').textContent = description;
    document.getElementById('passphraseModal').style.display = 'flex';
    document.getElementById('modalPassphrase').focus();
    pendingAction = { callback };
}

document.getElementById('exportKeys')?.addEventListener('click', () => {
    showPassphraseModal('Enter your passphrase to export keys:', async (passphrase) => {
        if (!passphrase) {
            showToast('Passphrase required', 'error');
            return;
        }

        const btn = document.getElementById('exportKeys');
        setButtonLoading(btn, true);

        const response = await chrome.runtime.sendMessage({
            type: 'EXPORT_KEYS',
            passphrase
        });

        setButtonLoading(btn, false);

        if (response && response.success) {
            const blob = new Blob([response.backup], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ciphermail-backup-${new Date().toISOString().split('T')[0]}.json`;
            a.click();
            URL.revokeObjectURL(url);
            showToast('Keys exported successfully!', 'success');
        } else {
            showToast(response?.error || 'Export failed', 'error');
        }
    });
});

document.getElementById('importKeys')?.addEventListener('click', () => {
    document.getElementById('backupFile').click();
});

document.getElementById('backupFile')?.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (event) => {
        const backupData = event.target.result;

        showPassphraseModal('Enter your passphrase to import the backup:', async (passphrase) => {
            if (!passphrase) {
                showToast('Passphrase required', 'error');
                return;
            }

            const btn = document.getElementById('importKeys');
            setButtonLoading(btn, true);

            const response = await chrome.runtime.sendMessage({
                type: 'IMPORT_KEYS',
                backupData,
                passphrase
            });

            setButtonLoading(btn, false);

            if (response && response.success) {
                document.getElementById('myPubKey').value = response.publicKey;
                showToast('Keys imported successfully!', 'success');
                await loadStoredKeys();
            } else {
                showToast(response?.error || 'Import failed', 'error');
            }
        });
    };
    reader.readAsText(file);
    e.target.value = '';
});

document.getElementById('rotateKeys')?.addEventListener('click', () => {
    const name = prompt('Enter your name for the new key:');
    if (!name) return;

    const email = prompt('Enter your email for the new key:');
    if (!email) return;

    showPassphraseModal('Enter a passphrase for your new keys:', async (passphrase) => {
        if (!passphrase) {
            showToast('Passphrase required', 'error');
            return;
        }

        const btn = document.getElementById('rotateKeys');
        setButtonLoading(btn, true);

        const response = await chrome.runtime.sendMessage({
            type: 'ROTATE_KEYS',
            name, email, passphrase
        });

        setButtonLoading(btn, false);

        if (response && response.success) {
            document.getElementById('myPubKey').value = response.publicKey;
            showToast('Keys rotated successfully!', 'success');
            await loadStoredKeys();
        } else {
            showToast(response?.error || 'Key rotation failed', 'error');
        }
    });
});

document.getElementById('deleteMyKeys')?.addEventListener('click', async () => {
    if (!confirm('Are you sure you want to delete your keys? This cannot be undone.')) {
        return;
    }

    const response = await chrome.runtime.sendMessage({
        type: 'DELETE_KEY',
        keyType: 'myKeys'
    });

    if (response && response.success) {
        document.getElementById('myPubKey').value = '';
        showToast('Keys deleted', 'info');
        await loadStoredKeys();
    } else {
        showToast(response?.error || 'Failed to delete keys', 'error');
    }
});

async function loadStoredKeys() {
    const response = await chrome.runtime.sendMessage({ type: 'GET_STORED_KEYS' });

    if (response && response.success) {
        const myKeyInfoDiv = document.getElementById('myKeyInfo');
        const recipientKeyInfoDiv = document.getElementById('recipientKeyInfo');

        if (response.hasMyKeys && response.myKeyInfo) {
            myKeyInfoDiv.innerHTML = `
                <p><strong>User:</strong> ${escapeHtml(response.myKeyInfo.user)}</p>
                <p><strong>Algorithm:</strong> <span class="algorithm">${escapeHtml(response.myKeyInfo.algorithm)}</span></p>
                <p class="fingerprint"><strong>Fingerprint:</strong> ${response.myKeyInfo.fingerprint}</p>
            `;
            document.getElementById('rotateKeys').style.display = 'block';
            document.getElementById('exportKeys').style.display = 'block';
            document.getElementById('deleteMyKeys').style.display = 'block';
            document.getElementById('showQRCode').style.display = 'block';
        } else {
            myKeyInfoDiv.innerHTML = '<p style="color:#5f6368;font-size:12px;">No keys generated yet</p>';
            document.getElementById('rotateKeys').style.display = 'none';
            document.getElementById('exportKeys').style.display = 'none';
            document.getElementById('deleteMyKeys').style.display = 'none';
            document.getElementById('showQRCode').style.display = 'none';
        }

        if (response.hasRecipientKey && response.recipientKeyInfo) {
            recipientKeyInfoDiv.innerHTML = `
                <p><strong>User:</strong> ${escapeHtml(response.recipientKeyInfo.user)}</p>
                <p><strong>Algorithm:</strong> <span class="algorithm">${escapeHtml(response.recipientKeyInfo.algorithm)}</span></p>
                <p class="fingerprint"><strong>Fingerprint:</strong> ${response.recipientKeyInfo.fingerprint}</p>
            `;
        } else {
            recipientKeyInfoDiv.innerHTML = '<p style="color:#5f6368;font-size:12px;">No recipient key saved</p>';
        }
    }
}

document.getElementById('savePubKey').onclick = async () => {
    const key = document.getElementById('pubKey').value.trim();
    const btn = document.getElementById('savePubKey');

    if (!key) {
        showToast('Please paste a public key', 'error');
        return;
    }

    setButtonLoading(btn, true);

    try {
        const publicKey = await openpgp.readKey({ armoredKey: key });

        if (!publicKey.isPublic()) {
            showToast('This appears to be a private key. Please paste a public key.', 'error');
            setButtonState(btn, 'error');
            return;
        }

        const primaryUser = publicKey.getPrimaryUser();
        if (!primaryUser) {
            showToast('Invalid key format - no user ID found.', 'error');
            setButtonState(btn, 'error');
            return;
        }

        chrome.storage.local.set({ publicKeyArmored: key }, () => {
            showToast('Public Key Saved!', 'success');
            setButtonState(btn, 'success');
            loadStoredKeys();
        });
    } catch (err) {
        showToast('Invalid PGP public key format. Please check and try again.', 'error');
        setButtonState(btn, 'error');
    } finally {
        setButtonLoading(btn, false);
    }
};

document.getElementById('lookupKey').onclick = async () => {
    const email = document.getElementById('lookupEmail').value.trim();
    const btn = document.getElementById('lookupKey');
    const resultDiv = document.getElementById('lookupResult');
    const importBtn = document.getElementById('importFoundKey');

    if (!email || !email.includes('@')) {
        showToast('Please enter a valid email address', 'error');
        return;
    }

    setButtonLoading(btn, true);
    resultDiv.style.display = 'none';
    importBtn.style.display = 'none';
    foundKey = null;

    try {
        const response = await chrome.runtime.sendMessage({
            type: 'LOOKUP_KEY',
            email: email
        });

        if (response && response.success) {
            foundKey = response.key;
            resultDiv.innerHTML = `
                <div style="margin-bottom:8px;"><strong>Key Found!</strong></div>
                <div><strong>User:</strong> ${escapeHtml(response.user || 'Unknown')}</div>
                <div><strong>Fingerprint:</strong> <code style="font-size:10px;word-break:break-all;">${escapeHtml(response.fingerprint || 'N/A')}</code></div>
                <div><strong>Algorithm:</strong> ${escapeHtml(response.algorithm || 'Unknown')}</div>
                <div><strong>Server:</strong> ${escapeHtml(response.server || 'Unknown')}</div>
            `;
            resultDiv.style.background = '#e6f4ea';
            resultDiv.style.borderLeft = '4px solid #0f9d58';
            importBtn.style.display = 'block';
        } else {
            resultDiv.innerHTML = '';
            const errorDiv = document.createElement('div');
            errorDiv.style.color = '#d93025';
            errorDiv.textContent = response.error || 'No key found for this email.';
            resultDiv.appendChild(errorDiv);
            resultDiv.style.background = '#fce8e6';
            resultDiv.style.borderLeft = '4px solid #d93025';
        }
        resultDiv.style.display = 'block';
    } catch (err) {
        resultDiv.innerHTML = '';
        const errorDiv = document.createElement('div');
        errorDiv.style.color = '#d93025';
        errorDiv.textContent = 'Search failed. Please try again.';
        resultDiv.appendChild(errorDiv);
        resultDiv.style.background = '#fce8e6';
        resultDiv.style.borderLeft = '4px solid #d93025';
        resultDiv.style.display = 'block';
    } finally {
        setButtonLoading(btn, false);
    }
};

document.getElementById('importFoundKey').onclick = async () => {
    if (!foundKey) {
        showToast('No key to import', 'error');
        return;
    }

    document.getElementById('pubKey').value = foundKey;
    showToast('Key imported! Click "Save Recipient Key" to store it.', 'success');

    document.getElementById('importFoundKey').style.display = 'none';
    document.getElementById('lookupResult').style.display = 'none';
    document.getElementById('lookupEmail').value = '';
};

document.getElementById('generateKeys').onclick = async () => {
    const name = prompt('Enter your name:');
    if (!name) return;

    const email = prompt('Enter your email:');
    if (!email) return;

    showPassphraseModal('Enter a passphrase for your new keys:', async (passphrase) => {
        if (!passphrase) {
            showToast('Passphrase required', 'error');
            return;
        }

        const btn = document.getElementById('generateKeys');
        setButtonLoading(btn, true);
        btn.querySelector('.btn-text').textContent = 'Generating keys...';

        const response = await chrome.runtime.sendMessage({
            type: 'GENERATE_KEYS',
            name, email, passphrase
        });

        setButtonLoading(btn, false);
        btn.querySelector('.btn-text').textContent = 'Generate New Keys';

        if (response && response.success) {
            document.getElementById('myPubKey').value = response.publicKey;
            showToast('Keys generated successfully!', 'success');
            setButtonState(btn, 'success');
            await loadStoredKeys();
        } else {
            showToast(response?.error || 'Key generation failed', 'error');
            setButtonState(btn, 'error');
        }
    });
};

document.getElementById('signMessageBtn').onclick = async () => {
    const message = document.getElementById('signMessage').value.trim();
    const btn = document.getElementById('signMessageBtn');
    const output = document.getElementById('signedOutput');
    const copyBtn = document.getElementById('copySignedMsg');

    if (!message) {
        showToast('Please enter a message to sign', 'error');
        return;
    }

    showPassphraseModal('Enter your passphrase to sign:', async (passphrase) => {
        if (!passphrase) {
            showToast('Passphrase required', 'error');
            return;
        }

        setButtonLoading(btn, true);

        try {
            const response = await chrome.runtime.sendMessage({
                type: 'SIGN_MESSAGE',
                text: message,
                passphrase: passphrase
            });

            if (response && response.success) {
                output.value = response.data;
                copyBtn.style.display = 'block';
                showToast('Message signed successfully!', 'success');
                setButtonState(btn, 'success');
            } else {
                showToast(response?.error || 'Signing failed', 'error');
                setButtonState(btn, 'error');
            }
        } catch (err) {
            showToast('Signing failed. Please try again.', 'error');
            setButtonState(btn, 'error');
        } finally {
            setButtonLoading(btn, false);
        }
    });
};

document.getElementById('copySignedMsg')?.addEventListener('click', async () => {
    const signedMsg = document.getElementById('signedOutput').value;
    const btn = document.getElementById('copySignedMsg');

    if (!signedMsg) {
        showToast('No signed message to copy', 'error');
        return;
    }

    if (await copyToClipboard(signedMsg)) {
        setButtonState(btn, 'success');
    } else {
        setButtonState(btn, 'error');
    }
});

document.getElementById('exportSettings')?.addEventListener('click', async () => {
    const btn = document.getElementById('exportSettings');
    setButtonLoading(btn, true);

    try {
        const storage = await chrome.storage.local.get(['settings', 'publicKeyArmored', 'defaultRecipient']);
        const hasRecipientData = storage.publicKeyArmored || storage.defaultRecipient;

        if (hasRecipientData) {
            const confirmed = confirm('Your settings export will include your recipient\'s public key and email address. Make sure you trust the recipient before sharing this file.');
            if (!confirmed) {
                setButtonLoading(btn, false);
                return;
            }
        }

        const exportData = {
            version: 1,
            exportedAt: new Date().toISOString(),
            settings: storage.settings || {},
            publicKeyArmored: storage.publicKeyArmored || null,
            defaultRecipient: storage.defaultRecipient || null
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ciphermail-settings-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);

        showToast('Settings exported!', 'success');
        setButtonState(btn, 'success');
    } catch (err) {
        showToast('Export failed', 'error');
        setButtonState(btn, 'error');
    } finally {
        setButtonLoading(btn, false);
    }
});

document.getElementById('importSettings')?.addEventListener('click', () => {
    document.getElementById('settingsFile').click();
});

document.getElementById('settingsFile')?.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (event) => {
        try {
            const importData = JSON.parse(event.target.result);

            if (importData.version !== 1) {
                showToast('Incompatible settings file', 'error');
                return;
            }

            await chrome.storage.local.set({
                settings: importData.settings,
                publicKeyArmored: importData.publicKeyArmored,
                defaultRecipient: importData.defaultRecipient
            });

            applySettings(importData.settings);
            showToast('Settings imported!', 'success');

            if (importData.publicKeyArmored) {
                document.getElementById('pubKey').value = importData.publicKeyArmored;
            }
        } catch (err) {
            showToast('Failed to import settings', 'error');
        }
    };
    reader.readAsText(file);
    e.target.value = '';
});

function applySettings(settings) {
    if (!settings) return;

    if (settings.sessionTimeout !== undefined) {
        sessionTimeout = settings.sessionTimeout;
        document.getElementById('sessionTimeout').checked = sessionTimeout;
        document.getElementById('timeoutSetting').style.display = sessionTimeout ? 'block' : 'none';
    }

    if (settings.timeoutMinutes !== undefined) {
        timeoutMinutes = settings.timeoutMinutes;
        document.getElementById('timeoutMinutes').value = timeoutMinutes;
    }

    if (settings.secureClipboard !== undefined) {
        secureClipboard = settings.secureClipboard;
        document.getElementById('secureClipboard').checked = secureClipboard;
        document.getElementById('clipboardTimeoutSetting').style.display = secureClipboard ? 'block' : 'none';
    }

    if (settings.clipboardSeconds !== undefined) {
        clipboardSeconds = settings.clipboardSeconds;
        document.getElementById('clipboardSeconds').value = clipboardSeconds;
    }

    if (settings.darkMode !== undefined) {
        darkMode = settings.darkMode;
        document.getElementById('darkMode').checked = darkMode;
        document.body.classList.toggle('dark', darkMode);
    }

    if (settings.autoSign !== undefined) {
        autoSign = settings.autoSign;
        document.getElementById('autoSign').checked = autoSign;
    }

    if (settings.autoLookup !== undefined) {
        autoLookup = settings.autoLookup;
        document.getElementById('autoLookup').checked = autoLookup;
    }

    if (settings.confirmEncrypt !== undefined) {
        confirmEncrypt = settings.confirmEncrypt;
        document.getElementById('confirmEncrypt').checked = confirmEncrypt;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

let currentlyRecordingShortcut = null;

function formatShortcutForDisplay(shortcut) {
    if (!shortcut || shortcut === 'Unassigned') return 'Unassigned';

    const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
    let display = shortcut;

    if (isMac) {
        display = shortcut.replace(/Ctrl\+/g, '⌘').replace(/Ctrl/gi, '⌘');
    } else {
        display = shortcut.replace(/Command\+/g, 'Ctrl+').replace(/Command/gi, 'Ctrl');
    }

    display = display.replace(/\+/g, ' + ');

    return display;
}

function normalizeShortcutForChrome(shortcut) {
    return shortcut
        .replace(/⌘/g, 'Command+')
        .replace(/ctrl\+/gi, 'Ctrl+')
        .replace(/alt\+/gi, 'Alt+')
        .replace(/shift\+/gi, 'Shift+')
        .replace(/meta\+/gi, 'Meta+');
}

async function loadShortcuts() {
    try {
        const response = await chrome.runtime.sendMessage({ type: 'GET_SHORTCUTS' });
        if (response && response.success && response.shortcuts) {
            for (const [cmdName, info] of Object.entries(response.shortcuts)) {
                const btn = document.getElementById(`shortcut-${cmdName}`);
                if (btn) {
                    const display = formatShortcutForDisplay(info.current);
                    btn.textContent = display;
                    btn.dataset.shortcut = info.current;
                }
            }
        }
    } catch (err) {
        console.error('Failed to load shortcuts:', err);
    }
}

document.querySelectorAll('.shortcut-button').forEach(btn => {
    btn.addEventListener('click', async (e) => {
        e.preventDefault();

        if (currentlyRecordingShortcut) {
            currentlyRecordingShortcut.classList.remove('recording');
        }

        btn.classList.add('recording');
        btn.textContent = 'Press keys...';
        currentlyRecordingShortcut = btn;

        const errorEl = document.getElementById('shortcut-error');
        if (errorEl) errorEl.style.display = 'none';
    });
});

document.querySelectorAll('.shortcut-button').forEach(btn => {
    btn.addEventListener('keydown', async (e) => {
        if (!btn.classList.contains('recording')) return;

        e.preventDefault();
        e.stopPropagation();

        if (e.key === 'Escape') {
            const cmdName = btn.dataset.command;
            const response = await chrome.runtime.sendMessage({ type: 'GET_SHORTCUTS' });
            if (response && response.shortcuts && response.shortcuts[cmdName]) {
                btn.textContent = formatShortcutForDisplay(response.shortcuts[cmdName].current);
            }
            btn.classList.remove('recording');
            currentlyRecordingShortcut = null;
            return;
        }

        if (e.key === 'Enter') {
            const cmdName = btn.dataset.command;
            const shortcut = btn.dataset.shortcut;

            if (shortcut && shortcut !== 'Unassigned') {
                const updateResponse = await chrome.runtime.sendMessage({
                    type: 'UPDATE_SHORTCUT',
                    command: cmdName,
                    shortcut: normalizeShortcutForChrome(shortcut)
                });

                if (updateResponse && !updateResponse.success) {
                    const errorEl = document.getElementById('shortcut-error');
                    if (errorEl) {
                        errorEl.textContent = updateResponse.error || 'Failed to update shortcut';
                        errorEl.style.display = 'block';
                    }
                } else {
                    showToast('Shortcut updated!', 'success');
                }
            }

            btn.classList.remove('recording');
            currentlyRecordingShortcut = null;
            return;
        }

        const parts = [];
        if (e.ctrlKey) parts.push('Ctrl');
        if (e.altKey) parts.push('Alt');
        if (e.shiftKey) parts.push('Shift');
        if (e.metaKey) parts.push('Command');

        let key = e.key;
        if (key.length === 1) {
            key = key.toUpperCase();
        } else if (key.startsWith('F') && /F\d{1,2}/.test(key)) {
            // Keep function keys as is
        } else if (key !== 'Control' && key !== 'Alt' && key !== 'Shift' && key !== 'Meta') {
            parts.push(key.toUpperCase());
        }

        if (parts.length > 0) {
            const shortcut = parts.join('+');
            btn.textContent = formatShortcutForDisplay(shortcut);
            btn.dataset.shortcut = shortcut;
        }
    });
});

document.querySelectorAll('.shortcut-reset').forEach(btn => {
    btn.addEventListener('click', async (e) => {
        e.preventDefault();
        const cmdName = btn.dataset.command;

        const response = await chrome.runtime.sendMessage({
            type: 'UPDATE_SHORTCUT',
            command: cmdName,
            shortcut: 'reset'
        });

        if (response && response.success) {
            await loadShortcuts();
            showToast('Shortcut reset to default', 'info');
        } else {
            const errorEl = document.getElementById('shortcut-error');
            if (errorEl) {
                errorEl.textContent = response?.error || 'Failed to reset shortcut';
                errorEl.style.display = 'block';
            }
        }
    });
});

document.getElementById('resetAllShortcuts')?.addEventListener('click', async () => {
    if (!confirm('Reset all shortcuts to their default values?')) return;

    const response = await chrome.runtime.sendMessage({ type: 'RESET_SHORTCUTS' });

    if (response && response.success) {
        await loadShortcuts();
        showToast('All shortcuts reset to defaults', 'info');
    } else {
        const errorEl = document.getElementById('shortcut-error');
        if (errorEl) {
            errorEl.textContent = response?.error || 'Failed to reset shortcuts';
            errorEl.style.display = 'block';
        }
    }
});

document.addEventListener('click', (e) => {
    if (currentlyRecordingShortcut && !e.target.classList.contains('shortcut-button')) {
        currentlyRecordingShortcut.classList.remove('recording');
        const cmdName = currentlyRecordingShortcut.dataset.command;
        loadShortcuts().then(() => {
            const btn = document.getElementById(`shortcut-${cmdName}`);
            if (btn) {
                btn.textContent = btn.dataset.shortcut || 'Unassigned';
            }
        });
        currentlyRecordingShortcut = null;
    }
});

chrome.storage.local.get(['settings', 'publicKeyArmored', 'myPublicKey', 'sessionLocked'], (data) => {
    if (data.settings) {
        applySettings(data.settings);
    }

    if (data.publicKeyArmored) {
        document.getElementById('pubKey').value = data.publicKeyArmored;
    }

    if (data.myPublicKey) {
        document.getElementById('myPubKey').value = data.myPublicKey;
    }

    if (data.sessionLocked) {
        chrome.storage.local.set({ sessionLocked: false });
    }

    loadStoredKeys();
    startActivityMonitor();
    loadShortcuts();
});