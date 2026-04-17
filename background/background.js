importScripts('../libs/openpgp.min.js');

const AES_GCM_ALGO = 'AES-GCM';
const PBKDF2_ITERATIONS = 310000;
const MIN_PASSPHRASE_LENGTH = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 30 * 60 * 1000;

const BRUTE_FORCE_KEY = 'bruteForceData';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ALLOWED_ORIGINS = ['https://mail.google.com'];

function isValidEmail(email) {
    if (!email || typeof email !== 'string') return false;
    const trimmed = email.trim();
    return EMAIL_REGEX.test(trimmed) && trimmed.length <= 254;
}

const MAX_MESSAGE_LENGTH = 100000;
const MAX_KEY_LENGTH = 50000;

function validateMessageLength(text, maxLength = MAX_MESSAGE_LENGTH) {
    if (!text || typeof text !== 'string') {
        return { valid: false, error: 'Invalid message format' };
    }
    if (text.length > maxLength) {
        return { valid: false, error: `Message exceeds maximum length of ${maxLength} characters` };
    }
    return { valid: true };
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

async function getBruteForceData() {
    const result = await chrome.storage.local.get(BRUTE_FORCE_KEY);
    return result[BRUTE_FORCE_KEY] || { attempts: 0, lockoutUntil: 0, backoffMultiplier: 1 };
}

async function recordFailedAttempt() {
    const data = await getBruteForceData();
    data.attempts += 1;
    data.backoffMultiplier = Math.min(data.backoffMultiplier + 1, 8);

    if (data.attempts >= MAX_FAILED_ATTEMPTS) {
        const baseLockout = LOCKOUT_DURATION_MS;
        const lockoutMs = baseLockout * data.backoffMultiplier;
        data.lockoutUntil = Date.now() + lockoutMs;
        data.attempts = 0;
    }
    await chrome.storage.local.set({ [BRUTE_FORCE_KEY]: data });
}

async function resetBruteForceAttempts() {
    await chrome.storage.local.set({ [BRUTE_FORCE_KEY]: { attempts: 0, lockoutUntil: 0, backoffMultiplier: 1 } });
}

async function isLockedOut() {
    const data = await getBruteForceData();
    if (data.lockoutUntil > Date.now()) {
        const remainingMinutes = Math.ceil((data.lockoutUntil - Date.now()) / 60000);
        return { locked: true, remainingMinutes, backoffMultiplier: data.backoffMultiplier };
    }
    if (data.lockoutUntil > 0 && data.lockoutUntil <= Date.now()) {
        await resetBruteForceAttempts();
    }
    return { locked: false, backoffMultiplier: 1 };
}

let pendingPassphraseResolver = null;
let passphraseRequestQueue = [];
const pendingRequests = new Map();

function processPassphraseQueue(passphrase) {
    if (passphraseRequestQueue.length > 0) {
        const { resolve } = passphraseRequestQueue.shift();
        resolve(passphrase);
    } else {
        pendingPassphraseResolver = null;
    }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (sender.tab && !isAllowedOrigin(sender.tab.url)) {
        sendResponse({ error: 'Unauthorized: Invalid origin' });
        return false;
    }

    if (request.type === 'ENCRYPT') {
        handleEncryption(request.data).then(sendResponse);
        return true;
    } else if (request.type === 'DECRYPT') {
        handleDecryption(request.data, request.passphrase).then(sendResponse);
        return true;
    } else if (request.type === 'GENERATE_KEYS') {
        handleKeyGeneration(request.name, request.email, request.passphrase).then(sendResponse);
        return true;
    } else if (request.type === 'CHECK_LOCKOUT') {
        isLockedOut().then(sendResponse);
        return true;
    } else if (request.type === 'VALIDATE_PASSPHRASE') {
        const error = validatePassphrase(request.passphrase);
        sendResponse({ valid: !error, error });
        return true;
    } else if (request.type === 'REQUEST_PASSPHRASE') {
        const requestId = crypto.randomUUID();
        const promise = new Promise((resolve) => {
            passphraseRequestQueue.push({ requestId, resolve });
        });

        pendingRequests.set(requestId, { resolve: sendResponse, timeout: Date.now() + 30000 });

        if (!pendingPassphraseResolver) {
            chrome.offscreen.createDocument({
                url: 'content/offscreen.html',
                reasons: ['USER_INTERACTION'],
                justification: 'Secure passphrase entry for PGP decryption'
            }).then(() => {
                pendingPassphraseResolver = { requestId, sendResponse };
            }).catch(err => {
                passphraseRequestQueue = passphraseRequestQueue.filter(r => r.requestId !== requestId);
                pendingRequests.delete(requestId);
                sendResponse({ error: err.message });
            });
        }

        promise.then((passphrase) => {
            const pending = pendingRequests.get(requestId);
            if (pending) {
                pending.resolve({ passphrase });
                pendingRequests.delete(requestId);
            }
        });

        return true;
    } else if (request.type === 'PASSPHRASE_RESPONSE') {
        const passphrase = request.passphrase;
        const resolver = pendingPassphraseResolver;
        if (resolver) {
            const queueItem = passphraseRequestQueue.find(r => r.requestId === resolver.requestId);
            if (queueItem) {
                queueItem.resolve(passphrase);
            }
            pendingPassphraseResolver = null;
            passphraseRequestQueue = [];
        }
        return false;
    } else if (request.type === 'LOOKUP_KEY') {
        handleKeyLookup(request.email).then(sendResponse);
        return true;
    } else if (request.type === 'VERIFY_SIGNATURE') {
        handleVerifySignature(request.message).then(sendResponse);
        return true;
    } else if (request.type === 'SIGN_MESSAGE') {
        handleSignMessage(request.text, request.passphrase).then(sendResponse);
        return true;
    } else if (request.type === 'ENCRYPT_AND_SIGN') {
        handleEncryptAndSign(request.text, request.passphrase).then(sendResponse);
        return true;
    } else if (request.type === 'EXPORT_KEYS') {
        handleExportKeys(request.passphrase).then(sendResponse);
        return true;
    } else if (request.type === 'IMPORT_KEYS') {
        handleImportKeys(request.backupData, request.passphrase).then(sendResponse);
        return true;
    } else if (request.type === 'ROTATE_KEYS') {
        handleKeyRotation(request.name, request.email, request.passphrase).then(sendResponse);
        return true;
    } else if (request.type === 'GET_STORED_KEYS') {
        handleGetStoredKeys().then(sendResponse);
        return true;
    } else if (request.type === 'DELETE_KEY') {
        handleDeleteKey(request.keyType).then(sendResponse);
        return true;
    } else if (request.type === 'SET_DEFAULT_RECIPIENT') {
        handleSetDefaultRecipient(request.email, request.key).then(sendResponse);
        return true;
    } else if (request.type === 'ADD_RECIPIENT') {
        handleAddRecipient(request.email, request.key).then(sendResponse);
        return true;
    } else if (request.type === 'REMOVE_RECIPIENT') {
        handleRemoveRecipient(request.email).then(sendResponse);
        return true;
    } else if (request.type === 'LIST_RECIPIENTS') {
        handleListRecipients().then(sendResponse);
        return true;
    } else if (request.type === 'SET_DEFAULT_RECIPIENT_EMAIL') {
        handleSetDefaultRecipientEmail(request.email).then(sendResponse);
        return true;
    } else if (request.type === 'VERIFY_RECIPIENT_FINGERPRINT') {
        handleVerifyRecipientFingerprint(request.email).then(sendResponse);
        return true;
    } else if (request.type === 'GET_SHORTCUTS') {
        handleGetShortcuts().then(sendResponse);
        return true;
    } else if (request.type === 'UPDATE_SHORTCUT') {
        handleUpdateShortcut(request.command, request.shortcut).then(sendResponse);
        return true;
    } else if (request.type === 'RESET_SHORTCUTS') {
        handleResetShortcuts().then(sendResponse);
        return true;
    }
});

async function handleEncryption(text, recipientEmail = null) {
    try {
        const validation = validateMessageLength(text);
        if (!validation.valid) {
            return { success: false, error: validation.error };
        }

        const storage = await chrome.storage.local.get(['recipientKeys', 'defaultRecipientEmail']);
        const recipientKeys = storage.recipientKeys || {};
        let publicKeyArmored = null;
        let selectedEmail = null;

        if (recipientEmail && recipientKeys[recipientEmail]) {
            publicKeyArmored = recipientKeys[recipientEmail].armoredKey;
            selectedEmail = recipientEmail;
        } else if (storage.defaultRecipientEmail && recipientKeys[storage.defaultRecipientEmail]) {
            publicKeyArmored = recipientKeys[storage.defaultRecipientEmail].armoredKey;
            selectedEmail = storage.defaultRecipientEmail;
        } else {
            const keys = Object.values(recipientKeys);
            if (keys.length > 0) {
                publicKeyArmored = keys[0].armoredKey;
                selectedEmail = keys[0].email;
            }
        }

        if (!publicKeyArmored) {
            return { success: false, error: 'No recipient public key configured. Please add a recipient key first.' };
        }

        const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
        const message = await openpgp.createMessage({ text: text });
        const encrypted = await openpgp.encrypt({
            message,
            encryptionKeys: publicKey
        });
        return { success: true, data: encrypted, recipientEmail: selectedEmail };
    } catch (err) {
        return { success: false, error: 'Encryption failed. Please try again.' };
    }
}

async function handleEncryptWithRecipient(text, recipientEmail) {
    try {
        const validation = validateMessageLength(text);
        if (!validation.valid) {
            return { success: false, error: validation.error };
        }

        const storage = await chrome.storage.local.get('recipientKeys');
        const recipientKeys = storage.recipientKeys || {};

        if (!recipientEmail) {
            return { success: false, error: 'Recipient email is required.' };
        }

        if (!recipientKeys[recipientEmail]) {
            return { success: false, error: `No key found for recipient: ${recipientEmail}` };
        }

        const publicKeyArmored = recipientKeys[recipientEmail].armoredKey;
        const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
        const message = await openpgp.createMessage({ text: text });
        const encrypted = await openpgp.encrypt({
            message,
            encryptionKeys: publicKey
        });
        return { success: true, data: encrypted, recipientEmail };
    } catch (err) {
        return { success: false, error: 'Encryption failed. Please try again.' };
    }
}

async function handleDecryption(armoredMessage, passphrase) {
    let localPassphrase = passphrase;
    try {
        const lockoutStatus = await isLockedOut();
        if (lockoutStatus.locked) {
            return {
                success: false,
                error: `Too many failed attempts. Please try again in ${lockoutStatus.remainingMinutes} minutes.`
            };
        }

        const validation = validateMessageLength(armoredMessage, MAX_KEY_LENGTH);
        if (!validation.valid) {
            return { success: false, error: validation.error };
        }

        const storage = await chrome.storage.local.get(['encryptedPrivateKey', 'salt', 'iv']);
        if (!storage.encryptedPrivateKey) {
            return { success: false, error: 'No private key found. Please generate keys first.' };
        }

        const passphraseError = validatePassphrase(passphrase);
        if (passphraseError) {
            return { success: false, error: 'Invalid passphrase format.' };
        }

        const privateKeyArmored = await aesDecrypt(
            new Uint8Array(storage.encryptedPrivateKey),
            new Uint8Array(storage.salt),
            new Uint8Array(storage.iv),
            localPassphrase
        );

        const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
        const message = await openpgp.readMessage({ armoredMessage });
        const { data: decrypted } = await openpgp.decrypt({
            message,
            decryptionKeys: privateKey
        });

        await resetBruteForceAttempts();
        return { success: true, data: decrypted };
    } catch (err) {
        await recordFailedAttempt();
        const lockoutStatus = await isLockedOut();
        if (lockoutStatus.locked) {
            return {
                success: false,
                error: `Invalid passphrase. Too many failed attempts. Please try again in ${lockoutStatus.remainingMinutes} minutes.`
            };
        }
        return { success: false, error: 'Decryption failed. Please check your passphrase and try again.' };
    } finally {
        localPassphrase = null;
    }
}

async function handleKeyGeneration(name, email, passphrase) {
    try {
        const passphraseError = validatePassphrase(passphrase);
        if (passphraseError) {
            return { success: false, error: passphraseError };
        }

        if (!name || !email) {
            return { success: false, error: 'Name and email are required.' };
        }

        const { privateKey, publicKey } = await openpgp.generateKey({
            type: 'rsa',
            rsaBits: 4096,
            userIDs: [{ name, email }],
        });

        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedPrivateKey = await aesEncrypt(privateKey, salt, iv, passphrase);

        await chrome.storage.local.set({
            myPublicKey: publicKey,
            encryptedPrivateKey: Array.from(new Uint8Array(encryptedPrivateKey)),
            salt: Array.from(salt),
            iv: Array.from(iv)
        });

        await resetBruteForceAttempts();
        return { success: true, publicKey };
    } catch (err) {
        return { success: false, error: 'Key generation failed. Please try again.' };
    }
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

const KEY_SERVERS = [
    'https://keys.openpgp.org',
    'https://keyserver.ubuntu.com',
    'https://pgpkeys.eu'
];

async function handleKeyLookup(email) {
    if (!isValidEmail(email)) {
        return { success: false, error: 'Invalid email address' };
    }

    const normalizedEmail = email.toLowerCase().trim();

    for (const server of KEY_SERVERS) {
        try {
            const response = await fetch(`${server}/pks/lookup?op=get&search=${encodeURIComponent(normalizedEmail)}`, {
                method: 'GET',
                headers: { 'Accept': 'application/pgp-keys' }
            });

            if (response.ok) {
                const armoredKey = await response.text();

                if (armoredKey && armoredKey.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
                    try {
                        const publicKey = await openpgp.readKey({ armoredKey });
                        const users = publicKey.getPrimaryUser();

                        return {
                            success: true,
                            key: armoredKey,
                            fingerprint: publicKey.getFingerprint().toUpperCase(),
                            algorithm: publicKey.getAlgorithmInfo().bits ? `RSA-${publicKey.getAlgorithmInfo().bits}` : 'RSA',
                            user: users ? users.user.userID.userID : normalizedEmail,
                            server: new URL(server).hostname
                        };
                    } catch (err) {
                        continue;
                    }
                }
            }
        } catch (err) {
            continue;
        }
    }

    return { success: false, error: 'No public key found for this email address' };
}

async function handleVerifySignature(armoredMessage) {
    if (!armoredMessage) {
        return { success: false, error: 'No message provided' };
    }

    try {
        const message = await openpgp.readMessage({ armoredMessage });

        const verified = await openpgp.verify({
            message,
            verificationKeys: message.getEncryptionKeyIDs ? undefined : null
        });

        const signatureInfo = verified.signatures?.[0];

        if (signatureInfo) {
            const key = signatureInfo.key;
            const fingerprint = key?.getFingerprint()?.toUpperCase();
            const primaryUser = key?.getPrimaryUser();

            return {
                success: true,
                verified: signatureInfo.verified === true,
                signed: true,
                signer: primaryUser ? primaryUser.user.userID.userID : 'Unknown',
                fingerprint: fingerprint,
                algorithm: key?.getAlgorithmInfo()?.bits ? `RSA-${key.getAlgorithmInfo().bits}` : 'RSA',
                keyID: signatureInfo.keyID?.toHex()?.toUpperCase()
            };
        }

        return { success: true, verified: false, signed: false };
    } catch (err) {
        return { success: false, error: 'Failed to verify signature: ' + err.message };
    }
}

async function handleSignMessage(text, passphrase) {
    if (!text) {
        return { success: false, error: 'No text provided' };
    }

    const validation = validateMessageLength(text);
    if (!validation.valid) {
        return { success: false, error: validation.error };
    }

    try {
        const storage = await chrome.storage.local.get(['encryptedPrivateKey', 'salt', 'iv']);
        if (!storage.encryptedPrivateKey) {
            return { success: false, error: 'No private key found. Please generate keys first.' };
        }

        if (!passphrase) {
            return { success: false, error: 'Passphrase is required for signing.' };
        }

        const privateKeyArmored = await aesDecrypt(
            new Uint8Array(storage.encryptedPrivateKey),
            new Uint8Array(storage.salt),
            new Uint8Array(storage.iv),
            passphrase
        );

        const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
        const message = await openpgp.createMessage({ text });

        const signed = await openpgp.sign({
            message,
            signingKeys: privateKey
        });

        return { success: true, data: signed };
    } catch (err) {
        return { success: false, error: 'Signing failed: ' + err.message };
    }
}

async function handleEncryptAndSign(text, passphrase) {
    if (!text) {
        return { success: false, error: 'No text provided' };
    }

    const validation = validateMessageLength(text);
    if (!validation.valid) {
        return { success: false, error: validation.error };
    }

    try {
        const storage = await chrome.storage.local.get(['encryptedPrivateKey', 'salt', 'iv', 'publicKeyArmored']);
        if (!storage.encryptedPrivateKey) {
            return { success: false, error: 'No private key found. Please generate keys first.' };
        }
        if (!storage.publicKeyArmored) {
            return { success: false, error: 'No recipient public key configured.' };
        }

        if (!passphrase) {
            return { success: false, error: 'Passphrase is required for signing.' };
        }

        const privateKeyArmored = await aesDecrypt(
            new Uint8Array(storage.encryptedPrivateKey),
            new Uint8Array(storage.salt),
            new Uint8Array(storage.iv),
            passphrase
        );

        const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
        const publicKey = await openpgp.readKey({ armoredKey: storage.publicKeyArmored });
        const message = await openpgp.createMessage({ text });

        const encrypted = await openpgp.encrypt({
            message,
            encryptionKeys: publicKey,
            signingKeys: privateKey
        });

        return { success: true, data: encrypted, signed: true };
    } catch (err) {
        return { success: false, error: 'Encrypt and sign failed: ' + err.message };
    }
}

async function handleExportKeys(passphrase) {
    try {
        const storage = await chrome.storage.local.get(['encryptedPrivateKey', 'salt', 'iv', 'myPublicKey']);
        if (!storage.encryptedPrivateKey || !storage.myPublicKey) {
            return { success: false, error: 'No keys found to export.' };
        }

        if (!passphrase) {
            return { success: false, error: 'Passphrase is required to export keys.' };
        }

        const backupData = {
            version: 1,
            myPublicKey: storage.myPublicKey,
            encryptedPrivateKey: storage.encryptedPrivateKey,
            salt: storage.salt,
            iv: storage.iv,
            exportedAt: new Date().toISOString()
        };

        const encoder = new TextEncoder();
        const dataStr = JSON.stringify(backupData);
        const exportedAt = Date.now().toString();

        const key = await deriveKey(passphrase, new Uint8Array([...encoder.encode('backup'), ...encoder.encode(exportedAt)]));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: AES_GCM_ALGO, iv },
            key,
            encoder.encode(dataStr)
        );

        const combined = {
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(encrypted)),
            salt: Array.from(new Uint8Array([...encoder.encode('backup'), ...encoder.encode(exportedAt)])),
            timestamp: exportedAt
        };

        return { success: true, backup: JSON.stringify(combined) };
    } catch (err) {
        return { success: false, error: 'Export failed: ' + err.message };
    }
}

async function handleImportKeys(backupJson, passphrase) {
    try {
        const combined = JSON.parse(backupJson);
        const { iv, data, salt, timestamp } = combined;

        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', encoder.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']
        );
        const key = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: new Uint8Array(salt), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
            keyMaterial,
            { name: AES_GCM_ALGO, length: 256 },
            false, ['decrypt']
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: AES_GCM_ALGO, iv: new Uint8Array(iv) },
            key,
            new Uint8Array(data)
        );

        const decoder = new TextDecoder();
        const backupData = JSON.parse(decoder.decode(decrypted));

        if (!backupData.myPublicKey || !backupData.encryptedPrivateKey) {
            return { success: false, error: 'Invalid backup data.' };
        }

        await chrome.storage.local.set({
            myPublicKey: backupData.myPublicKey,
            encryptedPrivateKey: backupData.encryptedPrivateKey,
            salt: backupData.salt,
            iv: backupData.iv
        });

        return { success: true, publicKey: backupData.myPublicKey };
    } catch (err) {
        return { success: false, error: 'Import failed. Check your passphrase and try again.' };
    }
}

async function handleKeyRotation(name, email, passphrase) {
    try {
        const passphraseError = validatePassphrase(passphrase);
        if (passphraseError) {
            return { success: false, error: passphraseError };
        }

        if (!name || !email) {
            return { success: false, error: 'Name and email are required.' };
        }

        const { privateKey, publicKey } = await openpgp.generateKey({
            type: 'rsa',
            rsaBits: 4096,
            userIDs: [{ name, email }],
        });

        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedPrivateKey = await aesEncrypt(privateKey, salt, iv, passphrase);

        await chrome.storage.local.set({
            myPublicKey: publicKey,
            encryptedPrivateKey: Array.from(new Uint8Array(encryptedPrivateKey)),
            salt: Array.from(salt),
            iv: Array.from(iv)
        });

        await resetBruteForceAttempts();
        return { success: true, publicKey };
    } catch (err) {
        return { success: false, error: 'Key rotation failed: ' + err.message };
    }
}

async function handleGetStoredKeys() {
    try {
        const storage = await chrome.storage.local.get(['myPublicKey', 'publicKeyArmored', 'defaultRecipient']);
        const result = {
            success: true,
            hasMyKeys: !!storage.myPublicKey,
            hasRecipientKey: !!storage.publicKeyArmored,
            defaultRecipient: storage.defaultRecipient || null
        };

        if (storage.myPublicKey) {
            try {
                const key = await openpgp.readKey({ armoredKey: storage.myPublicKey });
                const primaryUser = key.getPrimaryUser();
                result.myKeyInfo = {
                    fingerprint: key.getFingerprint().toUpperCase(),
                    algorithm: key.getAlgorithmInfo().bits ? `RSA-${key.getAlgorithmInfo().bits}` : 'RSA',
                    user: primaryUser ? primaryUser.user.userID.userID : 'Unknown'
                };
            } catch (e) {
                result.myKeyInfo = null;
            }
        }

        const recipientKeys = storage.recipientKeys || {};
        const recipientEmails = Object.keys(recipientKeys);
        result.hasRecipientKey = recipientEmails.length > 0;
        result.defaultRecipient = storage.defaultRecipientEmail || (recipientEmails.length > 0 ? recipientEmails[0] : null);

        if (recipientEmails.length > 0) {
            const firstEmail = recipientEmails[0];
            const firstRecipient = recipientKeys[firstEmail];
            result.recipientKeyInfo = {
                fingerprint: firstRecipient.fingerprint,
                algorithm: firstRecipient.algorithm,
                user: firstRecipient.userInfo
            };
        }

        return result;
    } catch (err) {
        return { success: false, error: 'Failed to get stored keys.' };
    }
}

async function handleDeleteKey(keyType) {
    try {
        if (keyType === 'myKeys') {
            await chrome.storage.local.remove(['myPublicKey', 'encryptedPrivateKey', 'salt', 'iv']);
            await resetBruteForceAttempts();
        } else if (keyType === 'recipientKey') {
            await chrome.storage.local.remove(['recipientKeys', 'defaultRecipientEmail']);
        }
        return { success: true };
    } catch (err) {
        return { success: false, error: 'Failed to delete key: ' + err.message };
    }
}

async function handleSetDefaultRecipient(email, key) {
    try {
        const data = { email, key, setAt: new Date().toISOString() };
        await chrome.storage.local.set({ defaultRecipient: data });
        return { success: true };
    } catch (err) {
        return { success: false, error: 'Failed to set default recipient: ' + err.message };
    }
}

async function handleAddRecipient(email, armoredKey) {
    try {
        if (!isValidEmail(email)) {
            return { success: false, error: 'Invalid email address' };
        }

        if (!armoredKey || !armoredKey.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
            return { success: false, error: 'Invalid PGP public key' };
        }

        const publicKey = await openpgp.readKey({ armoredKey });
        if (!publicKey.isPublic()) {
            return { success: false, error: 'This appears to be a private key. Please provide a public key.' };
        }

        const primaryUser = publicKey.getPrimaryUser();
        const fingerprint = publicKey.getFingerprint().toUpperCase();
        const userInfo = primaryUser ? primaryUser.user.userID.userID : email;

        const storage = await chrome.storage.local.get('recipientKeys');
        const recipientKeys = storage.recipientKeys || {};

        const existingKey = recipientKeys[email];
        let isNewFingerprint = true;
        let isTrusted = false;

        if (existingKey) {
            isNewFingerprint = existingKey.fingerprint !== fingerprint;
            isTrusted = existingKey.trusted && !isNewFingerprint;
        }

        recipientKeys[email] = {
            armoredKey,
            fingerprint,
            userInfo,
            algorithm: publicKey.getAlgorithmInfo().bits ? `RSA-${publicKey.getAlgorithmInfo().bits}` : 'RSA',
            addedAt: new Date().toISOString(),
            trusted: isTrusted,
            firstFingerprint: existingKey?.firstFingerprint || fingerprint
        };

        await chrome.storage.local.set({ recipientKeys });

        return {
            success: true,
            fingerprint,
            isNewFingerprint,
            isTrusted,
            userInfo
        };
    } catch (err) {
        return { success: false, error: 'Failed to add recipient: ' + err.message };
    }
}

async function handleRemoveRecipient(email) {
    try {
        const storage = await chrome.storage.local.get(['recipientKeys', 'defaultRecipientEmail']);
        const recipientKeys = storage.recipientKeys || {};

        if (!recipientKeys[email]) {
            return { success: false, error: 'Recipient not found' };
        }

        delete recipientKeys[email];
        await chrome.storage.local.set({ recipientKeys });

        if (storage.defaultRecipientEmail === email) {
            const remainingEmails = Object.keys(recipientKeys);
            const newDefault = remainingEmails.length > 0 ? remainingEmails[0] : null;
            await chrome.storage.local.set({ defaultRecipientEmail: newDefault });
        }

        return { success: true };
    } catch (err) {
        return { success: false, error: 'Failed to remove recipient: ' + err.message };
    }
}

async function handleListRecipients() {
    try {
        const storage = await chrome.storage.local.get(['recipientKeys', 'defaultRecipientEmail']);
        const recipientKeys = storage.recipientKeys || {};
        const defaultRecipientEmail = storage.defaultRecipientEmail || null;

        const recipients = Object.entries(recipientKeys).map(([email, data]) => ({
            email,
            fingerprint: data.fingerprint,
            userInfo: data.userInfo,
            algorithm: data.algorithm,
            trusted: data.trusted,
            isDefault: email === defaultRecipientEmail,
            firstFingerprint: data.firstFingerprint,
            isNewFingerprint: data.firstFingerprint !== data.fingerprint,
            addedAt: data.addedAt
        }));

        return {
            success: true,
            recipients,
            defaultRecipientEmail
        };
    } catch (err) {
        return { success: false, error: 'Failed to list recipients: ' + err.message };
    }
}

async function handleSetDefaultRecipientEmail(email) {
    try {
        const storage = await chrome.storage.local.get('recipientKeys');
        const recipientKeys = storage.recipientKeys || {};

        if (email && !recipientKeys[email]) {
            return { success: false, error: 'Recipient not found' };
        }

        await chrome.storage.local.set({ defaultRecipientEmail: email || null });
        return { success: true };
    } catch (err) {
        return { success: false, error: 'Failed to set default recipient: ' + err.message };
    }
}

async function handleVerifyRecipientFingerprint(email) {
    try {
        const storage = await chrome.storage.local.get('recipientKeys');
        const recipientKeys = storage.recipientKeys || {};

        if (!recipientKeys[email]) {
            return { success: false, error: 'Recipient not found' };
        }

        const data = recipientKeys[email];
        const currentKey = await openpgp.readKey({ armoredKey: data.armoredKey });
        const currentFingerprint = currentKey.getFingerprint().toUpperCase();

        return {
            success: true,
            email,
            storedFingerprint: data.fingerprint,
            currentFingerprint,
            isMatch: data.fingerprint === currentFingerprint,
            isTrusted: data.trusted && data.firstFingerprint === currentFingerprint,
            firstFingerprint: data.firstFingerprint
        };
    } catch (err) {
        return { success: false, error: 'Failed to verify fingerprint: ' + err.message };
    }
}

const DEFAULT_SHORTCUTS = {
    encrypt: { default: 'Ctrl+Shift+E', mac: 'Command+Shift+E' },
    decrypt: { default: 'Ctrl+Shift+D', mac: 'Command+Shift+D' },
    sign: { default: 'Ctrl+Shift+S', mac: 'Command+Shift+S' }
};

async function handleGetShortcuts() {
    try {
        const [commands, settings] = await Promise.all([
            chrome.commands.getAll(),
            chrome.storage.local.get('shortcuts')
        ]);

        const shortcuts = {};
        for (const cmd of commands) {
            if (cmd.name && DEFAULT_SHORTCUTS[cmd.name]) {
                shortcuts[cmd.name] = {
                    current: cmd.shortcut || 'Unassigned',
                    description: cmd.description || '',
                    default: DEFAULT_SHORTCUTS[cmd.name],
                    isCustom: settings.shortcuts?.[cmd.name] ? true : false
                };
            }
        }

        return { success: true, shortcuts };
    } catch (err) {
        return { success: false, error: 'Failed to get shortcuts: ' + err.message };
    }
}

async function handleUpdateShortcut(command, shortcut) {
    try {
        if (!DEFAULT_SHORTCUTS[command]) {
            return { success: false, error: 'Invalid command' };
        }

        if (shortcut === 'Unassigned' || shortcut === '') {
            return { success: false, error: 'Shortcut cannot be empty' };
        }

        if (shortcut !== 'reset') {
            const shortcutRegex = /^((Ctrl|Alt|Shift|Meta|Command|Command\+Shift|Command\+Alt)\+)*(Ctrl|Alt|Shift|Meta|Command)?(\+?[A-Z0-9]|F[1-9]|F1[0-2])?$/i;
            if (!shortcutRegex.test(shortcut)) {
                return { success: false, error: 'Invalid shortcut format' };
            }
        }

        const settings = await chrome.storage.local.get('shortcuts');
        const shortcuts = settings.shortcuts || {};

        if (shortcut === 'reset') {
            delete shortcuts[command];
        } else {
            shortcuts[command] = shortcut;
        }

        await chrome.storage.local.set({ shortcuts });

        if (shortcut !== 'reset') {
            try {
                await chrome.commands.update({
                    name: command,
                    shortcut: shortcut
                });
            } catch (updateErr) {
                return { success: false, error: 'Failed to update shortcut. It may already be in use by another extension.' };
            }
        }

        return { success: true };
    } catch (err) {
        return { success: false, error: 'Failed to update shortcut: ' + err.message };
    }
}

async function handleResetShortcuts() {
    try {
        const settings = await chrome.storage.local.get('shortcuts');
        const shortcuts = settings.shortcuts || {};

        for (const cmdName of Object.keys(DEFAULT_SHORTCUTS)) {
            delete shortcuts[cmdName];
            try {
                await chrome.commands.update({
                    name: cmdName,
                    shortcut: DEFAULT_SHORTCUTS[cmdName]
                });
            } catch (e) {
                // Ignore errors for individual commands
            }
        }

        await chrome.storage.local.set({ shortcuts });
        return { success: true };
    } catch (err) {
        return { success: false, error: 'Failed to reset shortcuts: ' + err.message };
    }
}