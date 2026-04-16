document.getElementById('submitBtn').onclick = () => {
    const passphrase = document.getElementById('passphrase').value;
    chrome.runtime.sendMessage({
        type: 'PASSPHRASE_RESPONSE',
        passphrase: passphrase
    });
    window.close();
};

document.getElementById('cancelBtn').onclick = () => {
    chrome.runtime.sendMessage({
        type: 'PASSPHRASE_RESPONSE',
        passphrase: null
    });
    window.close();
};

document.getElementById('passphrase').onkeydown = (e) => {
    if (e.key === 'Enter') {
        document.getElementById('submitBtn').click();
    }
};

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'REQUEST_PASSPHRASE') {
        document.getElementById('passphrase').focus();
    }
});