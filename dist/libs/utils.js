const CipherMailUtils = {
    escapeHtml(text) {
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    },

    validateEmail(email) {
        if (!email || typeof email !== 'string') return false;
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email.trim());
    },

    showToast(message, type = 'info', duration = 4000) {
        const existingToast = document.getElementById('ciphermail-toast');
        if (existingToast) existingToast.remove();

        const toast = document.createElement('div');
        toast.id = 'ciphermail-toast';
        const bgColor = type === 'error' ? '#d93025' : type === 'success' ? '#0f9d58' : '#333';
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: ${bgColor};
            color: white;
            padding: 14px 20px;
            border-radius: 8px;
            font-size: 14px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            z-index: 999999;
            animation: ciphermailToastSlide 0.3s ease;
            max-width: 320px;
        `;
        toast.textContent = message;

        if (!document.getElementById('ciphermail-toast-style')) {
            const style = document.createElement('style');
            style.id = 'ciphermail-toast-style';
            style.textContent = `
                @keyframes ciphermailToastSlide {
                    from { opacity: 0; transform: translateY(20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
            `;
            document.head.appendChild(style);
        }

        document.body.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    },

    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    generateId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = CipherMailUtils;
}