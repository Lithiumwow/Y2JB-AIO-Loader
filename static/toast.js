const Toast = {
    init() {
        if (!document.getElementById('toast-container')) {
            const container = document.createElement('div');
            container.id = 'toast-container';
            document.body.appendChild(container);
        }
    },

    show(message, type = 'info') {
        this.init();
        const container = document.getElementById('toast-container');
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        let icon = 'fa-info-circle';
        let colorClass = 'text-blue-400';
        
        if (type === 'success') { icon = 'fa-circle-check'; colorClass = 'text-green-400'; }
        if (type === 'error') { icon = 'fa-circle-xmark'; colorClass = 'text-red-400'; }
        if (type === 'warning') { icon = 'fa-triangle-exclamation'; colorClass = 'text-yellow-400'; }

        toast.innerHTML = `
            <i class="fa-solid ${icon} ${colorClass} text-xl"></i>
            <div class="flex flex-col">
                <span class="font-bold text-sm leading-tight">${type.charAt(0).toUpperCase() + type.slice(1)}</span>
                <span class="text-xs opacity-70">${message}</span>
            </div>
        `;

        container.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'fadeOut 0.3s forwards';
            toast.addEventListener('animationend', () => {
                if(toast.parentElement) toast.remove();
            });
        }, 4000);
    }
};

// Global wrapper function for convenience
function showToast(message, type = 'info') {
    Toast.show(message, type);
}