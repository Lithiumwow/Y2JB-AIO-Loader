document.addEventListener('DOMContentLoaded', loadSettings);

async function loadSettings() {
    try {
        const response = await fetch('/api/settings');
        const config = await response.json();

        if (config.ip) document.getElementById('ip').value = config.ip;
        if (config.ftp_port) document.getElementById('ftp_port').value = config.ftp_port;
        const loaderPortEl = document.getElementById('loader_port');
        if (loaderPortEl) loaderPortEl.value = config.loader_port || '50000';
        const voidshellPortEl = document.getElementById('voidshell_port');
        if (voidshellPortEl) voidshellPortEl.value = config.voidshell_port || '7007';
        document.getElementById('global_delay').value = config.global_delay || "5";
        
        document.getElementById('ajb').checked = config.ajb === 'true';
        const kstuffCheckbox = document.getElementById('kstuff-toggle');
        if (kstuffCheckbox) kstuffCheckbox.checked = config.kstuff !== 'false';

        const animCheckbox = document.getElementById('ui_animations');
        const animationsEnabled = config.ui_animations === 'true';
        animCheckbox.checked = animationsEnabled;
        
        document.getElementById('debug_mode').checked = config.debug_mode === 'true';
        document.getElementById('auto_update_repos').checked = config.auto_update_repos !== 'false';
        document.getElementById('dns_auto_start').checked = config.dns_auto_start !== 'false';
        
        const compactCheckbox = document.getElementById('compact_mode');
        compactCheckbox.checked = config.compact_mode === 'true';
        if (compactCheckbox.checked) document.body.classList.add('compact-mode');

        localStorage.setItem('animations', animationsEnabled);

    } catch (error) {
        console.error('Error loading settings:', error);
        Toast.show('Failed to load settings', 'error');
    }
}

async function saveAllSettings() {
    const payload = {
        ip: document.getElementById('ip').value,
        ftp_port: document.getElementById('ftp_port').value,
        loader_port: (document.getElementById('loader_port') && document.getElementById('loader_port').value) ? document.getElementById('loader_port').value : '50000',
        voidshell_port: (document.getElementById('voidshell_port') && document.getElementById('voidshell_port').value) ? document.getElementById('voidshell_port').value : '7007',
        global_delay: document.getElementById('global_delay').value,
        ajb: document.getElementById('ajb').checked ? "true" : "false",
        kstuff: document.getElementById('kstuff-toggle').checked ? "true" : "false",
        ui_animations: document.getElementById('ui_animations').checked ? "true" : "false",
        debug_mode: document.getElementById('debug_mode').checked ? "true" : "false",
        auto_update_repos: document.getElementById('auto_update_repos').checked ? "true" : "false",
        dns_auto_start: document.getElementById('dns_auto_start').checked ? "true" : "false",
        compact_mode: document.getElementById('compact_mode').checked ? "true" : "false"
    };

    try {
        const response = await fetch('/api/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload)
        });

        const result = await response.json();

        if (result.success) {
            document.body.classList.toggle('compact-mode', payload.compact_mode === "true");
            localStorage.setItem('animations', payload.ui_animations === "true");
            Toast.show('Settings saved successfully!', 'success');
        } else {
            Toast.show('Error: ' + result.error, 'error');
        }
    } catch (error) {
        console.error('Error saving settings:', error);
        Toast.show('Connection error while saving', 'error');
    }
}

async function updateWebUI() {
    const updateBtn = document.getElementById('update-btn');
    const updateBtnText = document.getElementById('update-btn-text');
    const updateStatus = document.getElementById('update-status');
    
    // Disable button and show loading
    updateBtn.disabled = true;
    updateBtn.classList.add('opacity-50', 'cursor-not-allowed');
    updateBtnText.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Updating...';
    updateStatus.classList.remove('hidden');
    updateStatus.textContent = 'Fetching latest changes...';
    updateStatus.className = 'mt-3 text-xs opacity-60';
    
    try {
        const response = await fetch('/api/update', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            if (result.updated) {
                updateStatus.textContent = `✓ Updated successfully! Commit: ${result.commit_after || 'unknown'}`;
                updateStatus.className = 'mt-3 text-xs text-green-400';
                Toast.show(`Updated successfully! New commit: ${result.commit_after || 'unknown'}`, 'success');
                
                // Suggest restart
                setTimeout(() => {
                    if (confirm('Update completed! The server needs to be restarted for changes to take effect. Would you like to reload the page?')) {
                        window.location.reload();
                    }
                }, 1000);
            } else {
                updateStatus.textContent = '✓ Already up to date';
                updateStatus.className = 'mt-3 text-xs text-green-400';
                Toast.show('Already up to date', 'success');
            }
        } else {
            updateStatus.textContent = `✗ Error: ${result.error}`;
            updateStatus.className = 'mt-3 text-xs text-red-400';
            Toast.show(`Update failed: ${result.error}`, 'error');
        }
    } catch (error) {
        console.error('Error updating:', error);
        updateStatus.textContent = `✗ Connection error: ${error.message}`;
        updateStatus.className = 'mt-3 text-xs text-red-400';
        Toast.show('Connection error while updating', 'error');
    } finally {
        // Re-enable button
        updateBtn.disabled = false;
        updateBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        updateBtnText.innerHTML = '<i class="fa-solid fa-download"></i> Update Now';
    }
}