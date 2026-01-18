document.addEventListener('DOMContentLoaded', loadSettings);

async function loadSettings() {
    try {
        const response = await fetch('/api/settings');
        const config = await response.json();

        if (config.ip) document.getElementById('ip').value = config.ip;
        if (config.ftp_port) document.getElementById('ftp_port').value = config.ftp_port;
        
        if (config.global_delay) {
            document.getElementById('global_delay').value = config.global_delay;
        } else {
            document.getElementById('global_delay').value = "5";
        }
        
        const ajbCheckbox = document.getElementById('ajb');
        if (config.ajb && config.ajb.toLowerCase() === 'true') {
            ajbCheckbox.checked = true;
        } else {
            ajbCheckbox.checked = false;
        }

    } catch (error) {
        console.error('Error loading settings:', error);
        Toast.show('Failed to load settings', 'error');
    }
}

async function saveAllSettings() {
    const ip = document.getElementById('ip').value;
    const ftpPort = document.getElementById('ftp_port').value;
    const globalDelay = document.getElementById('global_delay').value;
    const ajb = document.getElementById('ajb').checked ? "true" : "false";

    const payload = {
        ip: ip,
        ftp_port: ftpPort,
        global_delay: globalDelay,
        ajb: ajb
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
            Toast.show('Settings saved successfully!', 'success');
        } else {
            Toast.show('Error: ' + result.error, 'error');
        }
    } catch (error) {
        console.error('Error saving settings:', error);
        Toast.show('Connection error while saving', 'error');
    }
}