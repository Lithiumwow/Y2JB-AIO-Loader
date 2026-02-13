const ACCOUNT_ACTIVATOR_PAYLOAD = 'payloads/elf/np-fake-signin.elf';

document.addEventListener('DOMContentLoaded', async () => {
    try {
        const r = await fetch('/api/settings');
        const config = await r.json();
        const el = document.getElementById('activator-IP');
        if (el && config.ip) el.value = config.ip;
    } catch (e) {
        console.warn('Could not load IP from settings', e);
    }
});

function saveActivatorIP() {
    const el = document.getElementById('activator-IP');
    if (!el) return;
    const ip = (el.value || '').trim();
    fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    }).catch(() => {});
}

async function sendAccountActivator() {
    const btn = document.getElementById('btn-send-activator');
    const ipEl = document.getElementById('activator-IP');
    const host = (ipEl && ipEl.value && ipEl.value.trim()) || '';

    if (!host) {
        if (typeof Toast !== 'undefined') Toast.show('Enter PS5 IP address first', 'error');
        else alert('Enter PS5 IP address first.');
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Sending...';
    }
    if (typeof Toast !== 'undefined') Toast.show('Sending Account Activator payload...', 'info');

    try {
        const response = await fetch('/send_payload', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payload: ACCOUNT_ACTIVATOR_PAYLOAD, IP: host })
        });
        const data = await response.json();

        if (response.ok) {
            if (typeof Toast !== 'undefined') Toast.show('Payload sent. Reboot the PS5 for changes to apply.', 'success');
            else alert('Payload sent. Reboot the PS5 for changes to apply.');
        } else {
            if (typeof Toast !== 'undefined') Toast.show(data.error || 'Failed to send payload', 'error');
            else alert(data.error || 'Failed to send payload');
        }
    } catch (e) {
        if (typeof Toast !== 'undefined') Toast.show('Connection error: ' + e.message, 'error');
        else alert('Connection error: ' + e.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-user-check"></i> Send Account Activator';
        }
    }
}
