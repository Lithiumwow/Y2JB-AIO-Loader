async function setPayloadDelay(filename, currentVal) {
    const input = prompt(`Set delay (seconds) for ${filename}.\nLeave empty to use Global Default.`, currentVal || "");
    
    if (input === null) return;
    let payload = { filename: filename, delay: input };

    try {
        const response = await fetch('/api/payload_delay', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            if (typeof Toast !== 'undefined') Toast.show('Delay updated', 'success');
            if (typeof loadpayloads === 'function') loadpayloads();
        } else {
            alert("Failed to save delay");
        }
    } catch (e) {
        console.error(e);
        alert("Connection error");
    }
}