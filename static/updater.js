function updatePayloads() {
    if(!confirm("This will overwrite existing payloads with the latest versions from GitHub. Continue?")) return;
    
    const btn = document.getElementById('update-btn') || event.target.closest('button');
    const originalText = btn.innerHTML;
    
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Updating...';
    btn.disabled = true;

    fetch('/update_repos', { method: 'POST' })
    .then(response => response.json())
    .then(data => {
        btn.innerHTML = originalText;
        btn.disabled = false;
        
        if (data.success) {
            let msg = "Update Process Finished.\n\n";
            if (data.updated.length > 0) msg += "Updated:\n" + data.updated.join("\n") + "\n\n";
            else msg += "No files were updated (already latest).\n\n";
            
            if (data.errors.length > 0) msg += "Errors:\n" + data.errors.join("\n");
            
            alert(msg);
            location.reload();
        } else {
            alert("Update Failed: " + (data.message || "Unknown error"));
        }
    })
    .catch(error => {
        btn.innerHTML = originalText;
        btn.disabled = false;
        alert("Network Error: " + error);
    });
}
