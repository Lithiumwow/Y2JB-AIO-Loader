let currentPath = "/";
let currentFiles = [];

document.addEventListener('DOMContentLoaded', () => {
    loadDirectory('/');
});

async function loadDirectory(path) {
    showLoader(true);
    try {
        const response = await fetch('/api/ftp/list', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ path })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentPath = path;
            currentFiles = data.items;
            renderFiles(data.items);
            updateBreadcrumbs(path);
            document.getElementById('connection-status').innerText = "Connected";
            document.getElementById('connection-status').className = "text-xs uppercase tracking-wider text-green-500 font-bold font-mono";
        } else {
            Toast.show(data.error || "Failed to list directory", "error");
        }
    } catch (e) {
        Toast.show("Connection Error", "error");
    } finally {
        showLoader(false);
    }
}

function renderFiles(items) {
    const container = document.getElementById('file-list');
    container.innerHTML = '';

    if (items.length === 0) {
        container.innerHTML = `<div class="p-8 text-center opacity-30">Empty Directory</div>`;
        return;
    }

    items.forEach(item => {
        const isDir = item.type === 'dir';
        const icon = isDir ? 'fa-folder text-yellow-500' : 'fa-file text-brand-light';
        const size = isDir ? '-' : formatBytes(item.size);
        
        const div = document.createElement('div');
        div.className = "grid grid-cols-12 gap-4 p-3 border-b border-white/5 hover:bg-white/5 transition-colors items-center group text-sm";
        div.innerHTML = `
            <div class="col-span-1 text-center"><i class="fa-solid ${icon}"></i></div>
            <div class="col-span-7 md:col-span-6 font-medium truncate cursor-pointer select-none" onclick="${isDir ? `openDir('${item.name}')` : `editFile('${item.name}')`}">
                ${item.name}
            </div>
            <div class="col-span-2 hidden md:block text-right font-mono opacity-60 text-xs">${size}</div>
            <div class="col-span-4 md:col-span-3 flex justify-end gap-2 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity">
                ${!isDir ? `<button onclick="downloadFile('${item.name}')" class="p-1.5 hover:text-brand-light" title="Download"><i class="fa-solid fa-download"></i></button>` : ''}
                <button onclick="renameItem('${item.name}')" class="p-1.5 hover:text-yellow-400" title="Rename"><i class="fa-solid fa-pen"></i></button>
                <button onclick="deleteItem('${item.name}', ${isDir})" class="p-1.5 hover:text-red-500" title="Delete"><i class="fa-solid fa-trash"></i></button>
            </div>
        `;
        container.appendChild(div);
    });
}

function openDir(name) {
    const newPath = currentPath === '/' ? `/${name}` : `${currentPath}/${name}`;
    loadDirectory(newPath);
}

function navigateUp() {
    if (currentPath === '/') return;
    const parts = currentPath.split('/');
    parts.pop();
    const newPath = parts.length === 1 ? '/' : parts.join('/');
    loadDirectory(newPath);
}

function refreshDir() {
    loadDirectory(currentPath);
}

function updateBreadcrumbs(path) {
    document.getElementById('breadcrumbs').innerText = path;
}

async function createFolder() {
    const name = prompt("Folder Name:");
    if (!name) return;
    
    const path = currentPath === '/' ? `/${name}` : `${currentPath}/${name}`;
    await performAction('mkdir', { path });
}

function createFile() {
    const name = prompt("New File Name (e.g., script.py):");
    if (!name) return;

    const exists = currentFiles.find(f => f.name === name);
    if (exists) {
        Toast.show("File already exists!", "error");
        return;
    }

    openEditorModal(name, "");
}

async function deleteItem(name, isDir) {
    if (!confirm(`Are you sure you want to delete ${name}?`)) return;
    const path = currentPath === '/' ? `/${name}` : `${currentPath}/${name}`;
    await performAction('delete', { path, is_dir: isDir });
}

async function renameItem(name) {
    const newName = prompt("New Name:", name);
    if (!newName || newName === name) return;
    
    const oldPath = currentPath === '/' ? `/${name}` : `${currentPath}/${name}`;
    const newPath = currentPath === '/' ? `/${newName}` : `${currentPath}/${newName}`;
    
    await performAction('rename', { path: oldPath, new_path: newPath });
}

async function performAction(action, data) {
    showLoader(true);
    try {
        const res = await fetch('/api/ftp/action', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ action, ...data })
        });
        const json = await res.json();
        if (json.success) refreshDir();
        else Toast.show(json.error, "error");
    } catch (e) {
        Toast.show("Action failed", "error");
    } finally {
        showLoader(false);
    }
}

async function handleUpload(input) {
    if (!input.files.length) return;
    const file = input.files[0];
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('path', currentPath);
    
    showLoader(true);
    try {
        const res = await fetch('/api/ftp/upload_file', {
            method: 'POST',
            body: formData
        });
        const json = await res.json();
        if (json.success) {
            Toast.show("Upload successful", "success");
            refreshDir();
        } else {
            Toast.show(json.error, "error");
        }
    } catch (e) {
        Toast.show("Upload failed", "error");
    } finally {
        input.value = '';
        showLoader(false);
    }
}

function downloadFile(name) {
    const path = currentPath === '/' ? `/${name}` : `${currentPath}/${name}`;
    fetch('/api/ftp/download_file', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ path })
    })
    .then(res => res.blob())
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
    })
    .catch(() => Toast.show("Download failed", "error"));
}

async function editFile(name) {
    const ext = name.split('.').pop().toLowerCase();
    
    const imageExts = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico', 'svg'];
    if (imageExts.includes(ext)) {
        viewImage(name);
        return;
    }

    const editable = ['txt', 'json', 'ini', 'xml', 'py', 'js', 'css', 'html', 'sh', 'conf', 'md', 'yml'];
    
    if (!editable.includes(ext)) {
        downloadFile(name);
        return;
    }

    const path = currentPath === '/' ? `/${name}` : `${currentPath}/${name}`;
    showLoader(true);
    try {
        const res = await fetch('/api/ftp/download_file', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ path, as_text: true })
        });
        const json = await res.json();
        if (json.success) {
            openEditorModal(name, json.content);
        } else {
            Toast.show("Could not open file", "error");
        }
    } catch(e) {
        Toast.show("Error opening file", "error");
    } finally {
        showLoader(false);
    }
}

async function viewImage(name) {
    const path = currentPath === '/' ? `/${name}` : `${currentPath}/${name}`;
    showLoader(true);
    
    try {
        const res = await fetch('/api/ftp/download_file', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ path })
        });
        
        if (!res.ok) throw new Error("Failed to fetch image");
        
        const blob = await res.blob();
        
        const url = window.URL.createObjectURL(blob);
        
        const imgTarget = document.getElementById('image-viewer-target');
        const downloadLink = document.getElementById('image-viewer-download');
        
        imgTarget.src = url;
        document.getElementById('image-viewer-filename').innerText = name;
        
        // Setup the download button in the viewer
        downloadLink.href = url;
        downloadLink.download = name;
        
        document.getElementById('image-modal').classList.replace('hidden', 'flex');
        
    } catch (e) {
        Toast.show("Could not load image", "error");
    } finally {
        showLoader(false);
    }
}

function closeImageViewer() {
    const modal = document.getElementById('image-modal');
    const img = document.getElementById('image-viewer-target');
    modal.classList.replace('flex', 'hidden');
    setTimeout(() => {
        if (img.src) {
            window.URL.revokeObjectURL(img.src);
            img.src = '';
        }
    }, 300);
}

let currentEditingFile = null;

function openEditorModal(name, content) {
    currentEditingFile = name;
    document.getElementById('editor-filename').innerText = name;
    document.getElementById('editor-content').value = content;
    document.getElementById('editor-modal').classList.replace('hidden', 'flex');
}

function closeEditor() {
    document.getElementById('editor-modal').classList.replace('flex', 'hidden');
    currentEditingFile = null;
}

async function saveEditorContent() {
    if (!currentEditingFile) return;
    
    const content = document.getElementById('editor-content').value;
    const path = currentPath === '/' ? `/${currentEditingFile}` : `${currentPath}/${currentEditingFile}`;
    
    const formData = new FormData();
    formData.append('content', content);
    formData.append('path', path);
    
    showLoader(true);
    try {
        const res = await fetch('/api/ftp/upload_file', {
            method: 'POST',
            body: formData
        });
        const json = await res.json();
        if (json.success) {
            Toast.show("File saved", "success");
            closeEditor();
            refreshDir();
        } else {
            Toast.show(json.error, "error");
        }
    } catch (e) {
        Toast.show("Save failed", "error");
    } finally {
        showLoader(false);
    }
}

function showLoader(show) {
    const loader = document.getElementById('loader');
    if(show) loader.classList.remove('hidden');
    else loader.classList.add('hidden');
}

function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}