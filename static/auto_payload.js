document.addEventListener('DOMContentLoaded', () => {
    loadPayloadManager();
});

async function loadPayloadManager() {
    const container = document.getElementById('payload-autoload-list');
    if (!container) return;

    container.innerHTML = '<div class="text-center py-4 text-xs opacity-50"><i class="fa-solid fa-spinner fa-spin"></i> Loading...</div>';

    try {
        const [filesRes, configRes, orderRes, delaysRes] = await Promise.all([
            fetch('/list_payloads'),
            fetch('/api/payload_config'),
            fetch('/api/payload_order'),
            fetch('/api/payload_delays')
        ]);
        
        let files = await filesRes.json();
        const config = await configRes.json();
        const order = await orderRes.json();
        const delays = await delaysRes.json();

        container.innerHTML = ''; 

        if (!files || files.length === 0) {
            container.innerHTML = '<p class="text-xs opacity-50 p-4 text-center">No payloads found.</p>';
            return;
        }

        if (order && order.length > 0) {
            const weights = {};
            order.forEach((name, index) => weights[name] = index);
            files.sort((a, b) => {
                const wa = weights[a.split('/').pop()] ?? 9999;
                const wb = weights[b.split('/').pop()] ?? 9999;
                return wa - wb;
            });
        }

        files.forEach(file => {
            const configKey = file.split('/').pop();
            const checked = config[configKey] !== false && config[file] !== false; 
            const delayEnabled = delays[configKey] === true;

            const item = document.createElement('div');
            item.className = "draggable-item flex items-center justify-between p-3 bg-black/20 rounded-xl border border-white/5 group hover:border-brand-blue/30 transition-all cursor-grab active:cursor-grabbing mb-2";
            item.draggable = true;
            item.dataset.filename = configKey;
            
            const delayBtnClass = delayEnabled 
                ? "bg-brand-blue/20 text-brand-light border-brand-blue/50" 
                : "bg-transparent text-gray-500 hover:text-gray-300";

            item.innerHTML = `
                <div class="flex items-center gap-3 overflow-hidden flex-1 pointer-events-none">
                    <div class="text-white/20 group-hover:text-brand-light transition-colors px-1">
                         <i class="fa-solid fa-grip-vertical"></i>
                    </div>
                    
                    <div class="w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center text-brand-light">
                        <i class="fa-solid fa-microchip text-xs"></i>
                    </div>
                    <div class="flex flex-col overflow-hidden">
                        <span class="text-xs font-bold truncate" title="${file}">${file}</span>
                    </div>
                </div>
                
                <div class="flex items-center gap-4 pointer-events-auto mr-2">
                    <button onclick="togglePayloadDelay('${configKey}', this)" 
                            class="flex items-center gap-2 px-2 py-1 rounded-md transition-all border border-transparent ${delayBtnClass}"
                            title="Toggle Delay">
                        <i class="fa-solid fa-stopwatch text-xs"></i>
                        <span class="text-[10px] font-bold uppercase">Delay</span>
                    </button>

                    <label class="relative inline-flex items-center cursor-pointer">
                        <input type="checkbox" class="sr-only peer" onchange="togglePayloadAutoload('${configKey}', this)" ${checked ? 'checked' : ''}>
                        <div class="w-9 h-5 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-brand-blue"></div>
                    </label>
                </div>
            `;
            container.appendChild(item);
        });

        if (typeof enableDragSort === "function") {
            enableDragSort('payload-autoload-list', () => {
                saveCurrentOrder('payload-autoload-list');
            });
        }

    } catch (e) {
        console.error(e);
        container.innerHTML = '<p class="text-xs text-red-400 p-4 text-center">Failed to load payloads</p>';
        Toast.show('Failed to load payloads', 'error');
    }
}

async function togglePayloadAutoload(filename, checkbox) {
    const enabled = checkbox.checked;
    try {
        await fetch('/api/payload_config/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename, enabled })
        });
        Toast.show(`${filename} ${enabled ? 'enabled' : 'disabled'} for autoload`, 'info');
    } catch (e) {
        console.error(e);
        checkbox.checked = !enabled; 
        Toast.show('Failed to update autoload setting', 'error');
    }
}

async function togglePayloadDelay(filename, btn) {
    const isEnabled = btn.classList.contains('text-brand-light');
    const newState = !isEnabled;

    if (newState) {
        btn.classList.add('bg-brand-blue/20', 'text-brand-light', 'border-brand-blue/50');
        btn.classList.remove('bg-transparent', 'text-gray-500', 'hover:text-gray-300');
    } else {
        btn.classList.remove('bg-brand-blue/20', 'text-brand-light', 'border-brand-blue/50');
        btn.classList.add('bg-transparent', 'text-gray-500', 'hover:text-gray-300');
    }

    try {
        const response = await fetch('/api/payload_delays/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename, enabled: newState })
        });
        
        if (response.ok) {
            const status = newState ? "enabled" : "disabled";
            Toast.show(`Delay ${status} for ${filename}`, 'info');
        } else {
            throw new Error("Server error");
        }

    } catch (e) {
        console.error(e);
        Toast.show('Failed to update delay', 'error');
    }
}