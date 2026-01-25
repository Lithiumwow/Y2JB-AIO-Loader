        if (enabled) {
            document.body.classList.add('compact-mode');
        } else {
            document.body.classList.remove('compact-mode');
        }
    },

    initDebugLogging: (enabled) => {
        window.is_debug_enabled = enabled;
        
        window.debugLog = function(module, message, data = null) {
            if (!window.is_debug_enabled) return;
            
            const timestamp = new Date().toLocaleTimeString();
            console.group(`[DEBUG] ${timestamp} - ${module}`);
            console.log(`Message: ${message}`);
            if (data) console.dir(data);
            console.groupEnd();
        };

        if (enabled) {
            console.warn("DEBUG MODE ENABLED: Verbose logging is active.");
        }
    }
};

document.addEventListener('DOMContentLoaded', async () => {
    try {
        const response = await fetch('/api/settings');
        const config = await response.json();
        
        UI.applyCompactMode(config.compact_mode === 'true');
        UI.initDebugLogging(config.debug_mode === 'true');
    } catch (e) {
        console.error("Failed to initialize UI features", e);
    }
});
