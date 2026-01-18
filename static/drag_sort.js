let draggedItem = null;

function enableDragSort(containerId, onUpdate) {
    const container = document.getElementById(containerId);
    
    container.addEventListener('dragstart', (e) => {
        draggedItem = e.target.closest('.draggable-item');
        if (!draggedItem) return;
        
        e.dataTransfer.effectAllowed = 'move';
        setTimeout(() => draggedItem.classList.add('dragging'), 0);
    });

    container.addEventListener('dragend', () => {
        if (draggedItem) {
            draggedItem.classList.remove('dragging');
            draggedItem = null;
            if (onUpdate) onUpdate();
        }
    });

    container.addEventListener('dragover', (e) => {
        e.preventDefault();
        const afterElement = getDragAfterElement(container, e.clientY);
        const currentDraggable = document.querySelector('.dragging');
        
        if (afterElement == null) {
            container.appendChild(currentDraggable);
        } else {
            container.insertBefore(currentDraggable, afterElement);
        }
    });
}

function getDragAfterElement(container, y) {
    const draggableElements = [...container.querySelectorAll('.draggable-item:not(.dragging)')];

    return draggableElements.reduce((closest, child) => {
        const box = child.getBoundingClientRect();
        const offset = y - box.top - box.height / 2;
        
        if (offset < 0 && offset > closest.offset) {
            return { offset: offset, element: child };
        } else {
            return closest;
        }
    }, { offset: Number.NEGATIVE_INFINITY }).element;
}

async function saveCurrentOrder(containerId) {
    const container = document.getElementById(containerId);
    const items = Array.from(container.children);
    const order = items.map(item => item.dataset.filename).filter(x => x);

    try {
        await fetch('/api/payload_order', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ order })
        });
        if (typeof Toast !== "undefined" && Toast.show) Toast.show('Order saved', 'success');
    } catch (e) {
        console.error("Failed to save order", e);
        if (typeof Toast !== "undefined" && Toast.show) Toast.show('Failed to save order', 'error');
    }
}