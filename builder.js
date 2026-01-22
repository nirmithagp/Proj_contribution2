/**
 * Workflow Builder Logic
 */
document.addEventListener('DOMContentLoaded', () => {
    const canvas = document.getElementById('workflow-canvas');
    const placeholder = document.getElementById('canvas-placeholder');
    const yamlPreview = document.querySelector('#yaml-preview code');
    const workflowNameInput = document.getElementById('workflow-name');
    const triggerSelect = document.getElementById('trigger-select');
    const validationPill = document.getElementById('validation-pill');

    const exportBtn = document.getElementById('export-yaml-btn');
    const copyBtn = document.getElementById('copy-yaml');

    // Modals
    const editModal = document.getElementById('edit-modal');
    const saveEditBtn = document.getElementById('save-edit');
    const cancelEditBtn = document.getElementById('cancel-edit');

    let workflowSteps = [];
    let editingStepId = null;
    let draggedStepId = null;

    /* -------------------- Utilities -------------------- */

    const debounce = (fn, delay = 400) => {
        let t;
        return (...args) => {
            clearTimeout(t);
            t = setTimeout(() => fn(...args), delay);
        };
    };

    const debouncedYamlUpdate = debounce(updateYamlPreview);

    /* -------------------- Library Drag -------------------- */

    document.querySelectorAll('.draggable-step').forEach(step => {
        step.addEventListener('dragstart', (e) => {
            const data = {
                name: step.getAttribute('data-name'),
                type: step.getAttribute('data-type'),
                uses: step.getAttribute('data-uses') || null,
                run: step.getAttribute('data-run') || null
            };
            e.dataTransfer.effectAllowed = 'copy';
            e.dataTransfer.setData('application/json', JSON.stringify(data));
        });
    });

    /* -------------------- Canvas Drag -------------------- */

    canvas.addEventListener('dragover', (e) => {
        e.preventDefault();
        canvas.classList.add('drag-over');
    });

    canvas.addEventListener('dragleave', () => {
        canvas.classList.remove('drag-over');
    });

    canvas.addEventListener('drop', (e) => {
        e.preventDefault();
        canvas.classList.remove('drag-over');

        try {
            const json = e.dataTransfer.getData('application/json');
            if (!json) return;

            const stepData = JSON.parse(json);
            addStep(stepData);
        } catch (err) {
            console.error('Drop error:', err);
        }
    });

    /* -------------------- Workflow Management -------------------- */

    function addStep(data, index = null) {
        const id = crypto.randomUUID();
        const step = { id, ...data };

        if (index === null) {
            workflowSteps.push(step);
        } else {
            workflowSteps.splice(index, 0, step);
        }

        renderCanvas();
        debouncedYamlUpdate();
    }

    function removeStep(id) {
        workflowSteps = workflowSteps.filter(s => s.id !== id);
        renderCanvas();
        debouncedYamlUpdate();
    }

    function moveStep(fromIndex, toIndex) {
        if (fromIndex === toIndex) return;
        const [item] = workflowSteps.splice(fromIndex, 1);
        workflowSteps.splice(toIndex, 0, item);
    }

    function renderCanvas() {
        canvas.querySelectorAll('.step-block').forEach(b => b.remove());

        if (workflowSteps.length === 0) {
            placeholder.style.display = 'block';
            return;
        }

        placeholder.style.display = 'none';

        workflowSteps.forEach((step, index) => {
            const block = document.createElement('div');
            block.className = 'step-block';
            block.draggable = true;
            block.dataset.id = step.id;
            block.dataset.index = index;

            block.innerHTML = `
                <div class="step-info">
                    <h5>${step.name}</h5>
                    <p>${step.uses ? step.uses : step.run}</p>
                </div>
                <div class="step-actions">
                    <button class="icon-btn edit" type="button">
                        <i class="ri-edit-line"></i>
                    </button>
                    <button class="icon-btn delete" type="button">
                        <i class="ri-delete-bin-line"></i>
                    </button>
                </div>
            `;

            // Step drag reorder
            block.addEventListener('dragstart', () => {
                draggedStepId = step.id;
                block.classList.add('dragging');
            });

            block.addEventListener('dragend', () => {
                draggedStepId = null;
                block.classList.remove('dragging');
            });

            block.addEventListener('dragover', (e) => {
                e.preventDefault();
                const targetIndex = Number(block.dataset.index);
                const sourceIndex = workflowSteps.findIndex(s => s.id === draggedStepId);
                if (sourceIndex !== -1 && sourceIndex !== targetIndex) {
                    moveStep(sourceIndex, targetIndex);
                    renderCanvas();
                }
            });

            // Actions
            block.querySelector('.edit').addEventListener('click', () => {
                window.builder.openEdit(step.id);
            });

            block.querySelector('.delete').addEventListener('click', () => {
                window.builder.remove(step.id);
            });

            canvas.appendChild(block);
        });
    }

    /* -------------------- YAML Preview -------------------- */

    async function updateYamlPreview() {
        const workflowData = {
            name: workflowNameInput.value,
            on: triggerSelect.value,
            jobs: {
                build: {
                    runsOn: 'ubuntu-latest',
                    steps: workflowSteps.map(({ name, uses, run }) =>
                        uses ? { name, uses } : { name, run }
                    )
                }
            }
        };

        try {
            const res = await fetch('/api/workflow/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ workflowData })
            });

            const data = await res.json();
            yamlPreview.textContent = data.yaml;

            if (data.validation === 'Workflow is valid.') {
                validationPill.className = 'pill valid';
                validationPill.textContent = 'Valid';
                validationPill.title = '';
            } else {
                validationPill.className = 'pill error';
                validationPill.textContent = 'Warning';
                validationPill.title = data.validation;
            }
        } catch (err) {
            console.error('Preview error:', err);
        }
    }

    /* -------------------- Modal Logic -------------------- */

    window.builder = {
        remove: removeStep,
        openEdit: (id) => {
            editingStepId = id;
            const step = workflowSteps.find(s => s.id === id);
            if (!step) return;

            document.getElementById('edit-step-name').value = step.name;

            const usesField = document.getElementById('uses-field');
            const runField = document.getElementById('run-field');

            if (step.uses) {
                usesField.style.display = 'block';
                runField.style.display = 'none';
                document.getElementById('edit-step-uses').value = step.uses;
            } else {
                usesField.style.display = 'none';
                runField.style.display = 'block';
                document.getElementById('edit-step-run').value = step.run;
            }

            editModal.classList.remove('hidden');
        }
    };

    saveEditBtn.addEventListener('click', () => {
        const idx = workflowSteps.findIndex(s => s.id === editingStepId);
        if (idx === -1) return;

        workflowSteps[idx].name = document.getElementById('edit-step-name').value;

        if (workflowSteps[idx].uses) {
            workflowSteps[idx].uses = document.getElementById('edit-step-uses').value;
        } else {
            workflowSteps[idx].run = document.getElementById('edit-step-run').value;
        }

        editModal.classList.add('hidden');
        renderCanvas();
        debouncedYamlUpdate();
    });

    cancelEditBtn.addEventListener('click', () => {
        editModal.classList.add('hidden');
    });

    /* -------------------- Actions -------------------- */

    exportBtn.addEventListener('click', () => {
        const blob = new Blob([yamlPreview.textContent], { type: 'text/yaml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = workflowNameInput.value || 'main.yml';
        a.click();
        URL.revokeObjectURL(url);
    });

    copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(yamlPreview.textContent);
        copyBtn.innerHTML = '<i class="ri-check-line"></i>';
        setTimeout(() => {
            copyBtn.innerHTML = '<i class="ri-file-copy-line"></i>';
        }, 2000);
    });

    workflowNameInput.addEventListener('change', debouncedYamlUpdate);
    triggerSelect.addEventListener('change', debouncedYamlUpdate);
});
