/**
 * Release Notes Generator Frontend Logic
 */
document.addEventListener('DOMContentLoaded', () => {
    const generateBtn = document.getElementById('generate-btn');
    const publishBtn = document.getElementById('publish-btn');
    const copyBtn = document.getElementById('copy-btn');
    const loadingOverlay = document.getElementById('loading-overlay');

    // Inputs
    const repoInput = document.getElementById('repo-name');
    const baseInput = document.getElementById('base-tag');
    const headInput = document.getElementById('head-tag');

    // Output Areas
    const previewArea = document.getElementById('preview-area');
    const markdownArea = document.getElementById('markdown-area');
    const jsonArea = document.getElementById('json-area');
    const emptyState = document.querySelector('.empty-state');

    // Tabs
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    let currentNotes = null;

    // --- Tab Switching ---
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');

            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            tabContents.forEach(content => {
                content.classList.add('hidden');
                if (content.id === `${tabId}-tab`) {
                    content.classList.remove('hidden');
                }
            });
        });
    });

    // --- Generate Action ---
    generateBtn.addEventListener('click', async () => {
        const repo = repoInput.value.trim();
        const base = baseInput.value.trim();
        const head = headInput.value.trim();

        if (!repo || !base || !head) {
            alert('Please fill in all configuration fields.');
            return;
        }

        loadingOverlay.classList.remove('hidden');
        generateBtn.disabled = true;

        try {
            const response = await fetch('/api/release/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ repo, base, head })
            });

            const data = await response.json();

            if (data.success) {
                currentNotes = data.data;
                displayResults(currentNotes);
                publishBtn.disabled = false;
            } else {
                alert(data.message || 'Failed to generate notes');
            }
        } catch (error) {
            console.error(error);
            alert('An error occurred during generation.');
        } finally {
            loadingOverlay.classList.add('hidden');
            generateBtn.disabled = false;
        }
    });

    function displayResults(notes) {
        emptyState.classList.add('hidden');
        previewArea.classList.remove('hidden');

        // Render Preview
        previewArea.innerHTML = notes.html;

        // Render Markdown
        markdownArea.value = notes.markdown;

        // Render JSON
        jsonArea.textContent = JSON.stringify(notes.json, null, 2);
    }

    // --- Copy Action ---
    copyBtn.addEventListener('click', () => {
        const activeTab = document.querySelector('.tab-btn.active').dataset.tab;
        let contentToCopy = '';

        if (activeTab === 'markdown') contentToCopy = markdownArea.value;
        else if (activeTab === 'json') contentToCopy = jsonArea.textContent;
        else contentToCopy = previewArea.innerText;

        navigator.clipboard.writeText(contentToCopy).then(() => {
            const originalText = copyBtn.innerHTML;
            copyBtn.innerHTML = '<i class="ri-check-line"></i> Copied!';
            setTimeout(() => copyBtn.innerHTML = originalText, 2000);
        });
    });

    // --- Publish Action ---
    publishBtn.addEventListener('click', async () => {
        if (!currentNotes) return;

        const editedMarkdown = markdownArea.value;
        const headTag = headInput.value.trim();

        publishBtn.innerHTML = '<i class="ri-loader-line ri-spin"></i> Publishing...';
        publishBtn.disabled = true;

        try {
            const response = await fetch('/api/release/publish', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    repo: currentNotes.repo,
                    tag: headTag,
                    notes: editedMarkdown
                })
            });

            const data = await response.json();
            if (data.success) {
                alert('Release Notes published successfully!');
                window.open(data.releaseUrl, '_blank');
            }
        } catch (error) {
            alert('Failed to publish to GitHub.');
        } finally {
            publishBtn.innerHTML = '<i class="ri-github-fill"></i> Publish to GitHub';
            publishBtn.disabled = false;
        }
    });
});
