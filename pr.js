document.addEventListener('DOMContentLoaded', () => {
    const prListEl = document.getElementById('pr-list');
    const analysisPanel = document.getElementById('analysis-panel');
    const refreshBtn = document.getElementById('refresh-prs');
    const scanNewBtn = document.getElementById('scan-new');
    const diffModal = document.getElementById('diff-modal');
    const cancelScanBtn = document.getElementById('cancel-scan');
    const startScanBtn = document.getElementById('start-scan');

    // Load Pending PRs
    loadPendingPrs();

    refreshBtn.addEventListener('click', loadPendingPrs);

    scanNewBtn.addEventListener('click', () => {
        diffModal.classList.remove('hidden');
    });

    cancelScanBtn.addEventListener('click', () => {
        diffModal.classList.add('hidden');
    });

    startScanBtn.addEventListener('click', async () => {
        const title = document.getElementById('pr-title-input').value;
        const diff = document.getElementById('diff-input').value;

        if (!diff) return alert("Please paste a diff.");

        startScanBtn.innerHTML = '<i class="ri-loader-4-line ri-spin"></i> Analyzing...';

        try {
            const res = await fetch('/api/pr/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title, diff })
            });
            const data = await res.json();
            renderAnalysis(data);
            diffModal.classList.add('hidden');
        } catch (e) {
            console.error(e);
            alert("Analysis failed.");
        } finally {
            startScanBtn.innerText = 'Analyze Code';
        }
    });

    async function loadPendingPrs() {
        prListEl.innerHTML = '<div class="empty-state">Loading...</div>';
        try {
            const res = await fetch('/api/pr/pending');
            const data = await res.json();
            renderPrList(data);
        } catch (e) {
            prListEl.innerHTML = '<div class="error-state">Failed to load PRs</div>';
        }
    }

    function renderPrList(prs) {
        if (!prs.length) {
            prListEl.innerHTML = '<div class="empty-state">No pending PRs found.</div>';
            return;
        }

        prListEl.innerHTML = '';
        prs.forEach(pr => {
            const item = document.createElement('div');
            item.className = 'pr-item';
            const riskClass = pr.risks > 0 ? 'risk-high' : 'risk-low';

            item.innerHTML = `
                <h4>${pr.title} <span style="color:#888">#${pr.id}</span></h4>
                <div class="pr-meta">
                    <span>@${pr.author}</span>
                    <span class="risk-tag ${riskClass}">${pr.risks} Risks Detected</span>
                </div>
            `;

            // Mock click to analyze
            item.addEventListener('click', () => {
                // In real app, fetch specific PR analysis
                // simulating a scan for demo
                const diff = `const password = "admin";\nvar count = 0;\nfunction test() { console.log('debug'); }`;
                document.getElementById('pr-title-input').value = pr.title;
                document.getElementById('diff-input').value = diff;
                startScanBtn.click();
            });

            prListEl.appendChild(item);
        });
    }

    function renderAnalysis(data) {
        analysisPanel.classList.remove('hidden');
        document.getElementById('analysis-title').textContent = `Analysis: ${data.prTitle}`;
        document.getElementById('confidence-score').textContent = `Confidence: ${data.confidenceScore}%`;

        const secList = document.getElementById('security-list');
        const styleList = document.getElementById('style-list');
        const aiList = document.getElementById('ai-list');

        secList.innerHTML = data.securityIssues.length ? '' : '<li class="finding-item">No security issues found. ✅</li>';
        data.securityIssues.forEach(item => {
            secList.innerHTML += `<li class="finding-item ${item.type}"><strong>${item.type}:</strong> ${item.msg}</li>`;
        });

        styleList.innerHTML = data.styleIssues.length ? '' : '<li class="finding-item">Style is clean. ✨</li>';
        data.styleIssues.forEach(item => {
            styleList.innerHTML += `<li class="finding-item ${item.type}">${item.msg}</li>`;
        });

        aiList.innerHTML = data.aiSuggestions.length ? '' : '<li class="finding-item">No AI suggestions.</li>';
        data.aiSuggestions.forEach(item => {
            aiList.innerHTML += `
                <li class="finding-item Suggestion">
                    <strong>${item.file}:${item.line}</strong> - ${item.suggestion}
                </li>`;
        });
    }
});
