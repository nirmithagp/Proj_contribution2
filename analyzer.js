document.addEventListener('DOMContentLoaded', () => {
    const analyzeBtn = document.getElementById('analyze-btn');
    const repoInput = document.getElementById('repo-input');

    analyzeBtn.addEventListener('click', runAnalysis);
    runAnalysis();

    async function runAnalysis() {
        const repo = repoInput.value.trim();
        analyzeBtn.innerHTML = '<i class="ri-loader-4-line ri-spin"></i>';

        try {
            const res = await fetch(`/api/analyzer/analyze?repo=${repo}`);
            const data = await res.json();
            renderDashboard(data);

            const recsRes = await fetch(`/api/analyzer/recommendations?repo=${repo}`);
            const recsData = await recsRes.json();
            renderRecs(recsData.recommendations);
        } catch (e) {
            console.error(e);
        } finally {
            analyzeBtn.innerHTML = 'Analyze';
        }
    }

    function renderDashboard(data) {
        document.getElementById('total-files').textContent = data.totalFiles;
        document.getElementById('avg-complexity').textContent = data.avgComplexity;
        document.getElementById('maintainability').textContent = data.avgMaintainability + '%';
        document.getElementById('total-debt').textContent = Math.round(data.totalDebt / 60) + 'h';

        // Heatmap
        const heatmap = document.getElementById('debt-heatmap');
        heatmap.innerHTML = '';
        data.files.forEach(f => {
            const block = document.createElement('div');
            block.className = `heat-block heat-${f.rating.toLowerCase()}`;
            block.title = `${f.path}\nComplexity: ${f.cyclomaticComplexity}`;
            block.textContent = f.rating;
            heatmap.appendChild(block);
        });

        // Table
        const tbody = document.getElementById('files-table-body');
        tbody.innerHTML = '';
        data.files.forEach(f => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${f.path}</td>
                <td>${f.lines}</td>
                <td>${f.cyclomaticComplexity}</td>
                <td><span class="rating-badge rating-${f.rating}">${f.rating}</span></td>
                <td>${f.debtMinutes}m</td>
            `;
            tbody.appendChild(tr);
        });

        // Trends
        const trendChart = document.getElementById('trend-chart');
        trendChart.innerHTML = '';
        const maxDebt = Math.max(...data.trends.map(t => t.debtHours));
        data.trends.forEach(t => {
            const bar = document.createElement('div');
            bar.className = 'trend-bar';
            bar.style.height = `${(t.debtHours / maxDebt) * 100}%`;
            bar.innerHTML = `<span>${t.date.slice(5)}</span>`;
            trendChart.appendChild(bar);
        });
    }

    function renderRecs(recs) {
        const container = document.getElementById('ai-recs');
        container.innerHTML = recs.length ? '' : '<p style="color:var(--text-muted)">No critical issues detected. 🎉</p>';
        recs.forEach(r => {
            const item = document.createElement('div');
            item.className = 'rec-item';
            item.innerHTML = `<strong>${r.file}</strong><p>${r.suggestion}</p>`;
            container.appendChild(item);
        });
    }
});
