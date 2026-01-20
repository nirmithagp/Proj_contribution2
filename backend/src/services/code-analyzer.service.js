/**
 * Code Analyzer Service
 * Calculates complexity metrics and technical debt for code files
 */

class CodeAnalyzerService {

    analyzeRepository(repoName) {
        // Mock file analysis for demo
        const files = this.getMockFiles();
        const metrics = files.map(f => this.analyzeFile(f));

        return {
            repoName,
            totalFiles: files.length,
            avgComplexity: this.average(metrics.map(m => m.cyclomaticComplexity)),
            avgMaintainability: this.average(metrics.map(m => m.maintainabilityIndex)),
            totalDebt: metrics.reduce((sum, m) => sum + m.debtMinutes, 0),
            files: metrics,
            trends: this.getMockTrends(),
            timestamp: new Date()
        };
    }

    analyzeFile(file) {
        // Simulate complexity calculation
        const loc = file.lines;
        const cyclomaticComplexity = Math.floor(Math.random() * 20) + 1;
        const cognitiveComplexity = Math.floor(cyclomaticComplexity * 1.2);
        const maintainabilityIndex = Math.max(0, 100 - cyclomaticComplexity * 3);
        const debtMinutes = cyclomaticComplexity > 10 ? (cyclomaticComplexity - 10) * 5 : 0;

        return {
            path: file.path,
            lines: loc,
            cyclomaticComplexity,
            cognitiveComplexity,
            maintainabilityIndex,
            debtMinutes,
            codeSmells: this.detectSmells(cyclomaticComplexity),
            rating: this.getRating(maintainabilityIndex)
        };
    }

    detectSmells(complexity) {
        const smells = [];
        if (complexity > 15) smells.push({ type: 'High Complexity', severity: 'critical' });
        if (complexity > 10) smells.push({ type: 'Long Method', severity: 'major' });
        if (Math.random() > 0.7) smells.push({ type: 'Duplicate Code', severity: 'minor' });
        return smells;
    }

    getRating(maintainability) {
        if (maintainability >= 80) return 'A';
        if (maintainability >= 60) return 'B';
        if (maintainability >= 40) return 'C';
        if (maintainability >= 20) return 'D';
        return 'F';
    }

    getMockFiles() {
        return [
            { path: 'src/app.js', lines: 250 },
            { path: 'src/utils/auth.js', lines: 180 },
            { path: 'src/services/api.js', lines: 320 },
            { path: 'src/components/Dashboard.jsx', lines: 420 },
            { path: 'src/controllers/user.controller.js', lines: 280 },
            { path: 'src/middleware/validation.js', lines: 150 },
            { path: 'src/routes/index.js', lines: 90 }
        ];
    }

    getMockTrends() {
        return [
            { date: '2026-01-12', avgComplexity: 8.2, debtHours: 12 },
            { date: '2026-01-14', avgComplexity: 8.5, debtHours: 14 },
            { date: '2026-01-16', avgComplexity: 7.8, debtHours: 11 },
            { date: '2026-01-18', avgComplexity: 7.2, debtHours: 9 }
        ];
    }

    average(arr) {
        return arr.length ? (arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(1) : 0;
    }

    getAiRecommendations(metrics) {
        const critical = metrics.files.filter(f => f.rating === 'D' || f.rating === 'F');
        return critical.map(f => ({
            file: f.path,
            suggestion: `Refactor ${f.path} - complexity is ${f.cyclomaticComplexity}. Consider breaking into smaller functions.`
        }));
    }
}

module.exports = new CodeAnalyzerService();
