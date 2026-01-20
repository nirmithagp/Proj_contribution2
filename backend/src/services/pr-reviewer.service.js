/**
 * PR Reviewer Service
 * Core logic for automated code analysis
 */
const llmService = require('./llm.service');

class PrReviewerService {

    async analyzePR(prDiff, repoName, prNumber) {
        // 1. Static Analysis (Regex/Rule based)
        const securityWarnings = this.scanSecurity(prDiff);
        const codeIssues = this.scanQuality(prDiff);

        // 2. AI Analysis
        const aiAnalysis = await this.getAiAnalysis(prDiff, repoName);

        // 3. Compile Results
        const allIssues = [...codeIssues, ...aiAnalysis.issues];
        const suggestions = aiAnalysis.suggestions;
        const recommendations = this.generateRecommendations(allIssues);

        // 4. Calculate Stats
        const confidenceScore = this.calculateConfidence(allIssues, securityWarnings, suggestions);

        return {
            confidenceScore,
            totalIssues: allIssues.length,
            severityDistribution: this.getSeverityDistribution(allIssues),
            issues: allIssues,
            securityWarnings,
            suggestions,
            recommendations
        };
    }

    scanSecurity(diff) {
        const warnings = [];
        const patterns = [
            { regex: /password\s*=\s*['"][^'"]+['"]/i, title: 'Hardcoded Password', desc: 'Avoid hardcoding credentials.', severity: 'high' },
            { regex: /eval\(/, title: 'Dangerous Eval', desc: 'eval() can execute arbitrary code.', severity: 'high' },
            { regex: /innerHTML/, title: 'XSS Risk', desc: 'Direct innerHTML assignment.', severity: 'medium' }
        ];

        patterns.forEach(p => {
            if (p.regex.test(diff)) {
                warnings.push({
                    title: p.title,
                    description: p.desc,
                    solution: 'Use environment variables or safer alternatives.',
                    severity: p.severity
                });
            }
        });
        return warnings;
    }

    scanQuality(diff) {
        const issues = [];
        if (diff.includes('console.log')) {
            issues.push({
                type: 'quality',
                title: 'Console Log Leftover',
                description: 'Found console.log statements.',
                severity: 'low',
                codeSnippet: 'console.log(...)',
                suggestion: 'Remove debug logging.'
            });
        }
        if (diff.includes('var ')) {
            issues.push({
                type: 'best-practice',
                title: 'Var Usage',
                description: 'Usage of "var" keyword detected.',
                severity: 'low',
                codeSnippet: 'var x = ...',
                suggestion: 'Use "const" or "let".'
            });
        }
        return issues;
    }

    async getAiAnalysis(diff, repoName) {
        // Mock AI response for now (or integrate actual LLM)
        // In real impl: await llmService.generateResponse(...)
        return {
            issues: [],
            suggestions: [
                {
                    title: 'Optimize Loop',
                    description: 'Nested loop detected in data parsing.',
                    implementation: 'Use a Map for O(1) lookup.'
                }
            ]
        };
    }

    generateRecommendations(issues) {
        const recs = [];
        if (issues.some(i => i.severity === 'high')) {
            recs.push({ priority: 'high', title: 'Fix Critical Issues', description: 'Address high severity findings immediately.' });
        } else {
            recs.push({ priority: 'low', title: 'Good Job', description: 'Code looks mostly clean.' });
        }
        return recs;
    }

    getSeverityDistribution(issues) {
        return {
            high: issues.filter(i => i.severity === 'high').length,
            medium: issues.filter(i => i.severity === 'medium').length,
            low: issues.filter(i => i.severity === 'low').length
        };
    }

    calculateConfidence(issues, warnings, suggestions) {
        let score = 100;
        score -= issues.filter(i => i.severity === 'high').length * 15;
        score -= issues.filter(i => i.severity === 'medium').length * 5;
        score -= warnings.length * 10;
        return Math.max(10, score);
    }
}

module.exports = new PrReviewerService();