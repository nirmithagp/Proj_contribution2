/**
 * PR Review Controller
 * Handles automated pull request review requests
 */

const prReviewerService = require('../services/pr-reviewer.service');

/**
 * POST /api/pr-review/analyze
 * Analyze a pull request and provide automated review
 */
exports.analyzePR = async (req, res) => {
    try {
        const { prDiff, repoName, prNumber } = req.body;

        if (!prDiff || !repoName || !prNumber) {
            return res.status(400).json({
                message: "PR diff, repository name, and PR number are required"
            });
        }

        // Validate input lengths
        if (typeof prDiff !== 'string' || prDiff.length > 1000000) { // 1MB limit
            return res.status(400).json({
                message: "PR diff must be a string with maximum 1MB length"
            });
        }

        if (typeof repoName !== 'string' || repoName.length > 100) {
            return res.status(400).json({
                message: "Repository name must be a string with maximum 100 characters"
            });
        }

        if (typeof prNumber !== 'number' || prNumber <= 0) {
            return res.status(400).json({
                message: "PR number must be a positive integer"
            });
        }

        // Analyze the PR
        const analysis = await prReviewerService.analyzePR(prDiff, repoName, prNumber);

        res.json({
            success: true,
            data: analysis,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error("PR Analysis Error:", error);
        res.status(500).json({
            message: "Failed to analyze pull request",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

/**
 * POST /api/pr-review/batch-analyze
 * Analyze multiple pull requests at once
 */
exports.batchAnalyzePRs = async (req, res) => {
    try {
        const { prs } = req.body;

        if (!prs || !Array.isArray(prs) || prs.length === 0) {
            return res.status(400).json({
                message: "Array of PRs is required for batch analysis"
            });
        }

        if (prs.length > 10) {
            return res.status(400).json({
                message: "Maximum 10 PRs can be analyzed in a single batch request"
            });
        }

        const results = [];
        for (const pr of prs) {
            if (!pr.prDiff || !pr.repoName || !pr.prNumber) {
                results.push({
                    prNumber: pr.prNumber || 'unknown',
                    error: "Missing required fields (prDiff, repoName, prNumber)"
                });
                continue;
            }

            try {
                const analysis = await prReviewerService.analyzePR(
                    pr.prDiff,
                    pr.repoName,
                    pr.prNumber
                );
                
                results.push({
                    prNumber: pr.prNumber,
                    success: true,
                    analysis
                });
            } catch (error) {
                results.push({
                    prNumber: pr.prNumber,
                    success: false,
                    error: error.message
                });
            }
        }

        res.json({
            success: true,
            data: results,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error("Batch PR Analysis Error:", error);
        res.status(500).json({
            message: "Failed to analyze pull requests in batch",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

/**
 * GET /api/pr-review/templates
 * Get available PR review templates
 */
exports.getReviewTemplates = async (req, res) => {
    try {
        const templates = [
            {
                id: 'security-focused',
                name: 'Security Focused Review',
                description: 'Reviews code with emphasis on security vulnerabilities',
                categories: ['security', 'vulnerabilities'],
                checks: ['sqlInjection', 'xssRisk', 'hardcodedSecrets']
            },
            {
                id: 'performance-focused',
                name: 'Performance Focused Review',
                description: 'Reviews code with emphasis on performance issues',
                categories: ['performance', 'optimization'],
                checks: ['syncOperations', 'inefficientLoops']
            },
            {
                id: 'code-quality',
                name: 'Code Quality Review',
                description: 'Reviews code with emphasis on quality and best practices',
                categories: ['quality', 'best-practices'],
                checks: ['unusedVars', 'consoleLogs', 'evalUsage', 'improperErrorHandling']
            },
            {
                id: 'comprehensive',
                name: 'Comprehensive Review',
                description: 'Full review covering all categories',
                categories: ['security', 'performance', 'quality', 'best-practices'],
                checks: ['all']
            }
        ];

        res.json({
            success: true,
            data: templates,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error("Get Review Templates Error:", error);
        res.status(500).json({
            message: "Failed to fetch review templates",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

/**
 * GET /api/pr-review/stats
 * Get statistics about PR reviews
 */
exports.getReviewStats = async (req, res) => {
    try {
        // This would typically fetch from database
        // For now, return mock data
        const stats = {
            totalReviews: 1247,
            avgConfidenceScore: 78.5,
            mostCommonIssues: [
                { type: 'console-logs', count: 234 },
                { type: 'security-vulnerabilities', count: 89 },
                { type: 'performance-issues', count: 67 }
            ],
            reviewTrends: {
                last7Days: [
                    { date: '2026-01-12', reviews: 45 },
                    { date: '2026-01-13', reviews: 52 },
                    { date: '2026-01-14', reviews: 38 },
                    { date: '2026-01-15', reviews: 61 },
                    { date: '2026-01-16', reviews: 49 },
                    { date: '2026-01-17', reviews: 55 },
                    { date: '2026-01-18', reviews: 42 }
                ]
            }
        };

        res.json({
            success: true,
            data: stats,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error("Get Review Stats Error:", error);
        res.status(500).json({
            message: "Failed to fetch review statistics",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

/**
 * POST /api/pr-review/generate-comment
 * Generate a review comment based on issues found
 */
exports.generateReviewComment = async (req, res) => {
    try {
        const { issues, repoName, prNumber, templateId = 'comprehensive' } = req.body;

        if (!issues || !Array.isArray(issues)) {
            return res.status(400).json({
                message: "Array of issues is required to generate review comment"
            });
        }

        if (!repoName || !prNumber) {
            return res.status(400).json({
                message: "Repository name and PR number are required"
            });
        }

        const comment = this.generateCommentFromIssues(issues, repoName, prNumber, templateId);

        res.json({
            success: true,
            data: {
                comment,
                repoName,
                prNumber,
                templateUsed: templateId
            },
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error("Generate Review Comment Error:", error);
        res.status(500).json({
            message: "Failed to generate review comment",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Helper method to generate comment from issues
exports.generateCommentFromIssues = (issues, repoName, prNumber, templateId) => {
    const header = `## Automated Code Review for PR #${prNumber}\n\n`;
    
    // Group issues by severity
    const groupedIssues = {
        high: issues.filter(i => i.severity === 'high'),
        medium: issues.filter(i => i.severity === 'medium'),
        low: issues.filter(i => i.severity === 'low')
    };

    let comment = header;

    // Add summary
    comment += `### Summary\n`;
    comment += `- Total Issues Found: ${issues.length}\n`;
    comment += `- High Severity: ${groupedIssues.high.length}\n`;
    comment += `- Medium Severity: ${groupedIssues.medium.length}\n`;
    comment += `- Low Severity: ${groupedIssues.low.length}\n\n`;

    // Add high severity issues
    if (groupedIssues.high.length > 0) {
        comment += `### ⚠️ Critical Issues\n`;
        groupedIssues.high.forEach(issue => {
            comment += `- **${issue.title}**: ${issue.description}\n`;
            comment += `  - *Suggestion*: ${issue.suggestion}\n\n`;
        });
    }

    // Add medium severity issues
    if (groupedIssues.medium.length > 0) {
        comment += `### 🔍 Medium Priority Issues\n`;
        groupedIssues.medium.forEach(issue => {
            comment += `- **${issue.title}**: ${issue.description}\n`;
            comment += `  - *Suggestion*: ${issue.suggestion}\n\n`;
        });
    }

    // Add low severity issues
    if (groupedIssues.low.length > 0) {
        comment += `### 💡 Low Priority Issues\n`;
        groupedIssues.low.forEach(issue => {
            comment += `- **${issue.title}**: ${issue.description}\n`;
            comment += `  - *Suggestion*: ${issue.suggestion}\n\n`;
        });
    }

    // Add recommendations based on template
    const recommendations = this.getRecommendationsForTemplate(templateId);
    if (recommendations.length > 0) {
        comment += `### 📋 Recommendations\n`;
        recommendations.forEach(rec => {
            comment += `- ${rec}\n`;
        });
        comment += `\n`;
    }

    // Add footer
    comment += `---\n`;
    comment += `_This review was automatically generated by the AI PR Review Assistant. Please review and address these findings before merging._\n`;
    comment += `_Review Confidence Score: ${Math.max(1, 100 - issues.length * 2)}%_\n`;

    return comment;
};

// Helper method to get recommendations for template
exports.getRecommendationsForTemplate = (templateId) => {
    const recommendations = [];

    switch (templateId) {
        case 'security-focused':
            recommendations.push(
                "Ensure all user inputs are properly sanitized",
                "Consider implementing input validation middleware",
                "Review all authentication and authorization logic"
            );
            break;
        case 'performance-focused':
            recommendations.push(
                "Consider optimizing database queries",
                "Review memory usage patterns",
                "Check for potential bottlenecks"
            );
            break;
        case 'code-quality':
            recommendations.push(
                "Follow consistent naming conventions",
                "Add more comprehensive error handling",
                "Consider refactoring large functions"
            );
            break;
        case 'comprehensive':
        default:
            recommendations.push(
                "Address all identified issues before merging",
                "Consider adding more unit tests for covered functionality",
                "Ensure proper documentation for new features"
            );
            break;
    }

    return recommendations;
};