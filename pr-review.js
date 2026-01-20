/**
 * PR Review Assistant JavaScript
 * Handles automated pull request review functionality
 */

class PRReviewAssistant {
    constructor() {
        this.initializeElements();
        this.bindEvents();
        this.loadTemplates();
    }

    initializeElements() {
        // Input elements
        this.repoNameInput = document.getElementById('repo-name');
        this.prNumberInput = document.getElementById('pr-number');
        this.prDiffTextarea = document.getElementById('pr-diff');
        this.reviewTemplateSelect = document.getElementById('review-template');
        this.confidenceThresholdSelect = document.getElementById('confidence-threshold');
        
        // Action buttons
        this.analyzeBtn = document.getElementById('analyze-pr');
        this.clearBtn = document.getElementById('clear-form');
        this.generateCommentBtn = document.getElementById('generate-comment');
        this.copyCommentBtn = document.getElementById('copy-comment');
        
        // Results section
        this.resultsSection = document.getElementById('review-results');
        this.loadingState = document.getElementById('loading-state');
        
        // Summary elements
        this.confidenceScore = document.getElementById('confidence-score');
        this.totalIssues = document.getElementById('total-issues');
        this.severityLevel = document.getElementById('severity-level');
        this.highIssues = document.getElementById('high-issues');
        this.mediumIssues = document.getElementById('medium-issues');
        this.lowIssues = document.getElementById('low-issues');
        
        // Content containers
        this.issuesContainer = document.getElementById('issues-container');
        this.securityWarnings = document.getElementById('security-warnings');
        this.codeSuggestions = document.getElementById('code-suggestions');
        this.recommendations = document.getElementById('recommendations');
        this.reviewComment = document.getElementById('review-comment');
    }

    bindEvents() {
        // Button events
        this.analyzeBtn.addEventListener('click', () => this.analyzePR());
        this.clearBtn.addEventListener('click', () => this.clearForm());
        this.generateCommentBtn.addEventListener('click', () => this.generateComment());
        this.copyCommentBtn.addEventListener('click', () => this.copyComment());
        
        // Input validation
        this.prDiffTextarea.addEventListener('input', () => this.validateInput());
        this.prNumberInput.addEventListener('input', () => this.validateInput());
    }

    validateInput() {
        const repoName = this.repoNameInput.value.trim();
        const prNumber = this.prNumberInput.value.trim();
        const prDiff = this.prDiffTextarea.value.trim();
        
        const isValid = repoName && prNumber && prDiff && prDiff.length <= 1000000; // 1MB limit
        
        this.analyzeBtn.disabled = !isValid;
    }

    async analyzePR() {
        const repoName = this.repoNameInput.value.trim();
        const prNumber = parseInt(this.prNumberInput.value);
        const prDiff = this.prDiffTextarea.value.trim();
        const template = this.reviewTemplateSelect.value;

        if (!repoName || !prNumber || !prDiff) {
            alert('Please fill in all required fields');
            return;
        }

        if (prDiff.length > 1000000) {
            alert('PR diff exceeds 1MB limit');
            return;
        }

        this.showLoading(true);
        this.resultsSection.classList.add('hidden');

        try {
            const response = await fetch('/api/pr-review/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    prDiff,
                    repoName,
                    prNumber,
                    templateId: template
                })
            });

            if (!response.ok) {
                throw new Error('Failed to analyze PR');
            }

            const data = await response.json();
            this.displayResults(data.data);
            this.resultsSection.classList.remove('hidden');

        } catch (error) {
            console.error('PR analysis failed:', error);
            alert('Failed to analyze pull request. Please try again.');
        } finally {
            this.showLoading(false);
        }
    }

    displayResults(reviewData) {
        // Update summary stats
        this.confidenceScore.textContent = `${reviewData.confidenceScore}%`;
        this.confidenceScore.style.color = this.getConfidenceColor(reviewData.confidenceScore);
        
        this.totalIssues.textContent = reviewData.totalIssues;
        
        const severityLevel = this.getSeverityLevel(reviewData.confidenceScore);
        this.severityLevel.textContent = severityLevel;
        this.severityLevel.className = `stat-value severity-${severityLevel.toLowerCase()}`;
        
        // Update issue counts
        this.highIssues.textContent = reviewData.severityDistribution.high;
        this.mediumIssues.textContent = reviewData.severityDistribution.medium;
        this.lowIssues.textContent = reviewData.severityDistribution.low;

        // Display issues
        this.displayIssues(reviewData.issues);
        
        // Display security warnings
        this.displaySecurityWarnings(reviewData.securityWarnings);
        
        // Display code suggestions
        this.displayCodeSuggestions(reviewData.suggestions);
        
        // Display recommendations
        this.displayRecommendations(reviewData.recommendations);
    }

    displayIssues(issues) {
        this.issuesContainer.innerHTML = '';
        
        if (issues.length === 0) {
            this.issuesContainer.innerHTML = '<p class="no-issues">No issues detected in the code</p>';
            return;
        }

        issues.forEach((issue, index) => {
            const issueElement = document.createElement('div');
            issueElement.className = `issue-item issue-${issue.severity}`;
            
            issueElement.innerHTML = `
                <div class="issue-header">
                    <span class="issue-type">${this.getIssueIcon(issue.type)}</span>
                    <span class="issue-title">${issue.title}</span>
                    <span class="issue-severity">${issue.severity.toUpperCase()}</span>
                </div>
                <div class="issue-content">
                    <p class="issue-description">${issue.description}</p>
                    <div class="issue-code">
                        <code>${issue.codeSnippet}</code>
                    </div>
                    <div class="issue-suggestion">
                        <strong>Suggestion:</strong> ${issue.suggestion}
                    </div>
                </div>
            `;
            
            this.issuesContainer.appendChild(issueElement);
        });
    }

    displaySecurityWarnings(warnings) {
        this.securityWarnings.innerHTML = '';
        
        if (warnings.length === 0) {
            this.securityWarnings.innerHTML = '<p class="no-warnings">No security warnings detected</p>';
            return;
        }

        warnings.forEach(warning => {
            const warningElement = document.createElement('div');
            warningElement.className = 'warning-item warning-security';
            
            warningElement.innerHTML = `
                <div class="warning-header">
                    <span class="warning-icon">🔒</span>
                    <span class="warning-title">${warning.title}</span>
                </div>
                <div class="warning-content">
                    <p>${warning.description}</p>
                    <div class="warning-solution">
                        <strong>Resolution:</strong> ${warning.solution}
                    </div>
                </div>
            `;
            
            this.securityWarnings.appendChild(warningElement);
        });
    }

    displayCodeSuggestions(suggestions) {
        this.codeSuggestions.innerHTML = '';
        
        if (suggestions.length === 0) {
            this.codeSuggestions.innerHTML = '<p class="no-suggestions">No code suggestions available</p>';
            return;
        }

        suggestions.forEach(suggestion => {
            const suggestionElement = document.createElement('div');
            suggestionElement.className = 'suggestion-item';
            
            suggestionElement.innerHTML = `
                <div class="suggestion-header">
                    <span class="suggestion-title">${suggestion.title}</span>
                </div>
                <div class="suggestion-content">
                    <p>${suggestion.description}</p>
                    <div class="suggestion-implementation">
                        <strong>Implementation:</strong> ${suggestion.implementation}
                    </div>
                </div>
            `;
            
            this.codeSuggestions.appendChild(suggestionElement);
        });
    }

    displayRecommendations(recommendations) {
        this.recommendations.innerHTML = '';
        
        recommendations.forEach(rec => {
            const recElement = document.createElement('div');
            recElement.className = `recommendation-item priority-${rec.priority}`;
            
            recElement.innerHTML = `
                <div class="recommendation-header">
                    <span class="recommendation-priority">${rec.priority.toUpperCase()}</span>
                    <span class="recommendation-title">${rec.title}</span>
                </div>
                <div class="recommendation-content">
                    <p>${rec.description}</p>
                </div>
            `;
            
            this.recommendations.appendChild(recElement);
        });
    }

    async generateComment() {
        const repoName = this.repoNameInput.value.trim();
        const prNumber = parseInt(this.prNumberInput.value);
        const template = this.reviewTemplateSelect.value;
        
        // Get current issues from display
        const issues = this.getCurrentIssues();

        if (!repoName || !prNumber || issues.length === 0) {
            alert('Please analyze a PR first to generate a comment');
            return;
        }

        try {
            const response = await fetch('/api/pr-review/generate-comment', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    issues,
                    repoName,
                    prNumber,
                    templateId: template
                })
            });

            if (!response.ok) {
                throw new Error('Failed to generate comment');
            }

            const data = await response.json();
            this.reviewComment.textContent = data.data.comment;
            this.copyCommentBtn.disabled = false;

        } catch (error) {
            console.error('Comment generation failed:', error);
            alert('Failed to generate review comment. Please try again.');
        }
    }

    getCurrentIssues() {
        // In a real scenario, this would come from the actual analysis data
        // For now, return a simplified representation
        return [];
    }

    copyComment() {
        const commentText = this.reviewComment.textContent;
        
        navigator.clipboard.writeText(commentText)
            .then(() => {
                // Show temporary confirmation
                const originalText = this.copyCommentBtn.innerHTML;
                this.copyCommentBtn.innerHTML = '✓ Copied!';
                
                setTimeout(() => {
                    this.copyCommentBtn.innerHTML = originalText;
                }, 2000);
            })
            .catch(err => {
                console.error('Failed to copy text: ', err);
                alert('Failed to copy comment to clipboard');
            });
    }

    async loadTemplates() {
        try {
            const response = await fetch('/api/pr-review/templates', {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.populateTemplates(data.data);
            }
        } catch (error) {
            console.error('Failed to load templates:', error);
        }
    }

    populateTemplates(templates) {
        // Templates are already in the HTML select, but we could dynamically populate them here
        // For now, we'll just log the available templates
        console.log('Available review templates:', templates);
    }

    clearForm() {
        this.repoNameInput.value = '';
        this.prNumberInput.value = '';
        this.prDiffTextarea.value = '';
        this.reviewTemplateSelect.value = 'comprehensive';
        this.confidenceThresholdSelect.value = 'medium';
        
        this.resultsSection.classList.add('hidden');
        this.analyzeBtn.disabled = true;
        this.copyCommentBtn.disabled = true;
    }

    showLoading(show) {
        if (show) {
            this.loadingState.classList.remove('hidden');
        } else {
            this.loadingState.classList.add('hidden');
        }
    }

    getConfidenceColor(score) {
        if (score >= 80) return '#10b981'; // Green
        if (score >= 60) return '#f59e0b'; // Yellow
        return '#ef4444'; // Red
    }

    getSeverityLevel(score) {
        if (score >= 80) return 'Low Risk';
        if (score >= 60) return 'Medium Risk';
        return 'High Risk';
    }

    getIssueIcon(type) {
        const icons = {
            security: '🔒',
            performance: '⚡',
            quality: '🔍',
            'best-practice': '💡'
        };
        return icons[type] || '⚠️';
    }
}

// Initialize PR Review Assistant when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.prReviewAssistant = new PRReviewAssistant();
});

// Theme toggle functionality
document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('theme-toggle');
    const themeIcon = themeToggle.querySelector('.theme-icon');
    
    // Check for saved theme or default to dark
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    themeIcon.textContent = savedTheme === 'dark' ? '☀️' : '🌙';
    
    themeToggle.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        themeIcon.textContent = newTheme === 'dark' ? '☀️' : '🌙';
    });
});