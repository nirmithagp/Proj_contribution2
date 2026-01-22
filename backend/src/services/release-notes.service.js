/**
 * Release Notes Generator Service
 * Analyzes commits and generates structured release notes using AI.
 */
const llmService = require('./llm.service');

class ReleaseNotesService {
    /**
     * Generates release notes for a given repo and range.
     * @param {string} repo - owner/repo
     * @param {string} base - base tag/branch
     * @param {string} head - head tag/branch
     */
    async generateNotes(repo, base, head) {
        // 1. Fetch commits (Mocking GitHub API fetch for logic implementation)
        const commits = this.getMockCommits();

        // 2. Parse Commits
        const parsedData = this.parseCommits(commits);

        // 3. AI Summarization
        const summary = await this.getAiSummary(repo, parsedData);

        // 4. Generate Markdown
        const markdown = this.formatMarkdown(repo, parsedData, summary, head);

        return {
            repo,
            range: `${base}...${head}`,
            summary,
            categories: parsedData.categories,
            breakingChanges: parsedData.breakingChanges,
            contributors: parsedData.contributors,
            markdown,
            html: this.convertToHtml(markdown),
            json: parsedData
        };
    }

    parseCommits(commits) {
        const categories = {
            feat: [],
            fix: [],
            chore: [],
            docs: [],
            perf: [],
            refactor: [],
            other: []
        };
        const breakingChanges = [];
        const contributors = new Set();

        commits.forEach(c => {
            const message = c.message;
            contributors.add(c.author);

            // Extract PR number if present (e.g., "message (#123)")
            const prMatch = message.match(/\(#(\d+)\)/);
            const prNumber = prMatch ? prMatch[1] : null;

            // Conventional Commit Parsing regex: type(scope)!: message
            const match = message.match(/^(\w+)(?:\(([^)]+)\))?(!)?:\s+(.*)$/);

            if (match) {
                const [, type, scope, isBreaking, description] = match;
                const entry = {
                    hash: c.hash,
                    author: c.author,
                    scope: scope || null,
                    description: description.replace(/\(#\d+\)/, '').trim(),
                    pr: prNumber,
                    original: message
                };

                if (isBreaking || message.includes('BREAKING CHANGE')) {
                    breakingChanges.push(entry);
                }

                if (categories[type]) {
                    categories[type].push(entry);
                } else {
                    categories.other.push(entry);
                }
            } else {
                categories.other.push({
                    hash: c.hash,
                    author: c.author,
                    description: message.replace(/\(#\d+\)/, '').trim(),
                    pr: prNumber,
                    original: message
                });
            }
        });

        return {
            categories,
            breakingChanges,
            contributors: Array.from(contributors)
        };
    }

    async getAiSummary(repo, data) {
        try {
            return await llmService.generateReleaseSummary(repo, data);
        } catch (error) {
            console.error("LLM Summary Error:", error);
            return "This release focused on stability and core feature improvements.";
        }
    }

    formatMarkdown(repo, data, summary, version) {
        let md = `# Release Notes - ${repo} (${version})\n\n`;
        md += `## 📝 Summary\n${summary}\n\n`;

        if (data.breakingChanges.length > 0) {
            md += `## ⚠️ BREAKING CHANGES\n`;
            data.breakingChanges.forEach(bc => {
                md += `- ${bc.description} (${bc.hash.slice(0, 7)})\n`;
            });
            md += `\n`;
        }

        const labels = {
            feat: '🚀 Features',
            fix: '🐛 Bug Fixes',
            perf: '⚡ Performance',
            docs: '📚 Documentation',
            refactor: '♻️ Refactoring',
            chore: '🔧 Maintenance'
        };

        Object.keys(labels).forEach(type => {
            const items = data.categories[type];
            if (items && items.length > 0) {
                md += `## ${labels[type]}\n`;
                items.forEach(item => {
                    const scopePart = item.scope ? `**${item.scope}**: ` : '';
                    const prPart = item.pr ? ` ([#${item.pr}](https://github.com/${repo}/pull/${item.pr}))` : '';
                    md += `- ${scopePart}${item.description}${prPart} (@${item.author})\n`;
                });
                md += `\n`;
            }
        });

        md += `## 👥 Contributors\n`;
        data.contributors.forEach(author => {
            md += `- @${author}\n`;
        });

        return md;
    }

    convertToHtml(md) {
        // Simple conversion for demo
        return md.replace(/\n/g, '<br>').replace(/#(.*)/g, '<h1>$1</h1>').replace(/##(.*)/g, '<h2>$2</h2>').replace(/- (.*)/g, '<li>$1</li>');
    }

    getMockCommits() {
        return [
            { hash: 'a1b2c3d', author: 'SatyamPandey-07', message: 'feat(ui): add new release notes dashboard interface' },
            { hash: 'e5f6g7h', author: 'Saatvik-GT', message: 'fix(auth): resolve session timeout issue on mobile' },
            { hash: 'i9j0k1l', author: 'SatyamPandey-07', message: 'feat(core)!: migrate to new database schema' },
            { hash: 'm2n3o4p', author: 'dev-user', message: 'perf(graph): optimize 3D rendering loop' },
            { hash: 'q5r6s7t', author: 'SatyamPandey-07', message: 'docs: update contribution guidelines' },
            { hash: 'u8v9w0x', author: 'Saatvik-GT', message: 'chore: update dependency versions' }
        ];
    }
}

module.exports = new ReleaseNotesService();
