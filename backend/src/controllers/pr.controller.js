const prService = require('../services/pr-reviewer.service');

exports.analyzePr = async (req, res) => {
    try {
        const { title, diff, repo } = req.body;
        if (!diff) {
            return res.status(400).json({ message: "Diff content is required" });
        }

        const analysis = await prService.reviewPr(title || 'Untitled PR', diff);
        res.json(analysis);
    } catch (error) {
        console.error("PR Review Error:", error);
        res.status(500).json({ message: "Failed to analyze PR" });
    }
};

exports.getPendingPrs = (req, res) => {
    // Mock data for dashboard
    res.json([
        { id: 295, title: 'feat: Add user profile', author: 'dev_jane', status: 'open', risks: 2 },
        { id: 296, title: 'fix: Login bug', author: 'bug_hunter', status: 'open', risks: 0 },
        { id: 297, title: 'chore: Update deps', author: 'dependabot', status: 'review_required', risks: 5 }
    ]);
};
