const githubCompareService = require('../services/github-compare.service');

exports.compareRepos = async (req, res) => {
    try {
        const { repos } = req.query; // Expecting comma-separated list of reponames like "owner/repo1,owner/repo2"

        if (!repos) {
            return res.status(400).json({ message: 'At least one repository is required for comparison' });
        }

        const parseRepoInput = (input) => {
            let clean = input.trim();
            // Remove .git suffix
            clean = clean.replace(/\.git$/i, '');
            // Remove URL prefix
            clean = clean.replace(/^https?:\/\/github\.com\//i, '');
            // Remove leading/trailing slashes
            return clean.replace(/^\/+|\/+$/g, '');
        };

        const repoList = repos.split(',')
            .map(r => parseRepoInput(r))
            .filter(r => r.length > 0 && r.split('/').length === 2); // Ensure owner/repo format

        if (repoList.length > 3) {
            return res.status(400).json({ message: 'Maximum 3 repositories can be compared at once' });
        }

        const comparisonData = await githubCompareService.compareRepositories(repoList);

        res.json(comparisonData);
    } catch (error) {
        console.error('Comparison error:', error);
        res.status(error.message.includes('not found') ? 404 : 500).json({
            message: error.message || 'Error comparing repositories'
        });
    }
};

exports.getTrendingForComparison = async (req, res) => {
    // Optional: Return some trending combinations or popular repos for comparison suggestions
    res.json([
        { name: 'threejs', fullName: 'mrdoob/three.js' },
        { name: 'react', fullName: 'facebook/react' },
        { name: 'vue', fullName: 'vuejs/core' }
    ]);
};
