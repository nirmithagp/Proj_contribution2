const releaseNotesService = require('../services/release-notes.service');

/**
 * Controller for Release Notes generation
 */
exports.generateReleaseNotes = async (req, res) => {
    try {
        const { repo, base, head } = req.body;

        if (!repo || !base || !head) {
            return res.status(400).json({
                message: "Repository name, base tag, and head tag are required."
            });
        }

        const notes = await releaseNotesService.generateNotes(repo, base, head);

        res.json({
            success: true,
            data: notes
        });
    } catch (error) {
        console.error("Release Notes Generation Error:", error);
        res.status(500).json({
            message: "Failed to generate release notes.",
            error: error.message
        });
    }
};

exports.publishToGithub = async (req, res) => {
    try {
        const { repo, tag, notes } = req.body;
        // Mock GitHub API call
        console.log(`Publishing notes to ${repo} for tag ${tag}`);

        res.json({
            success: true,
            message: "Successfully published release notes to GitHub.",
            releaseUrl: `https://github.com/${repo}/releases/tag/${tag}`
        });
    } catch (error) {
        res.status(500).json({ message: "Failed to publish to GitHub." });
    }
};
