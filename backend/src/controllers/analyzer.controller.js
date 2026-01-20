const analyzerService = require('../services/code-analyzer.service');

exports.analyzeRepo = (req, res) => {
    try {
        const { repo } = req.query;
        const analysis = analyzerService.analyzeRepository(repo || 'SatyamPandey-07/xaytheon');
        res.json(analysis);
    } catch (error) {
        res.status(500).json({ message: "Analysis failed" });
    }
};

exports.getRecommendations = (req, res) => {
    try {
        const { repo } = req.query;
        const analysis = analyzerService.analyzeRepository(repo || 'SatyamPandey-07/xaytheon');
        const recs = analyzerService.getAiRecommendations(analysis);
        res.json({ recommendations: recs });
    } catch (error) {
        res.status(500).json({ message: "Failed to get recommendations" });
    }
};
