const express = require('express');
const router = express.Router();
const analyzerController = require('../controllers/analyzer.controller');

router.get('/analyze', analyzerController.analyzeRepo);
router.get('/recommendations', analyzerController.getRecommendations);

module.exports = router;
