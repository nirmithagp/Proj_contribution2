/**
 * PR Review Routes
 * Routes for automated pull request review system
 */

const express = require('express');
const router = express.Router();
const prReviewController = require('../controllers/pr-review.controller');
const authMiddleware = require('../middleware/auth.middleware');

// Apply authentication middleware to all routes
router.use(authMiddleware.verifyAccessToken);

/**
 * @route   POST /api/pr-review/analyze
 * @desc    Analyze a pull request and provide automated review
 * @access  Private
 */
router.post('/analyze', prReviewController.analyzePR);

/**
 * @route   POST /api/pr-review/batch-analyze
 * @desc    Analyze multiple pull requests in a batch
 * @access  Private
 */
router.post('/batch-analyze', prReviewController.batchAnalyzePRs);

/**
 * @route   GET /api/pr-review/templates
 * @desc    Get available PR review templates
 * @access  Private
 */
router.get('/templates', prReviewController.getReviewTemplates);

/**
 * @route   GET /api/pr-review/stats
 * @desc    Get PR review statistics
 * @access  Private
 */
router.get('/stats', prReviewController.getReviewStats);

/**
 * @route   POST /api/pr-review/generate-comment
 * @desc    Generate a review comment based on issues found
 * @access  Private
 */
router.post('/generate-comment', prReviewController.generateReviewComment);

module.exports = router;