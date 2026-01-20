const express = require('express');
const router = express.Router();
const prController = require('../controllers/pr.controller');

router.post('/analyze', prController.analyzePr);
router.get('/pending', prController.getPendingPrs);

module.exports = router;
