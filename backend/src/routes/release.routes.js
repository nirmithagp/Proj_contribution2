const express = require('express');
const router = express.Router();
const releaseController = require('../controllers/release.controller');

router.post('/generate', releaseController.generateReleaseNotes);
router.post('/publish', releaseController.publishToGithub);

module.exports = router;
