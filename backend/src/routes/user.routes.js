const express = require("express");
const router = express.Router();
const userController = require("../controllers/user.controller");
const { verifyAccessToken, generalRateLimiter } = require("../middleware/auth.middleware");

router.use(generalRateLimiter); // Apply rate limiting to all user routes

router.get("/history", verifyAccessToken, userController.getHistory);
router.post("/history", verifyAccessToken, userController.updateHistory);

router.get("/preferences", verifyAccessToken, userController.getPreferences);
router.put("/preferences", verifyAccessToken, userController.updatePreferences);

module.exports = router;
