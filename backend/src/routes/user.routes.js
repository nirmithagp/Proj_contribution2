const express = require("express");
const router = express.Router();
const userController = require("../controllers/user.controller");
const { verifyAccessToken, generalRateLimiter } = require("../middleware/auth.middleware");
const rbacAuthorize = require("../middleware/rbacMiddleware");
const { PERMISSIONS } = require("../config/roles");
const authAuthorize = require("../middleware/authorize");
const { ACTIONS } = require("../config/permissions");

router.use(generalRateLimiter);

router.get(
  "/history",
  verifyAccessToken,
  rbacAuthorize(PERMISSIONS.VIEW_HISTORY),
  authAuthorize(ACTIONS.READ),
  userController.getHistory
);

router.post(
  "/history",
  verifyAccessToken,
  rbacAuthorize(PERMISSIONS.UPDATE_HISTORY),
  authAuthorize(ACTIONS.UPDATE),
  userController.updateHistory
);

router.get("/preferences", verifyAccessToken, userController.getPreferences);
router.put("/preferences", verifyAccessToken, userController.updatePreferences);

module.exports = router;

