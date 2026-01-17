const User = require("../models/user.model");
const { validateArray, validateString, validateUrl, validateNumber } = require("../utils/validation");

// Input validation functions
function isValidHistoryItem(item) {
  return (
    typeof item === 'object' &&
    item !== null &&
    validateString(item.id, 'id', { required: true, maxLength: 100 }).length > 0 &&
    validateString(item.title, 'title', { maxLength: 200 }).length >= 0 &&
    validateUrl(item.url, 'url').length >= 0 &&
    (item.timestamp === undefined || (typeof item.timestamp === 'number' && item.timestamp > 0))
  );
}

function sanitizeHistoryItem(item) {
  if (!isValidHistoryItem(item)) {
    return null;
  }

  return {
    id: validateString(item.id, 'id', { required: true, maxLength: 100 }),
    title: validateString(item.title, 'title', { maxLength: 200 }),
    url: validateUrl(item.url, 'url'),
    timestamp: item.timestamp || Date.now()
  };
}

exports.getHistory = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    let history = [];
    if (user.view_history) {
      try {
        const parsed = JSON.parse(user.view_history);
        if (Array.isArray(parsed)) {
          history = parsed.filter(item => isValidHistoryItem(item));
        }
      } catch (err) {
        console.warn("Invalid history JSON for user", req.userId, err);
        // Continue with empty history
      }
    }

    res.json(history);
  } catch (err) {
    console.error("Get history error:", err);
    res.status(500).json({ message: "Failed to fetch history" });
  }
};

exports.updateHistory = async (req, res) => {
  try {
    const { history } = req.body;

    // Validate input
    const validatedHistory = validateArray(history, 'history', {
      required: true,
      maxLength: 100,
      itemValidator: (item) => {
        const sanitized = sanitizeHistoryItem(item);
        if (!sanitized) {
          throw new Error('Invalid history item');
        }
        return sanitized;
      }
    });

    // Limit to 50 items as before
    const limitedHistory = validatedHistory.slice(0, 50);

    await User.updateViewHistory(req.userId, JSON.stringify(limitedHistory));
    res.json({ message: "History updated successfully" });
  } catch (err) {
    console.error("Update history error:", err);

    // Handle validation errors
    if (err.name === 'ValidationError') {
      return res.status(err.statusCode).json({ message: err.message, field: err.field });
    }

    res.status(500).json({ message: "Failed to update history" });
  }
};

exports.getPreferences = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    let preferences = {};
    if (user.preferences) {
      try {
        preferences = JSON.parse(user.preferences);
      } catch (err) {
        console.warn("Invalid preferences JSON for user", req.userId, err);
      }
    }

    res.json(preferences);
  } catch (err) {
    console.error("Get preferences error:", err);
    res.status(500).json({ message: "Failed to fetch preferences" });
  }
};

exports.updatePreferences = async (req, res) => {
  try {
    const { theme, analytics } = req.body;
    let newPrefs = {};

    // Fetch existing preferences to merge
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    if (user.preferences) {
      try {
        newPrefs = JSON.parse(user.preferences);
      } catch (e) { }
    }

    // Merge/Verify fields
    if (theme && (theme === 'light' || theme === 'dark')) {
      newPrefs.theme = theme;
    }

    if (analytics && typeof analytics === 'object') {
      // Allow partial updates to analytics object
      newPrefs.analytics = { ... (newPrefs.analytics || {}), ...analytics };

      // Sanitize specific keys if needed 
      const allowedKeys = ['starsChartType', 'followersChartType', 'showTable'];
      // For now, accept what's sent but could filter here
    }

    await User.updatePreferences(req.userId, JSON.stringify(newPrefs));
    res.json({ message: "Preferences updated", preferences: newPrefs });
  } catch (err) {
    console.error("Update preferences error:", err);
    res.status(500).json({ message: "Failed to update preferences" });
  }
};
