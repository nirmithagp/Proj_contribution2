// backend/src/utils/hasPermission.js

const { PERMISSIONS } = require('../config/permissions');

const hasPermission = (role, action) => {
  if (!role || !action) return false;
  return PERMISSIONS[role]?.includes(action);
};

module.exports = hasPermission;

