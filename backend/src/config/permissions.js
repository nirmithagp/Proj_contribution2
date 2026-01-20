// backend/src/config/permissions.js

const ROLES = {
  ADMIN: 'admin',
  MANAGER: 'manager',
  USER: 'user',
  VIEWER: 'viewer',
};

const ACTIONS = {
  CREATE: 'CREATE',
  READ: 'READ',
  UPDATE: 'UPDATE',
  DELETE: 'DELETE',
};

const PERMISSIONS = {
  [ROLES.ADMIN]: [
    ACTIONS.CREATE,
    ACTIONS.READ,
    ACTIONS.UPDATE,
    ACTIONS.DELETE,
  ],
  [ROLES.MANAGER]: [
    ACTIONS.CREATE,
    ACTIONS.READ,
    ACTIONS.UPDATE,
  ],
  [ROLES.USER]: [ACTIONS.READ],
  [ROLES.VIEWER]: [ACTIONS.READ],
};

module.exports = { ROLES, ACTIONS, PERMISSIONS };

