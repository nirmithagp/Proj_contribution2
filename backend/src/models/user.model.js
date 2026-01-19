const db = require("../config/db");

/**
 * Create a new user
 */
exports.createUser = (email, password) =>
  new Promise((resolve, reject) => {
    if (!email || typeof email !== "string" || email.length > 254) {
      return reject(new Error("Invalid email"));
    }

    if (!password || typeof password !== "string" || password.length > 128) {
      return reject(new Error("Invalid password"));
    }

    db.run(
      `INSERT INTO users (email, password)
       VALUES (?, ?)`,
      [email, password],
      function (err) {
        if (err) return reject(err);
        resolve({
          id: this.lastID,
          email
        });
      }
    );
  });

/**
 * Find user by email
 */
exports.findByEmail = (email) =>
  new Promise((resolve, reject) => {
    if (!email || typeof email !== "string") {
      return reject(new Error("Invalid email"));
    }

    db.get(
      `SELECT id, email, password, refresh_token
       FROM users
       WHERE email = ?`,
      [email],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });

/**
 * Find user by ID
 */
exports.findById = (id) =>
  new Promise((resolve, reject) => {
    const userId = Number(id);
    if (!userId || userId <= 0) {
      return reject(new Error("Invalid user ID"));
    }

    db.get(
      `SELECT id, email, view_history
       FROM users
       WHERE id = ?`,
      [userId],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });

/**
 * Update refresh token (login / logout)
 */
exports.updateRefreshToken = (userId, refreshToken) =>
  new Promise((resolve, reject) => {
    db.run(
      "UPDATE users SET refresh_token = ? WHERE id = ?",
      [refreshToken, userId],
      function (err) {
        if (err) reject(err);
        else resolve(this.changes);
      }
    );
  });


/**
 * Update user view history
 */
exports.updateViewHistory = (userId, historyJson) =>
  new Promise((resolve, reject) => {
    const id = Number(userId);
    if (!id || id <= 0) {
      return reject(new Error("Invalid user ID"));
    }

    if (historyJson && typeof historyJson !== "string") {
      return reject(new Error("Invalid history data"));
    }

    db.run(
      `UPDATE users
       SET view_history = ?

       WHERE id = ?`,
      [historyJson, id],
      function (err) {
        if (err) return reject(err);
        resolve(this.changes);
      }
    );
  });
exports.deleteAllUsers = () =>
  new Promise((resolve, reject) => {
    db.run("DELETE FROM users", (err) => {
      if (err) reject(err);
      else resolve();
    });
  });

