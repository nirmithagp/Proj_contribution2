/**
 * Database Migration Script
 * Adds necessary columns to existing users table if they don't exist.
 * 
 * Run this script if you have an existing database:
 * node migrate-db.js
 */

const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const dbPath = path.join(__dirname, "users.db");
const db = new sqlite3.Database(dbPath);

const COLUMNS_TO_ADD = [
  { name: "refresh_token", type: "TEXT" },
  { name: "view_history", type: "TEXT DEFAULT '[]'" },
  { name: "created_at", type: "DATETIME DEFAULT CURRENT_TIMESTAMP" },
  { name: "updated_at", type: "DATETIME DEFAULT CURRENT_TIMESTAMP" },
  { name: "password_reset_token", type: "TEXT" },
  { name: "password_reset_expires", type: "DATETIME" },
  { name: "preferred_language", type: "TEXT DEFAULT 'en'" },
  { name: "preferences", type: "TEXT DEFAULT '{}'" }
];

console.log("🔄 Starting database migration...\n");

db.serialize(() => {
  // 1. Create auxiliary tables
  db.run(`CREATE TABLE IF NOT EXISTS search_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    query TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS search_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    query TEXT NOT NULL,
    results_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // 2. Add columns to users table
  db.all("PRAGMA table_info(users)", (err, columns) => {
    if (err) {
      console.error("❌ Error reading table info:", err);
      db.close();
      return;
    }

    const existingColumnNames = columns.map(col => col.name);
    let migrationsRun = 0;

    const runNextMigration = (index) => {
      if (index >= COLUMNS_TO_ADD.length) {
        // All checks done
        if (migrationsRun === 0) {
          console.log("✅ Database is already up to date!");
        } else {
          // Verify final state
          db.all("PRAGMA table_info(users)", (err, newColumns) => {
            if (!err) {
              console.log("\n📋 Final columns:", newColumns.map(col => col.name).join(", "));
              console.log("\n✅ Migration completed successfully!");
            }
            db.close();
          });
          return; // Don't close immediately here, closed in callback
        }
        db.close();
        return;
      }

      const col = COLUMNS_TO_ADD[index];
      if (!existingColumnNames.includes(col.name)) {
        console.log(`➕ Adding column: ${col.name}...`);
        db.run(`ALTER TABLE users ADD COLUMN ${col.name} ${col.type}`, (err) => {
          if (err) {
            console.error(`❌ Error adding ${col.name}:`, err.message);
          } else {
            console.log(`✅ Added ${col.name}`);
            migrationsRun++;
          }
          runNextMigration(index + 1);
        });
      } else {
        runNextMigration(index + 1);
      }
    };

    runNextMigration(0);
  });
});
