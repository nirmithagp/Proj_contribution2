const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const dbPath = path.join(__dirname, "..", "..", "users.db");
const db = new sqlite3.Database(dbPath);

console.log("🔄 Adding missing columns to users table...");

db.serialize(() => {
    // Add username column
    db.run("ALTER TABLE users ADD COLUMN username TEXT", (err) => {
        if (err && !err.message.includes("duplicate column")) {
            console.error("❌ Error adding username:", err.message);
        } else {
            console.log("✅ Added username column");
        }
    });

    // Add github_username column
    db.run("ALTER TABLE users ADD COLUMN github_username TEXT", (err) => {
        if (err && !err.message.includes("duplicate column")) {
            console.error("❌ Error adding github_username:", err.message);
        } else {
            console.log("✅ Added github_username column");
        }
    });
});

db.close(() => {
    console.log("📦 Migration complete.");
});
