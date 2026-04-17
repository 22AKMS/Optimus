const path = require("path");
const dotenv = require("dotenv");

dotenv.config({ path: path.join(__dirname, "..", ".env") });

const { spawn } = require("child_process");

const child = spawn(process.execPath, [path.join(__dirname, "syncNvdToDb.js"), "--days=30", "--max-records=300"], {
  stdio: "inherit",
  env: process.env
});

child.on("exit", (code) => {
  process.exit(code ?? 0);
});
