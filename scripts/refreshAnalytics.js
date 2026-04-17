const path = require("path");
try {
  const dotenv = require("dotenv");
  dotenv.config({ path: path.join(__dirname, "..", ".env") });
} catch (error) {
  // dotenv is optional when env vars are already provided
}

const { refreshAnalyticsTables } = require("../lib/analytics");

async function main() {
  await refreshAnalyticsTables();
  console.log("Analytics refresh complete.");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
