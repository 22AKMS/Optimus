const path = require("path");
const dotenv = require("dotenv");

dotenv.config({ path: path.join(__dirname, "..", ".env") });

const { refreshAnalyticsTables } = require("../lib/analytics");

async function main() {
  await refreshAnalyticsTables();
  console.log("Analytics refresh complete.");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
