const path = require("path");
try {
  const dotenv = require("dotenv");
  dotenv.config({ path: path.join(__dirname, "..", ".env") });
} catch (error) {
  // dotenv is optional when env vars are already provided
}

const { refreshAnalyticsTables } = require("../lib/analytics");

function parseArgs(argv) {
  const args = {};
  for (const entry of argv) {
    if (!entry.startsWith("--")) continue;
    const [rawKey, rawValue] = entry.slice(2).split("=");
    args[rawKey] = rawValue === undefined ? true : rawValue;
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = await refreshAnalyticsTables({ windowDays: args.days });
  console.log(`Analytics refresh complete for the last ${result.window_days} day(s).`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
