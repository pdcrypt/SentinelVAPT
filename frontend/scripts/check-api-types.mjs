// Fails if src/lib/api/schema.d.ts is not what openapi-typescript generates
// from the committed OpenAPI snapshot (openapi/sentinelvapt.openapi.json).
// Refresh the snapshot from the backend with:
//   python -c "import json; from app.main import create_app; print(json.dumps(create_app().openapi(), indent=1, sort_keys=True))"
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const out = join(mkdtempSync(join(tmpdir(), "sv-api-")), "schema.d.ts");
execFileSync(
  process.execPath,
  ["node_modules/openapi-typescript/bin/cli.js", "openapi/sentinelvapt.openapi.json", "-o", out],
  { stdio: "ignore" },
);
if (readFileSync(out, "utf8") !== readFileSync("src/lib/api/schema.d.ts", "utf8")) {
  console.error("src/lib/api/schema.d.ts is out of date: run `npm run api:types`.");
  process.exit(1);
}
console.log("API types match the OpenAPI snapshot.");
