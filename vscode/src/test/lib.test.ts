import { test } from "node:test";
import * as assert from "node:assert/strict";
import { parseListing, referenceAt, referenceFor, dotenvValue } from "../lib";

test("parses the CLI listing", () => {
  const listing = parseListing(JSON.stringify({
    projects: [{ name: "shop", environments: [{ name: "dev", inherits: null, variables: [{ key: "API_KEY", secret: true, type: null }] }] }],
  }));
  assert.equal(listing.projects[0].environments[0].variables[0].key, "API_KEY");
  assert.throws(() => parseListing("not json"), /yasecret/);
});

test("finds the variable a reference points at", () => {
  const at = (line: string, col: number) => referenceAt(line, col)?.key;
  assert.equal(at("const k = process.env.API_KEY;", 25), "API_KEY");
  assert.equal(at('const k = process.env["DB_URL"]', 25), "DB_URL");
  assert.equal(at('x = os.environ["PORT"]', 18), "PORT");
  assert.equal(at('x = os.getenv("PORT")', 16), "PORT");
  assert.equal(at('url: "${DATABASE_URL}/x"', 10), "DATABASE_URL");
  assert.equal(at("echo $HOME_DIR", 8), "HOME_DIR");
  assert.equal(at('let v = env::var("TOKEN")', 19), "TOKEN");
  assert.equal(at("const k = process.env.API_KEY;", 3), undefined, "cursor outside the reference");
  assert.equal(at("plain words", 3), undefined);
});

test("writes references in the file's language", () => {
  assert.equal(referenceFor("typescript", "API_KEY"), "process.env.API_KEY");
  assert.equal(referenceFor("python", "API_KEY"), 'os.environ["API_KEY"]');
  assert.equal(referenceFor("go", "API_KEY"), 'os.Getenv("API_KEY")');
  assert.equal(referenceFor("rust", "API_KEY"), 'std::env::var("API_KEY")');
  assert.equal(referenceFor("shellscript", "API_KEY"), '"${API_KEY}"');
  assert.equal(referenceFor("plaintext", "API_KEY"), "${API_KEY}");
});

test("reads one value out of dotenv output", () => {
  const text = "A=1\nB='two words'\nC=\"line1\\nline2\"\n";
  assert.equal(dotenvValue(text, "B"), "two words");
  assert.equal(dotenvValue(text, "C"), "line1\nline2");
  assert.equal(dotenvValue(text, "Z"), undefined);
});
