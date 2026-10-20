// Pure helpers for the extension (no vscode imports), so they can be unit-tested.

export type Variable = { key: string; secret: boolean; type: string | null };
export type Environment = { name: string; inherits: string | null; variables: Variable[] };
export type Project = { name: string; environments: Environment[] };
export type Listing = { projects: Project[] };

export function parseListing(text: string): Listing {
  try {
    const value = JSON.parse(text);
    if (!Array.isArray(value?.projects)) throw new Error("no projects");
    return value as Listing;
  } catch {
    throw new Error("Unexpected output from `yasecret ls --json`; is the yasecret CLI up to date?");
  }
}

// Each pattern captures the variable name in group 1.
const REFERENCE_PATTERNS: RegExp[] = [
  /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g,
  /process\.env\[\s*["'`]([A-Za-z_][A-Za-z0-9_]*)["'`]\s*\]/g,
  /import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)/g,
  /os\.environ(?:\.get)?[\[(]\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/g,
  /os\.(?:getenv|Getenv|LookupEnv)\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/g,
  /env::var\(\s*"([A-Za-z_][A-Za-z0-9_]*)"/g,
  /ENV\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]/g,
  /System\.getenv\(\s*"([A-Za-z_][A-Za-z0-9_]*)"/g,
  /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g,
  /\$([A-Za-z_][A-Za-z0-9_]*)/g,
];

/** The variable referenced at column `col` of `line`, if any. */
export function referenceAt(line: string, col: number): { key: string; start: number; end: number } | undefined {
  for (const pattern of REFERENCE_PATTERNS) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(line))) {
      const start = m.index;
      const end = m.index + m[0].length;
      if (col >= start && col <= end) return { key: m[1], start, end };
    }
  }
  return undefined;
}

/** How code in `languageId` reads an environment variable. */
export function referenceFor(languageId: string, key: string): string {
  switch (languageId) {
    case "javascript":
    case "typescript":
    case "javascriptreact":
    case "typescriptreact":
      return `process.env.${key}`;
    case "python":
      return `os.environ["${key}"]`;
    case "go":
      return `os.Getenv("${key}")`;
    case "rust":
      return `std::env::var("${key}")`;
    case "ruby":
      return `ENV["${key}"]`;
    case "java":
    case "kotlin":
      return `System.getenv("${key}")`;
    case "shellscript":
    case "dockerfile":
      return `"\${${key}}"`;
    default:
      return `\${${key}}`;
  }
}

/** One value from `yasecret pull` output (the CLI's own quoting rules). */
export function dotenvValue(text: string, key: string): string | undefined {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const eq = lines[i].indexOf("=");
    if (eq < 0 || lines[i].slice(0, eq) !== key) continue;
    let rest = lines[i].slice(eq + 1);
    if (rest.startsWith("'")) {
      while (!rest.slice(1).includes("'") && i + 1 < lines.length) rest += "\n" + lines[++i];
      return rest.slice(1, rest.indexOf("'", 1));
    }
    if (rest.startsWith('"')) {
      let body = rest.slice(1);
      while (!/(^|[^\\])(\\\\)*"$/.test(body) && i + 1 < lines.length) body += "\n" + lines[++i];
      body = body.slice(0, -1);
      return body.replace(/\\(.)/g, (_, c) => ({ n: "\n", r: "\r", t: "\t" } as Record<string, string>)[c] ?? c);
    }
    return rest;
  }
  return undefined;
}
