import * as vscode from "vscode";
import { spawn } from "node:child_process";
import * as path from "node:path";
import { Environment, Listing, Project, Variable, dotenvValue, parseListing, referenceAt, referenceFor } from "./lib";

/** Runs the CLI with the master password on stdin; it never appears in the process list. */
function runCli(args: string[], password: string): Promise<string> {
  const cli = vscode.workspace.getConfiguration("yasecret").get<string>("cliPath") || "yasecret";
  return new Promise((resolve, reject) => {
    const child = spawn(cli, [...args, "--password-stdin"], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("error", (e) => reject(new Error(`Couldn't run ${cli}: ${e.message}. Install the yasecret CLI or set yasecret.cliPath.`)));
    child.on("close", (code) => (code === 0 ? resolve(out) : reject(new Error(err.trim().replace(/^error: /, "") || `${cli} exited with ${code}`))));
    child.stdin.end(password + "\n");
  });
}

type Node =
  | { kind: "project"; project: Project }
  | { kind: "environment"; project: Project; env: Environment }
  | { kind: "variable"; project: Project; env: Environment; variable: Variable };

class Vault implements vscode.TreeDataProvider<Node> {
  private password: string | null = null;
  private lockTimer: NodeJS.Timeout | undefined;
  listing: Listing | null = null;
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.changed.event;

  constructor(private readonly state: vscode.Memento) {}

  get unlocked() {
    return this.password !== null;
  }

  /** The environment hovers describe: [project, environment]. */
  get hoverTarget(): [string, string] | undefined {
    return this.state.get<[string, string]>("hoverTarget");
  }

  async setHoverTarget(project: string, env: string) {
    await this.state.update("hoverTarget", [project, env]);
  }

  private touch() {
    clearTimeout(this.lockTimer);
    const minutes = vscode.workspace.getConfiguration("yasecret").get<number>("lockAfterMinutes") ?? 15;
    this.lockTimer = setTimeout(() => this.lock(), minutes * 60_000);
  }

  async unlock(): Promise<boolean> {
    const password = await vscode.window.showInputBox({ prompt: "Yasecret master password", password: true, ignoreFocusOut: true });
    if (!password) return false;
    try {
      this.listing = parseListing(await runCli(["ls", "--json"], password));
    } catch (e) {
      vscode.window.showErrorMessage(`Yasecret: ${(e as Error).message}`);
      return false;
    }
    this.password = password;
    this.touch();
    await vscode.commands.executeCommand("setContext", "yasecret.unlocked", true);
    this.changed.fire();
    return true;
  }

  lock() {
    this.password = null;
    this.listing = null;
    clearTimeout(this.lockTimer);
    void vscode.commands.executeCommand("setContext", "yasecret.unlocked", false);
    this.changed.fire();
  }

  /** Runs a CLI command, asking to unlock first if needed. */
  async cli(args: string[]): Promise<string | undefined> {
    if (!this.password && !(await this.unlock())) return undefined;
    this.touch();
    return runCli(args, this.password!);
  }

  async refresh() {
    const out = await this.cli(["ls", "--json"]);
    if (out !== undefined) this.listing = parseListing(out);
    this.changed.fire();
  }

  getTreeItem(n: Node): vscode.TreeItem {
    switch (n.kind) {
      case "project": {
        const item = new vscode.TreeItem(n.project.name, vscode.TreeItemCollapsibleState.Collapsed);
        item.iconPath = new vscode.ThemeIcon("folder");
        item.contextValue = "project";
        return item;
      }
      case "environment": {
        const item = new vscode.TreeItem(n.env.name, vscode.TreeItemCollapsibleState.Collapsed);
        const hover = this.hoverTarget;
        const active = hover?.[0] === n.project.name && hover?.[1] === n.env.name;
        item.description = [n.env.inherits ? `inherits ${n.env.inherits}` : "", active ? "used for hovers" : ""].filter(Boolean).join(" · ");
        item.iconPath = new vscode.ThemeIcon("layers");
        item.contextValue = "environment";
        return item;
      }
      case "variable": {
        const v = n.variable;
        const item = new vscode.TreeItem(v.key, vscode.TreeItemCollapsibleState.None);
        item.description = [v.secret ? "secret" : "", v.type ?? ""].filter(Boolean).join(" · ");
        item.iconPath = new vscode.ThemeIcon(v.secret ? "lock" : "symbol-variable");
        item.contextValue = v.secret ? "variable-secret" : "variable";
        item.tooltip = `${v.key} in ${n.project.name}/${n.env.name}`;
        return item;
      }
    }
  }

  getChildren(n?: Node): Node[] {
    if (!this.listing) return [];
    if (!n) return this.listing.projects.map((project) => ({ kind: "project", project }));
    if (n.kind === "project") return n.project.environments.map((env) => ({ kind: "environment", project: n.project, env }));
    if (n.kind === "environment") return n.env.variables.map((variable) => ({ kind: "variable", project: n.project, env: n.env, variable }));
    return [];
  }

  /** A value as programs see it (inheritance and references applied). */
  async value(project: string, env: string, key: string): Promise<string | undefined> {
    const out = await this.cli(["env", "-p", project, "-e", env, "--shell", "dotenv", "--only", key]);
    return out === undefined ? undefined : dotenvValue(out, key);
  }
}

export function activate(context: vscode.ExtensionContext) {
  const vault = new Vault(context.workspaceState);
  void vscode.commands.executeCommand("setContext", "yasecret.unlocked", false);
  const reg = (id: string, fn: (...a: any[]) => unknown) =>
    context.subscriptions.push(
      vscode.commands.registerCommand(id, async (...a) => {
        try {
          await fn(...a);
        } catch (e) {
          vscode.window.showErrorMessage(`Yasecret: ${(e as Error).message}`);
        }
      }),
    );

  context.subscriptions.push(vscode.window.registerTreeDataProvider("yasecret.variables", vault));
  reg("yasecret.unlock", () => vault.unlock());
  reg("yasecret.lock", () => vault.lock());
  reg("yasecret.refresh", () => vault.refresh());
  reg("yasecret.useEnvironment", async (n: Node) => {
    if (n.kind !== "environment") return;
    await vault.setHoverTarget(n.project.name, n.env.name);
    await vault.refresh();
  });
  reg("yasecret.copyKey", (n: Node) => n.kind === "variable" && vscode.env.clipboard.writeText(n.variable.key));
  reg("yasecret.copyValue", async (n: Node) => {
    if (n.kind !== "variable") return;
    const value = await vault.value(n.project.name, n.env.name, n.variable.key);
    if (value === undefined) return;
    await vscode.env.clipboard.writeText(value);
    if (n.variable.secret) {
      vscode.window.setStatusBarMessage(`Copied ${n.variable.key}; the clipboard clears in 60 seconds`, 5000);
      setTimeout(async () => {
        if ((await vscode.env.clipboard.readText()) === value) await vscode.env.clipboard.writeText("");
      }, 60_000);
    }
  });
  reg("yasecret.insertReference", async (n: Node) => {
    const editor = vscode.window.activeTextEditor;
    if (n.kind !== "variable" || !editor) return;
    const text = referenceFor(editor.document.languageId, n.variable.key);
    await editor.edit((b) => editor.selections.forEach((s) => b.replace(s, text)));
  });
  reg("yasecret.pullEnv", async (n?: Node) => {
    let project: string | undefined;
    let env: string | undefined;
    if (n?.kind === "environment") {
      [project, env] = [n.project.name, n.env.name];
    } else {
      if (!vault.listing && !(await vault.unlock())) return;
      const pick = await vscode.window.showQuickPick(
        vault.listing!.projects.flatMap((p) => p.environments.map((e) => ({ label: `${p.name} / ${e.name}`, project: p.name, env: e.name }))),
        { placeHolder: "Which environment?" },
      );
      if (!pick) return;
      [project, env] = [pick.project, pick.env];
    }
    const folder = vscode.workspace.workspaceFolders?.[0]?.uri;
    const target = await vscode.window.showSaveDialog({
      defaultUri: folder ? vscode.Uri.joinPath(folder, ".env") : undefined,
      saveLabel: "Write .env",
    });
    if (!target) return;
    await vault.cli(["pull", "-p", project!, "-e", env!, "-o", target.fsPath]);
    vscode.window.showInformationMessage(`Wrote ${path.basename(target.fsPath)} from ${project}/${env}. Keep it out of version control.`);
  });

  context.subscriptions.push(
    vscode.languages.registerHoverProvider({ scheme: "file" }, {
      provideHover(doc, pos) {
        const ref = referenceAt(doc.lineAt(pos.line).text, pos.character);
        const target = vault.hoverTarget;
        if (!ref || !vault.listing || !target) return undefined;
        const env = vault.listing.projects.find((p) => p.name === target[0])?.environments.find((e) => e.name === target[1]);
        const v = env?.variables.find((x) => x.key === ref.key);
        if (!env) return undefined;
        const md = new vscode.MarkdownString();
        if (v) {
          md.appendMarkdown(`**${v.key}** · ${target[0]}/${target[1]}`);
          if (v.secret || v.type) md.appendMarkdown(` · ${[v.secret ? "secret" : "", v.type ?? ""].filter(Boolean).join(", ")}`);
        } else if (env.inherits) {
          md.appendMarkdown(`**${ref.key}** isn't set in ${target[0]}/${target[1]} itself (it may come from ${env.inherits})`);
        } else {
          md.appendMarkdown(`**${ref.key}** isn't set in ${target[0]}/${target[1]}`);
        }
        return new vscode.Hover(md, new vscode.Range(pos.line, ref.start, pos.line, ref.end));
      },
    }),
  );
}

export function deactivate() {}
