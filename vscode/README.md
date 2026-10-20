# Yasecret for VS Code

Browse the variables in your [Yasecret](https://github.com/PegosStelios/yasecret) vault from the sidebar and use them without leaving the editor.

- **Variables view:** projects → environments → variable names (values are never listed).
- **Copy Value** (secrets are cleared from the clipboard after 60 seconds), **Copy Name**, and **Insert Reference**, written for the file's language (`process.env.API_KEY`, `os.environ["API_KEY"]`, `os.Getenv("API_KEY")`…).
- **Write .env…** writes an environment to a file, readable only by you.
- **Hovers:** pick *Use This Environment for Hovers* on an environment, then hover a reference in code to see where the variable comes from and its type.

Requires the `yasecret` CLI (`cargo install --path crates/cli` from the Yasecret repository) or set `yasecret.cliPath`. The extension asks for your master password once and passes it to the CLI over standard input; it keeps it in memory only and forgets it after `yasecret.lockAfterMinutes` (default 15) without use.
