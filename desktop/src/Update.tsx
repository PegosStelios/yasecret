import { useEffect, useState } from "react";
import { check, Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { Download } from "lucide-react";
import { errorText } from "./api";
import { Button } from "./ui";

/** Checks GitHub Releases once per launch; offers a signed update without interrupting. */
export default function UpdateBar() {
  const [update, setUpdate] = useState<Update | null>(null);
  const [state, setState] = useState<"idle" | "installing" | "dismissed">("idle");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (import.meta.env.DEV) return;
    // Offline or no release yet: stay quiet.
    check().then(setUpdate).catch(() => {});
  }, []);

  if (!update || state === "dismissed") return null;
  const install = async () => {
    setState("installing");
    setError(null);
    try {
      await update.downloadAndInstall();
      await relaunch();
    } catch (e) {
      setError(errorText(e));
      setState("idle");
    }
  };
  return (
    <div className="flex items-center gap-3 border-b border-line bg-field px-4 py-2 text-[13px]">
      <Download size={15} className="text-accent" />
      <span className="flex-1">
        {error ? `Update failed: ${error}` : `Yasecret ${update.version} is available.`}
      </span>
      <Button variant="ghost" disabled={state === "installing"} onClick={() => setState("dismissed")}>Later</Button>
      <Button variant="primary" disabled={state === "installing"} onClick={install}>
        {state === "installing" ? "Installing…" : "Install and Restart"}
      </Button>
    </div>
  );
}
