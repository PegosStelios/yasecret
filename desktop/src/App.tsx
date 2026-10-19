import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { getCurrent } from "@tauri-apps/plugin-deep-link";
import { api } from "./api";
import Unlock from "./Unlock";
import Main from "./MainWindow";

const IDLE_LOCK_MS = 10 * 60 * 1000;

export default function App() {
  const [unlocked, setUnlocked] = useState<boolean | null>(null);
  const [joinLink, setJoinLink] = useState<string | null>(null);

  useEffect(() => {
    // A failure here still shows the unlock screen, which reports the error itself.
    api.vaultState().then((s) => setUnlocked(s.unlocked)).catch(() => setUnlocked(false));
    getCurrent().then((urls) => urls?.[0] && setJoinLink(urls[0])).catch(() => {});
    const off = listen<string>("join-link", (e) => setJoinLink(e.payload));
    return () => { off.then((f) => f()); };
  }, []);

  const lock = useCallback(async () => {
    await api.lock();
    setUnlocked(false);
  }, []);

  // No portable screen-lock hook, so lock after a stretch of inactivity instead.
  useEffect(() => {
    if (!unlocked) return;
    let timer = window.setTimeout(lock, IDLE_LOCK_MS);
    const reset = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(lock, IDLE_LOCK_MS);
    };
    const events = ["mousemove", "keydown", "mousedown", "wheel"];
    events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    return () => {
      window.clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, reset));
    };
  }, [unlocked, lock]);

  if (unlocked === null) return null;
  return unlocked ? (
    <Main onLock={lock} joinLink={joinLink} onJoinLinkHandled={() => setJoinLink(null)} />
  ) : (
    <Unlock onUnlocked={() => setUnlocked(true)} />
  );
}
