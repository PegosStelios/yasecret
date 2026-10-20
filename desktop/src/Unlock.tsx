import { FormEvent, useEffect, useState } from "react";
import { Lock } from "lucide-react";
import { api, errorText, VaultState } from "./api";
import { Button, TextInput } from "./ui";
import { ForgotPasswordSheet, RestoreBackupSheet } from "./vault";

export default function Unlock({ onUnlocked }: { onUnlocked: () => void }) {
  const [state, setState] = useState<VaultState | null>(null);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  // Saving is opt-in unless Windows Hello guards the saved password.
  const [remember, setRemember] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dialog, setDialog] = useState<{ kind: "forgot" } | { kind: "restore"; file: string } | null>(null);

  useEffect(() => {
    api.vaultState().catch((e) => { setError(errorText(e)); return null; }).then(async (s) => {
      if (!s) return;
      setState(s);
      setRemember(s.hello);
      if (s.devPassword) {
        await api.devUnlock().then(onUnlocked).catch((e) => setError(errorText(e)));
      } else if (s.hello && s.hasRemembered && !s.firstRun) {
        // Like Touch ID on the Mac: ask straight away; cancelling leaves the password field.
        setBusy(true);
        await api.unlockRemembered().then(onUnlocked).catch((e) => setError(errorText(e)));
        setBusy(false);
      }
    });
  }, [onUnlocked]);

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.unlock(password, state?.firstRun ? confirm : null, remember);
      onUnlocked();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const useSaved = async () => {
    setBusy(true);
    try {
      await api.unlockRemembered();
      onUnlocked();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  if (!state) {
    return error ? (
      <div className="flex h-full items-center justify-center p-8 text-center text-danger">Couldn't open Yasecret: {error}</div>
    ) : null;
  }
  const firstRun = state.firstRun;
  return (
    <div className="flex h-full items-center justify-center">
      <form onSubmit={submit} className="flex w-72 flex-col items-center gap-3">
        <Lock size={44} className="mb-1 text-muted" />
        <h1 className="text-[26px] font-bold">Yasecret</h1>
        {firstRun && <p className="text-muted">Create your master password</p>}
        <TextInput type="password" autoFocus placeholder="Master password" value={password} onChange={(e) => setPassword(e.target.value)} />
        {firstRun && <TextInput type="password" placeholder="Confirm password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />}
        <label className="flex w-full items-center gap-2 text-muted">
          <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
          {state.hello ? "Unlock with Windows Hello next time" : "Remember on this device"}
        </label>
        {error && <p className="text-[13px] text-danger">{error}</p>}
        <Button type="submit" variant="primary" disabled={busy || !password || (firstRun && !confirm)} className="w-full justify-center">
          {busy ? "Unlocking…" : firstRun ? "Create Vault" : "Unlock"}
        </Button>
        <div className="flex gap-4 text-[13px]">
          {!firstRun && <button type="button" className="text-accent hover:underline" onClick={() => setDialog({ kind: "forgot" })}>Forgot password?</button>}
          <button
            type="button"
            className="text-accent hover:underline"
            onClick={async () => {
              setError(null);
              try {
                const file = await api.pickBackup();
                if (file) setDialog({ kind: "restore", file });
              } catch (e) {
                setError(errorText(e));
              }
            }}
          >
            Restore from backup…
          </button>
        </div>
        {state.hasRemembered && !firstRun && (
          <div className="flex gap-1">
            <Button variant="ghost" onClick={useSaved} disabled={busy}>{state.hello ? "Unlock with Windows Hello" : "Unlock with saved password"}</Button>
            <Button
              variant="ghost"
              disabled={busy}
              onClick={async () => {
                await api.forgetPassword().catch(() => {});
                setState({ ...state, hasRemembered: false });
              }}
            >
              Forget it
            </Button>
          </div>
        )}
      </form>
      {dialog?.kind === "forgot" && <ForgotPasswordSheet onClose={() => setDialog(null)} onUnlocked={onUnlocked} />}
      {dialog?.kind === "restore" && (
        <RestoreBackupSheet fileName={dialog.file} replaces={!firstRun} onClose={() => setDialog(null)} onUnlocked={onUnlocked} />
      )}
    </div>
  );
}
