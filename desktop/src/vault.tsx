import { useEffect, useState } from "react";
import { Check, Copy, Download, KeyRound, ShieldCheck } from "lucide-react";
import { api, errorText } from "./api";
import { Button, ErrorLine, Modal, SHEET, TextInput } from "./ui";

function mismatch(a: string, b: string): string | null {
  return a && b && a !== b ? "The new passwords don't match" : null;
}

function NewPasswordFields({ value, confirm, onValue, onConfirm }: { value: string; confirm: string; onValue: (v: string) => void; onConfirm: (v: string) => void }) {
  return (
    <>
      <TextInput type="password" placeholder="New password" value={value} onChange={(e) => onValue(e.target.value)} />
      <TextInput type="password" placeholder="Repeat new password" value={confirm} onChange={(e) => onConfirm(e.target.value)} />
    </>
  );
}

/** Vault actions from the sidebar: password, recovery key, backup. */
export function VaultSheet({ onClose, onLockedOut }: { onClose: () => void; onLockedOut: () => void }) {
  const [view, setView] = useState<"menu" | "password" | "recovery">("menu");
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (view === "password") return <ChangePasswordSheet onClose={onClose} onLockedOut={onLockedOut} />;
  if (view === "recovery") return <RecoveryKeySheet onClose={onClose} />;

  const backup = async () => {
    setError(null);
    try {
      const name = await api.backupVault();
      if (name) setNote(`Backed up to ${name}. Restoring it needs the master password you have now.`);
    } catch (e) {
      setError(errorText(e));
    }
  };
  const row = (icon: React.ReactNode, title: string, text: string, action: string, onClick: () => void) => (
    <div className="flex items-center gap-3 py-2.5">
      <span className="text-muted">{icon}</span>
      <div className="min-w-0 flex-1">
        <div className="font-medium">{title}</div>
        <div className="text-xs text-muted">{text}</div>
      </div>
      <Button onClick={onClick}>{action}</Button>
    </div>
  );
  return (
    <Modal title="Vault" onClose={onClose} width={SHEET.medium} footer={<Button variant="primary" onClick={onClose}>Done</Button>}>
      <div className="divide-y divide-line">
        {row(<KeyRound size={18} />, "Master password", "Re-encrypts the vault with a new password.", "Change…", () => setView("password"))}
        {row(<ShieldCheck size={18} />, "Recovery key", "Resets a forgotten master password.", "Set Up…", () => setView("recovery"))}
        {row(<Download size={18} />, "Backup", "One encrypted file with every project.", "Back Up…", backup)}
      </div>
      {note && <p className="mt-3 text-[13px] text-muted">{note}</p>}
      <ErrorLine text={error} />
    </Modal>
  );
}

function ChangePasswordSheet({ onClose, onLockedOut }: { onClose: () => void; onLockedOut: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const can = !busy && !!current && !!next && next === confirm;
  const change = async () => {
    if (!can) return;
    setBusy(true);
    setError(null);
    try {
      await api.changePassword(current, next);
      onClose();
    } catch (e) {
      setError(errorText(e));
      // If the vault couldn't be reopened, the main window has nothing to show.
      const s = await api.vaultState().catch(() => null);
      if (s && !s.unlocked) onLockedOut();
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Change Master Password"
      onClose={onClose}
      dismissible={!busy}
      onEnter={change}
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant="primary" disabled={!can} onClick={change}>{busy ? "Re-encrypting…" : "Change Password"}</Button>
        </>
      }
    >
      <p className="mb-3 text-muted">The vault is re-encrypted with the new password. Your recovery key keeps working; earlier backups still need the password they were made with.</p>
      <div className="space-y-2">
        <TextInput type="password" autoFocus placeholder="Current password" value={current} onChange={(e) => setCurrent(e.target.value)} />
        <NewPasswordFields value={next} confirm={confirm} onValue={setNext} onConfirm={setConfirm} />
      </div>
      <ErrorLine text={error ?? mismatch(next, confirm)} />
    </Modal>
  );
}

function RecoveryKeySheet({ onClose }: { onClose: () => void }) {
  const [existing, setExisting] = useState(false);
  const [key, setKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { api.hasRecoveryKey().then(setExisting).catch(() => {}); }, []);
  const make = async () => {
    try {
      setKey(await api.createRecoveryKey());
    } catch (e) {
      setError(errorText(e));
    }
  };
  return (
    <Modal
      title="Recovery Key"
      onClose={onClose}
      dismissible={!key}
      onEnter={key ? onClose : make}
      footer={key
        ? <Button variant="primary" onClick={onClose}>I've Saved It</Button>
        : <>
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" onClick={make}>{existing ? "Make New Key" : "Make Recovery Key"}</Button>
          </>}
    >
      {key ? (
        <>
          <p className="mb-3 text-muted">Write this down or store it in a password manager, away from this computer. It's shown only once.</p>
          <div className="flex items-start gap-2 rounded-lg bg-field p-2.5">
            <code className="selectable min-w-0 flex-1 font-mono text-sm break-all">{key}</code>
            <Button
              onClick={async () => {
                await api.copyText(key, true).catch(() => {});
                setCopied(true);
              }}
            >
              {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <p className="mt-2 text-xs text-muted">Anyone with this key and your vault files can reset the master password.</p>
        </>
      ) : (
        <p className="text-muted">
          {existing
            ? "This vault has a recovery key. Making a new one retires the old key."
            : "A recovery key lets you set a new master password if you forget it. Without one, a forgotten password means losing the vault."}
        </p>
      )}
      <ErrorLine text={error} />
    </Modal>
  );
}

/** From the unlock screen: reset the master password with the recovery key. */
export function ForgotPasswordSheet({ onClose, onUnlocked }: { onClose: () => void; onUnlocked: () => void }) {
  const [available, setAvailable] = useState<boolean | null>(null);
  const [key, setKey] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { api.hasRecoveryKey().then(setAvailable).catch(() => setAvailable(false)); }, []);
  const can = !busy && !!available && !!key.trim() && !!next && next === confirm;
  const reset = async () => {
    if (!can) return;
    setBusy(true);
    setError(null);
    try {
      await api.recoverVault(key, next);
      onUnlocked();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Reset Master Password"
      onClose={onClose}
      dismissible={!busy}
      onEnter={reset}
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant="primary" disabled={!can} onClick={reset}>{busy ? "Resetting…" : "Reset Password"}</Button>
        </>
      }
    >
      {available === false ? (
        <p className="text-muted">This vault has no recovery key, so the master password can't be reset. If you have a backup, restore it instead.</p>
      ) : (
        <>
          <p className="mb-3 text-muted">Enter your recovery key and choose a new master password.</p>
          <div className="space-y-2">
            <TextInput mono autoFocus placeholder="Recovery key" value={key} onChange={(e) => setKey(e.target.value)} />
            <NewPasswordFields value={next} confirm={confirm} onValue={setNext} onConfirm={setConfirm} />
          </div>
        </>
      )}
      <ErrorLine text={error ?? mismatch(next, confirm)} />
    </Modal>
  );
}

/** From the unlock screen, after a backup file was picked. */
export function RestoreBackupSheet({ fileName, replaces, onClose, onUnlocked }: { fileName: string; replaces: boolean; onClose: () => void; onUnlocked: () => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const restore = async () => {
    if (busy || !password) return;
    setBusy(true);
    setError(null);
    try {
      await api.restoreBackup(password);
      onUnlocked();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Restore from Backup"
      onClose={onClose}
      dismissible={!busy}
      onEnter={restore}
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant={replaces ? "danger" : "primary"} disabled={busy || !password} onClick={restore}>
            {busy ? "Restoring…" : replaces ? "Replace and Restore" : "Restore"}
          </Button>
        </>
      }
    >
      <p className="mb-3 text-muted">
        Restore “{fileName}” using the master password the vault had when it was backed up.
        {replaces && " This replaces the vault on this computer."}
      </p>
      <TextInput type="password" autoFocus placeholder="Backup's master password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <ErrorLine text={error} />
    </Modal>
  );
}
