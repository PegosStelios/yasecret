import { useEffect, useState } from "react";
import { Check, Copy, Crown, Radio, User } from "lucide-react";
import { api, errorText, levelLabel, relativeTime, Member, Project, SyncStatus } from "./api";
import { Button, Confirm, ErrorLine, Modal, Segmented, TextInput } from "./ui";

export function sharingSummary(status: SyncStatus | null, members: Member[]): string | null {
  if (!status?.shared) return null;
  const parts = [
    ({ owner: "Shared", viewer: "View only", pending: "Waiting for the owner" } as Record<string, string>)[status.myLevel] ?? "Shared",
  ];
  const others = Math.max(members.length - 1, 0);
  if (others) parts.push(`${others} member${others === 1 ? "" : "s"}`);
  parts.push(status.peersOnline > 0 ? `${status.peersOnline} online` : "offline");
  return parts.join(" · ");
}

function CopyBox({ text, sensitive }: { text: string; sensitive: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-start gap-2 rounded-lg bg-field p-2.5">
      <code className="selectable line-clamp-3 min-w-0 flex-1 font-mono text-xs break-all">{text}</code>
      <Button onClick={async () => { await api.copyText(text, sensitive); setCopied(true); setTimeout(() => setCopied(false), 2000); }}>
        {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? "Copied" : "Copy"}
      </Button>
    </div>
  );
}

export function ShareSheet({ project, status, members, onRefresh, onStopped, onClose }: {
  project: Project;
  status: SyncStatus | null;
  members: Member[];
  onRefresh: () => Promise<void>;
  onStopped: () => void;
  onClose: () => void;
}) {
  const [mode, setMode] = useState<"link" | "device">("link");
  const [access, setAccess] = useState<"editor" | "viewer">("editor");
  const [code, setCode] = useState("");
  const [link, setLink] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmStop, setConfirmStop] = useState(false);
  const shared = status?.shared ?? false;
  const isOwner = !shared || (status?.isOwner ?? false);
  const cleaned = code.replace(/\s+/g, "");

  useEffect(() => {
    const t = window.setInterval(() => onRefresh().catch(() => {}), 3000);
    return () => window.clearInterval(t);
  }, [onRefresh]);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      setLink(await api.createInvite(project.id, mode === "device" ? cleaned : null, access));
      await onRefresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const setLevel = async (m: Member, level: string) => {
    try {
      await api.setMemberLevel(project.id, m.peerId, level);
      await onRefresh();
    } catch (e) {
      setError(errorText(e));
    }
  };

  return (
    <Modal
      title={`Share “${project.name}”`}
      onClose={onClose}
      width={580}
      footer={
        <>
          {shared && <Button variant="danger" className="mr-auto" onClick={() => setConfirmStop(true)}>{isOwner ? "Stop Sharing…" : "Leave Project…"}</Button>}
          <Button variant="primary" onClick={onClose}>Done</Button>
        </>
      }
    >
      {isOwner ? (
        <div className="space-y-3">
          <Segmented value={mode} onChange={(v) => { setMode(v); setLink(null); }} options={[{ value: "link", label: "Invite link" }, { value: "device", label: "Device-bound invite" }]} />
          <p className="text-muted">
            {mode === "link"
              ? "Anyone with the link can join once, within 24 hours. Send it over a private channel."
              : "Only the device whose code you paste can use this invite, so it's safe to send anywhere. Your teammate finds their code in Join."}
          </p>
          {mode === "device" && <TextInput mono placeholder="Teammate's device code" value={code} onChange={(e) => setCode(e.target.value)} />}
          <div className="flex items-center gap-3">
            <span className="text-muted">Access</span>
            <Segmented value={access} onChange={setAccess} options={[{ value: "editor", label: "Can edit" }, { value: "viewer", label: "Can view" }]} />
            <span className="flex-1" />
            <Button variant="primary" disabled={busy || (mode === "device" && cleaned.length !== 64)} onClick={create}>
              {busy ? "Creating…" : link ? "Create Another" : "Create Invite"}
            </Button>
          </div>
          {link && (
            <>
              <CopyBox text={link} sensitive={mode === "link"} />
              <p className="flex items-center gap-1.5 text-xs text-muted"><Radio size={13} /> Keep Yasecret open and unlocked until they've joined. Devices sync directly, with no server in between.</p>
            </>
          )}
        </div>
      ) : (
        <p className="text-muted">Only the owner of this project can invite people.</p>
      )}

      {shared && (
        <div className="mt-5 border-t border-line pt-4">
          <h3 className="mb-2 font-semibold">People</h3>
          {members.length === 0 && <p className="text-muted">No one has joined yet.</p>}
          {members.map((m) => (
            <div key={m.peerId} className="flex items-center gap-3 py-1.5">
              {m.level === "owner" ? <Crown size={16} className="text-muted" /> : <User size={16} className="text-muted" />}
              <div className="min-w-0 flex-1">
                <div className="truncate">{m.name}{m.isMe ? " (this computer)" : ""}</div>
                <div className="text-xs text-muted">Joined {relativeTime(m.joinedAt)}</div>
              </div>
              {isOwner && !m.isMe && m.level !== "owner" && m.level !== "pending" ? (
                <select value={m.level} onChange={(e) => setLevel(m, e.target.value)} className="h-7 rounded-md border border-line bg-field px-2">
                  <option value="editor">Can edit</option>
                  <option value="viewer">Can view</option>
                  <option value="removed">Remove</option>
                </select>
              ) : (
                <span className="text-muted">{levelLabel(m.level)}</span>
              )}
            </div>
          ))}
          {isOwner && members.length > 1 && (
            <p className="mt-2 text-xs text-muted">Removing someone replaces the project key, so they can't read anything written afterwards.</p>
          )}
        </div>
      )}
      <ErrorLine text={error} />
      {confirmStop && (
        <Confirm
          title={isOwner ? `Stop sharing “${project.name}”?` : `Leave “${project.name}”?`}
          message={isOwner
            ? "Everyone loses access to future changes. The project key is replaced, so old invites and copies can't read new values. You keep all your data."
            : "The project and its variables are removed from this computer. You'll need a new invite to rejoin."}
          action={isOwner ? "Stop Sharing" : "Leave and Remove"}
          onClose={() => setConfirmStop(false)}
          onConfirm={async () => {
            try {
              await api.stopSharing(project.id);
              onStopped();
              onClose();
            } catch (e) {
              setError(errorText(e));
            }
          }}
        />
      )}
    </Modal>
  );
}

export function JoinSheet({ initialLink, onJoined, onClose }: { initialLink: string; onJoined: (projectId: string) => Promise<void>; onClose: () => void }) {
  const [link, setLink] = useState(initialLink);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { api.deviceCode().then(setCode).catch(() => {}); }, []);
  const trimmed = link.trim();
  const join = async () => {
    setBusy(true);
    setError(null);
    try {
      const pid = await api.joinProject(trimmed);
      await onJoined(pid);
      onClose();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Join a Shared Project"
      onClose={onClose}
      width={540}
      footer={
        <>
          {busy && <span className="mr-auto text-muted">Connecting to the owner's computer…</span>}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={busy || !trimmed.startsWith("yasecret://join")} onClick={join}>Join</Button>
        </>
      }
    >
      <p className="mb-3 text-muted">Paste the invite link you were sent. The person who shared it needs Yasecret open and unlocked while you join.</p>
      <textarea
        value={link}
        disabled={busy}
        onChange={(e) => setLink(e.target.value)}
        rows={3}
        className="w-full resize-none rounded-md border border-line bg-field p-2.5 font-mono text-xs outline-none focus:border-accent"
      />
      <div className="mt-4 rounded-lg border border-line p-3">
        <p className="mb-2">Asked for a device code? Send this to the project owner:</p>
        <CopyBox text={code.match(/.{1,8}/g)?.join(" ") ?? ""} sensitive={false} />
      </div>
      <ErrorLine text={error} />
    </Modal>
  );
}
