import { useEffect, useState } from "react";
import { Check, Copy, Crown, Radio, Server, User } from "lucide-react";
import { api, errorText, levelLabel, relativeTime, Member, Project, Relay, SyncStatus } from "./api";
import { Button, Confirm, ErrorLine, Modal, SHEET, Segmented, TextInput } from "./ui";

export function sharingSummary(status: SyncStatus | null, members: Member[]): string | null {
  if (!status?.shared) return null;
  const parts = [({ viewer: "View only", pending: "Waiting for owner" } as Record<string, string>)[status.myLevel] ?? "Shared"];
  const others = Math.max(members.length - 1, 0);
  if (others === 0) {
    parts.push(status.isOwner ? "no one has joined" : "connecting");
  } else {
    parts.push(`${others} member${others === 1 ? "" : "s"}`);
    parts.push(status.peersOnline > 0 ? `${status.peersOnline} online` : "none online");
  }
  return parts.join(" · ");
}

function CopyBox({ text, copyValue, sensitive, onError }: { text: string; copyValue?: string; sensitive: boolean; onError: (e: string) => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-start gap-2 rounded-lg bg-field p-2.5">
      <code className="selectable line-clamp-3 min-w-0 flex-1 font-mono text-xs break-all">{text}</code>
      <Button
        disabled={!text}
        onClick={async () => {
          try {
            await api.copyText(copyValue ?? text, sensitive);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
          } catch (e) {
            onError(errorText(e));
          }
        }}
      >
        {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? "Copied" : "Copy"}
      </Button>
    </div>
  );
}

function RelaySection({ projectId, isOwner, onError }: { projectId: string; isOwner: boolean; onError: (e: string) => void }) {
  const [relays, setRelays] = useState<Relay[]>([]);
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [command, setCommand] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const cleaned = code.replace(/\s+/g, "").toLowerCase();

  useEffect(() => {
    let alive = true;
    const load = () => api.listRelays(projectId).then((r) => alive && setRelays(r)).catch(() => {});
    load();
    const t = window.setInterval(load, 3000);
    return () => { alive = false; window.clearInterval(t); };
  }, [projectId]);

  const add = async () => {
    setBusy(true);
    try {
      const link = await api.addRelay(projectId, cleaned, name);
      setCommand(`yasecret relay add '${link}'`);
      setCode("");
      setRelays(await api.listRelays(projectId));
    } catch (e) {
      onError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const canAdd = !busy && cleaned.length === 64;
  // Enter here adds the relay instead of triggering the sheet's Create Invite.
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key !== "Enter") return;
    e.preventDefault();
    e.stopPropagation();
    if (canAdd) add();
  };

  if (!isOwner && relays.length === 0) return null;
  return (
    <div className="mt-5 border-t border-line pt-4">
      <h3 className="mb-1 font-semibold">Always-on peer</h3>
      <p className="mb-2 text-muted">
        Run <code className="font-mono text-xs">yasecret relay</code> on a computer that stays on, so teammates can join and sync while this one is off. It only stores encrypted values.
      </p>
      {relays.map((r) => (
        <div key={r.code} className="flex items-center gap-3 py-1.5">
          <Server size={16} className="text-muted" />
          <div className="min-w-0 flex-1">
            <div className="truncate">{r.name}</div>
            <div className="font-mono text-xs text-muted">{r.code.slice(0, 16)}…</div>
          </div>
          <span className={`flex items-center gap-1.5 text-xs ${r.online ? "text-accent" : "text-muted"}`}>
            <span className={`size-2 rounded-full ${r.online ? "bg-accent" : "bg-line"}`} /> {r.online ? "Online" : "Offline"}
          </span>
          {isOwner && (
            <Button
              onClick={async () => {
                try {
                  await api.removeRelay(projectId, r.code);
                  setRelays(await api.listRelays(projectId));
                } catch (e) {
                  onError(errorText(e));
                }
              }}
            >
              Remove
            </Button>
          )}
        </div>
      ))}
      {isOwner && (
        <div className="mt-2 flex items-center gap-2" onKeyDown={onKey}>
          <div className="min-w-0 flex-1">
            <TextInput mono placeholder="Relay code (yasecret relay code)" value={code} onChange={(e) => setCode(e.target.value)} />
          </div>
          <div className="w-36 shrink-0">
            <TextInput placeholder="Name (optional)" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <Button disabled={!canAdd} onClick={add}>{busy ? "Adding…" : "Add"}</Button>
        </div>
      )}
      {isOwner && relays.length > 0 && (
        <p className="mt-2 text-xs text-muted">A removed peer keeps what it already stored. To cut one off completely, stop sharing and share again.</p>
      )}
      {command && (
        <div className="mt-2 space-y-1.5">
          <p className="text-xs text-muted">Run this on the relay machine:</p>
          <CopyBox text={command} sensitive onError={onError} />
        </div>
      )}
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
  const [pendingRemoval, setPendingRemoval] = useState<Member | null>(null);
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
      width={SHEET.large}
      onEnter={isOwner && !link ? create : onClose}
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
              <CopyBox text={link} sensitive={mode === "link"} onError={setError} />
              <p className="flex items-center gap-1.5 text-xs text-muted"><Radio size={13} /> Keep Yasecret open and unlocked until they've joined, or add an always-on peer below so they can join while this computer is off.</p>
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
                <select
                  value={m.level}
                  aria-label={`Access for ${m.name}`}
                  onChange={(e) => (e.target.value === "removed" ? setPendingRemoval(m) : setLevel(m, e.target.value))}
                  className="h-7 rounded-md border border-line bg-field px-2"
                >
                  <option value="editor">Can edit</option>
                  <option value="viewer">Can view</option>
                  <option value="removed">Remove…</option>
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
      {(shared || isOwner) && <RelaySection projectId={project.id} isOwner={isOwner} onError={setError} />}
      <ErrorLine text={error} />
      {pendingRemoval && (
        <Confirm
          title={`Remove ${pendingRemoval.name}?`}
          message="The project key is replaced and handed to everyone else, so they can't read anything changed afterwards."
          action="Remove"
          onConfirm={() => setLevel(pendingRemoval, "removed")}
          onClose={() => setPendingRemoval(null)}
        />
      )}
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
  const [codeError, setCodeError] = useState<string | null>(null);
  useEffect(() => { api.deviceCode().then(setCode).catch((e) => setCodeError(errorText(e))); }, []);
  const trimmed = link.trim();
  const canJoin = !busy && trimmed.startsWith("yasecret://join");
  const join = async () => {
    if (!canJoin) return;
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
      width={SHEET.medium}
      dismissible={!busy}
      onEnter={join}
      footer={
        <>
          {busy && <span className="mr-auto text-muted">Connecting…</span>}
          <Button onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant="primary" disabled={!canJoin} onClick={join}>Join</Button>
        </>
      }
    >
      <p className="mb-3 text-muted">Paste the invite link you were sent. The person who shared it needs Yasecret open and unlocked while you join, unless the project has an always-on peer.</p>
      <textarea
        value={link}
        disabled={busy}
        onChange={(e) => setLink(e.target.value)}
        rows={3}
        className="w-full resize-none rounded-md border border-line bg-field p-2.5 font-mono text-xs outline-none focus:border-accent"
      />
      <div className="mt-4 rounded-lg border border-line p-3">
        <p className="mb-2">Asked for a device code? Send this to the project owner:</p>
        {code ? (
          <CopyBox text={code.match(/.{1,8}/g)?.join(" ") ?? ""} copyValue={code} sensitive={false} onError={setError} />
        ) : (
          <p className="text-muted">Unavailable — {codeError ?? "unlock the vault first"}</p>
        )}
      </div>
      <ErrorLine text={error} />
    </Modal>
  );
}
