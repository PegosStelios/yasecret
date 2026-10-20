import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Eye, EyeOff, FileUp } from "lucide-react";
import {
  api, errorText, formatDate, plural, relativeTime,
  Activity, DiffRow, Environment, ExportFormat, ImportSummary, Project, Secret, Version,
} from "./api";
import { Button, Confirm, EmptyValue, ErrorLine, IconButton, MASK, Modal, SHEET, Segmented, TextInput, Toggle } from "./ui";

// ── Name prompts ──────────────────────────────────────────────────────────────

export function NameSheet({ title, initial = "", placeholder, action, note, onSubmit, onClose }: {
  title: string;
  initial?: string;
  placeholder?: string;
  action: string;
  note?: string;
  /** Throw to keep the sheet open and show the error in it. */
  onSubmit: (name: string) => Promise<void>;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const trimmed = name.trim();
  const submit = async () => {
    if (!trimmed || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onSubmit(trimmed);
      onClose();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={title}
      onClose={onClose}
      width={SHEET.small}
      onEnter={submit}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!trimmed || busy} onClick={submit}>{action}</Button></>}
    >
      <TextInput autoFocus placeholder={placeholder} value={name} onChange={(e) => setName(e.target.value)} />
      {note && <p className="mt-2 text-xs text-muted">{note}</p>}
      <ErrorLine text={error} />
    </Modal>
  );
}

export function NewProjectSheet({ onCreate, onClose }: { onCreate: (name: string, withDefaults: boolean) => Promise<void>; onClose: () => void }) {
  const [name, setName] = useState("");
  const [withDefaults, setWithDefaults] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const trimmed = name.trim();
  const submit = async () => {
    if (!trimmed || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onCreate(trimmed, withDefaults);
      onClose();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title="New Project"
      onClose={onClose}
      width={SHEET.small}
      onEnter={submit}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!trimmed || busy} onClick={submit}>Create</Button></>}
    >
      <TextInput autoFocus placeholder="Project name" value={name} onChange={(e) => setName(e.target.value)} />
      <div className="mt-4">
        <Toggle checked={withDefaults} onChange={setWithDefaults} label="Add development, staging and production" />
      </div>
      <ErrorLine text={error} />
    </Modal>
  );
}

// ── Variable editor ───────────────────────────────────────────────────────────

const toDateInput = (unix: number) => new Date(unix * 1000).toISOString().slice(0, 10);
const fromDateInput = (s: string) => Math.floor(new Date(`${s}T12:00:00`).getTime() / 1000);

export function VariableEditor({ projectId, envId, secret, prefill, onSaved, onClose }: {
  projectId: string;
  envId: string;
  secret: Secret | null;
  /** For a new variable: start with this key (overriding an inherited variable). */
  prefill?: { key: string; isSecret: boolean };
  onSaved: () => Promise<void>;
  onClose: () => void;
}) {
  const [key, setKey] = useState(secret?.key ?? prefill?.key ?? "");
  const [value, setValue] = useState("");
  const [original, setOriginal] = useState("");
  const [isSecret, setIsSecret] = useState(secret?.isSecret ?? prefill?.isSecret ?? true);
  const [kindTouched, setKindTouched] = useState(!!prefill);
  const [valueType, setValueType] = useState<string | null>(secret?.valueType ?? null);
  const [typeTouched, setTypeTouched] = useState(false);
  const [typeProblem, setTypeProblem] = useState<string | null>(null);
  const [show, setShow] = useState(false);
  const [expires, setExpires] = useState(secret?.expiresAt != null);
  const [expiry, setExpiry] = useState(toDateInput(secret?.expiresAt ?? Date.now() / 1000 + 90 * 86400));
  const [validKey, setValidKey] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (secret) api.getValue(projectId, secret.id, false).then((v) => { setValue(v); setOriginal(v); }).catch((e) => setError(errorText(e)));
  }, [secret, projectId]);
  useEffect(() => {
    if (!key) { setValidKey(true); return; }
    api.isValidKey(key).then(setValidKey);
    if (!secret && !kindTouched) api.looksSecret(key).then(setIsSecret);
    if (!secret && !typeTouched) api.suggestValueType(key).then(setValueType);
  }, [key, secret, kindTouched, typeTouched]);
  useEffect(() => {
    let current = true;
    if (!valueType) setTypeProblem(null);
    else api.valueTypeProblem(valueType, value).then((p) => current && setTypeProblem(p));
    return () => { current = false; };
  }, [valueType, value]);

  const [busy, setBusy] = useState(false);
  const save = async () => {
    if (busy || !key || !validKey || typeProblem) return;
    setBusy(true);
    setError(null);
    // Compare by calendar day: re-saving an unchanged date must not rewrite the expiry.
    const originalDay = secret?.expiresAt != null ? toDateInput(secret.expiresAt) : null;
    const expiryChanged = (expires ? expiry : null) !== originalDay;
    const newExpiry = expires ? (expiryChanged ? fromDateInput(expiry) : secret?.expiresAt ?? fromDateInput(expiry)) : null;
    try {
      const typeChanged = valueType !== (secret?.valueType ?? null);
      if (secret) {
        // Clear the old type first so a new value is checked against the new type only.
        if (typeChanged && secret.valueType) await api.setValueType(projectId, secret.id, null);
        await api.editSecret({
          projectId,
          secretId: secret.id,
          newKey: key === secret.key ? null : key,
          newValue: value === original ? null : value,
          isSecret: isSecret === secret.isSecret ? null : isSecret,
          expiryChanged,
          expiresAt: newExpiry,
        });
        if (typeChanged && valueType) await api.setValueType(projectId, secret.id, valueType);
      } else {
        const created = await api.createSecret({ projectId, envId, key, value, isSecret, expiresAt: newExpiry });
        if (valueType) await api.setValueType(projectId, created.id, valueType);
      }
      await onSaved();
      onClose();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const masked = isSecret && !show;
  return (
    <Modal
      title={secret ? "Edit Variable" : "Add Variable"}
      onClose={onClose}
      width={SHEET.medium}
      onEnter={save}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!key || !validKey || !!typeProblem || busy} onClick={save}>{secret ? "Save" : "Add"}</Button></>}
    >
      <label className="mb-1 block text-xs text-muted">Key</label>
      <TextInput mono autoFocus placeholder="API_KEY" value={key} onChange={(e) => setKey(e.target.value)} />
      {!validKey && <p className="mt-1 text-xs text-danger">Use letters, digits and _ — can't start with a digit or contain spaces</p>}

      <div className="mt-4 mb-1 flex items-center justify-between">
        <label className="text-xs text-muted">Value</label>
        {isSecret && (
          <button type="button" className="text-xs text-accent" onClick={() => setShow(!show)}>{show ? "Hide" : "Show"}</button>
        )}
      </div>
      {masked ? (
        <TextInput mono type="password" value={value} onChange={(e) => setValue(e.target.value)} />
      ) : (
        <textarea
          value={value}
          onChange={(e) => setValue(e.target.value)}
          rows={3}
          className="w-full resize-y rounded-md border border-line bg-field px-2.5 py-1.5 font-mono outline-none focus:border-accent"
        />
      )}

      {typeProblem && <p className="mt-1 text-xs text-danger">This value isn't valid: {typeProblem}</p>}

      <div className="mt-4 space-y-3">
        <div className="flex items-center justify-between gap-3">
          <div>
            <div>Type</div>
            <div className="text-xs text-muted">Values are checked against it whenever they change.</div>
          </div>
          <select
            value={valueType ?? ""}
            aria-label="Type"
            onChange={(e) => { setValueType(e.target.value || null); setTypeTouched(true); }}
            className="h-7 rounded-md border border-line bg-field px-2"
          >
            {[["", "Text"], ["url", "URL"], ["number", "Number"], ["port", "Port"], ["boolean", "Boolean"], ["email", "Email"], ["json", "JSON"]].map(([v, l]) => (
              <option key={v} value={v}>{l}</option>
            ))}
          </select>
        </div>
        <Toggle
          checked={isSecret}
          onChange={(v) => { setIsSecret(v); setKindTouched(true); }}
          label="Secret"
          hint={isSecret ? "Value is masked until you reveal it." : "Plain variable — value is shown in the list."}
        />
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={expires} onChange={(e) => setExpires(e.target.checked)} />
            Expires
          </label>
          {expires && (
            <>
              <input type="date" value={expiry} min={toDateInput(Date.now() / 1000)} onChange={(e) => setExpiry(e.target.value)} className="h-7 rounded-md border border-line bg-field px-2" />
              <span className="text-xs text-muted">You'll get a reminder a week before.</span>
            </>
          )}
        </div>
      </div>
      <ErrorLine text={error} />
    </Modal>
  );
}

// ── Import ────────────────────────────────────────────────────────────────────

type Draft = { key: string; value: string; exists: boolean; include: boolean; isSecret: boolean; valid: boolean };

export function ImportSheet({ projectId, env, onDone, onClose }: {
  projectId: string;
  env: Environment;
  onDone: (s: ImportSummary) => Promise<void>;
  onClose: () => void;
}) {
  const [content, setContent] = useState("");
  const [drafts, setDrafts] = useState<Draft[] | null>(null);
  const [overwrite, setOverwrite] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const chooseFile = async () => {
    try {
      const picked = await api.openTextFile();
      if (picked) setContent(picked[1]);
    } catch (e) {
      setError(errorText(e));
    }
  };

  const preview = async () => {
    setError(null);
    try {
      const rows = await api.previewImport(env.id, content);
      // Later lines win when a file repeats a key, like dotenv loaders.
      const last = new Map(rows.map((r, i) => [r.key, i]));
      const unique = rows.filter((r, i) => last.get(r.key) === i);
      if (!unique.length) { setError("No variables found."); return; }
      const valid = await Promise.all(unique.map((r) => api.isValidKey(r.key)));
      setDrafts(unique.map((r, i) => ({ key: r.key, value: r.value, exists: r.exists, include: valid[i], isSecret: r.suggestedSecret, valid: valid[i] })));
      const bad = unique.filter((_, i) => !valid[i]).map((r) => r.key);
      if (bad.length) setError(`Unchecked invalid names: ${bad.join(", ")}`);
    } catch (e) {
      setError(errorText(e));
    }
  };

  const counted = drafts?.filter((d) => d.include && (!d.exists || overwrite)) ?? [];
  const apply = async () => {
    if (!drafts) return;
    try {
      const sum = await api.applyImport(projectId, env.id, counted.map((d) => ({ key: d.key, value: d.value, isSecret: d.isSecret })), overwrite);
      await onDone({ ...sum, skipped: sum.skipped + (drafts.length - counted.length) });
      onClose();
    } catch (e) {
      setError(errorText(e));
    }
  };
  const update = (i: number, patch: Partial<Draft>) => setDrafts((ds) => ds && ds.map((d, j) => (j === i ? { ...d, ...patch } : d)));

  return (
    <Modal
      title={`Import into “${env.name}”`}
      onClose={onClose}
      width={SHEET.large}
      footer={
        drafts ? (
          <>
            <Button onClick={() => setDrafts(null)} className="mr-auto">Back</Button>
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" disabled={!counted.length} onClick={apply}>Import {plural(counted.length, "Variable")}</Button>
          </>
        ) : (
          <>
            <Button onClick={chooseFile} className="mr-auto"><FileUp size={15} /> Choose File…</Button>
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" disabled={!content.trim()} onClick={preview}>Preview</Button>
          </>
        )
      }
    >
      {!drafts ? (
        <>
          <p className="mb-3 text-muted">Paste a .env or JSON file, drop one here, or choose a file. Nothing is saved until you confirm the preview.</p>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={async (e) => {
              e.preventDefault();
              setDragging(false);
              const file = e.dataTransfer.files[0];
              if (file) setContent(await file.text());
            }}
            placeholder={"DATABASE_URL=postgres://…\nAPI_KEY=sk_live_…"}
            className={`h-64 w-full resize-none rounded-lg border bg-field p-3 font-mono outline-none placeholder:text-faint ${dragging ? "border-accent" : "border-dashed border-line"}`}
          />
        </>
      ) : (
        <>
          <div className="mb-3 flex items-center gap-4">
            <span className="font-medium text-ok">{drafts.filter((d) => !d.exists).length} new</span>
            <span className="font-medium text-warn">{drafts.filter((d) => d.exists).length} already exist</span>
            <span className="font-medium text-muted">{drafts.filter((d) => d.isSecret).length} secret</span>
            <span className="flex-1" />
            {drafts.some((d) => d.exists) && (
              <span className="flex items-center gap-2">
                <span className="text-muted">Existing:</span>
                <Segmented value={overwrite ? "overwrite" : "skip"} onChange={(v) => setOverwrite(v === "overwrite")} options={[{ value: "skip", label: "Skip" }, { value: "overwrite", label: "Overwrite" }]} />
              </span>
            )}
          </div>
          <table className="w-full table-fixed text-left">
            <thead className="text-xs text-muted">
              <tr className="border-b border-line">
                <th className="w-8 py-1" />
                <th className="py-1 font-medium">Key</th>
                <th className="py-1 font-medium">Value</th>
                <th className="w-20 py-1 font-medium">Status</th>
                <th className="w-14 py-1 font-medium">Secret</th>
              </tr>
            </thead>
            <tbody>
              {drafts.map((d, i) => (
                <tr key={d.key} className="h-8 border-b border-line/60">
                  <td><input type="checkbox" disabled={!d.valid} checked={d.include} onChange={(e) => update(i, { include: e.target.checked })} /></td>
                  <td className="truncate pr-2 font-mono">{d.key}</td>
                  <td className={`truncate pr-2 font-mono ${d.isSecret ? "text-muted" : ""}`}>{d.isSecret ? MASK : d.value === "" ? <EmptyValue /> : d.value}</td>
                  <td className={`text-xs font-medium ${d.exists ? "text-warn" : "text-ok"}`}>{d.exists ? (overwrite ? "Overwrite" : "Skip") : "New"}</td>
                  <td><input type="checkbox" checked={d.isSecret} onChange={(e) => update(i, { isSecret: e.target.checked })} /></td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-3 text-xs text-muted">Names containing KEY, TOKEN, SECRET, PASSWORD, PRIVATE, AUTH or CREDENTIAL are marked secret automatically.</p>
        </>
      )}
      <ErrorLine text={error} />
    </Modal>
  );
}

// ── Export ────────────────────────────────────────────────────────────────────

const FORMATS: { value: ExportFormat; label: string; file: string; named?: boolean }[] = [
  { value: "dotenv", label: ".env", file: ".env" },
  { value: "json", label: "JSON", file: "env.json" },
  { value: "docker-compose", label: "Docker Compose", file: "docker-compose.env.yml", named: true },
  { value: "k8s-secret", label: "Kubernetes Secret", file: "secret.yaml", named: true },
  { value: "k8s-configmap", label: "Kubernetes ConfigMap", file: "configmap.yaml", named: true },
  { value: "example", label: ".env.example (keys only)", file: ".env.example" },
];

export function ExportSheet({ project, env, secrets, onSaved, onClose }: {
  project: Project;
  env: Environment;
  secrets: Secret[];
  onSaved: (file: string) => void;
  onClose: () => void;
}) {
  const [format, setFormat] = useState<ExportFormat>("dotenv");
  const [includeSecrets, setIncludeSecrets] = useState(true);
  const [selected, setSelected] = useState<Set<string>>(new Set(secrets.map((s) => s.key)));
  const [name, setName] = useState(project.name);
  const [preview, setPreview] = useState("");
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const meta = FORMATS.find((f) => f.value === format)!;
  const withValues = includeSecrets && format !== "example";

  useEffect(() => {
    if (!selected.size) { setPreview(""); return; }
    // An older response must never replace a newer one: Save writes whatever is previewed.
    let current = true;
    setPreview("");
    api.exportVariables({ projectId: project.id, envId: env.id, format, keys: [...selected], includeSecretValues: withValues, name: name || project.name })
      .then((p) => { if (current) { setPreview(p); setError(null); } })
      .catch((e) => { if (current) setError(errorText(e)); });
    return () => { current = false; };
  }, [format, withValues, selected, name, project, env]);

  const saveFile = async () => {
    try {
      const saved = await api.saveTextFile(meta.file, preview);
      if (!saved) return;
      onSaved(saved);
      onClose();
    } catch (e) {
      setError(errorText(e));
    }
  };

  const hasSecretValues = withValues && secrets.some((s) => s.isSecret && selected.has(s.key));
  return (
    <Modal
      title={`Export “${env.name}”`}
      onClose={onClose}
      width={SHEET.wide}
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          <Button
            disabled={!preview}
            onClick={async () => {
              try {
                await api.copyText(preview, withValues);
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              } catch (e) {
                setError(errorText(e));
              }
            }}
          >
            {copied ? "Copied" : "Copy"}
          </Button>
          <Button variant="primary" disabled={!preview} onClick={saveFile}>Save…</Button>
        </>
      }
    >
      <div className="flex gap-5">
        <div className="w-64 shrink-0 space-y-3">
          <label className="block">
            <span className="mb-1 block text-xs text-muted">Format</span>
            <select value={format} onChange={(e) => setFormat(e.target.value as ExportFormat)} className="h-8 w-full rounded-md border border-line bg-field px-2">
              {FORMATS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
            </select>
          </label>
          {meta.named && <TextInput placeholder={format === "docker-compose" ? "Service name" : "Resource name"} value={name} onChange={(e) => setName(e.target.value)} />}
          {format !== "example" && <Toggle checked={includeSecrets} onChange={setIncludeSecrets} label="Include secret values" />}
          <div className="flex items-center justify-between pt-1">
            <span className="font-medium">Variables</span>
            <button type="button" className="text-xs text-accent" onClick={() => setSelected(selected.size === secrets.length ? new Set() : new Set(secrets.map((s) => s.key)))}>
              {selected.size === secrets.length ? "None" : "All"}
            </button>
          </div>
          <div className="max-h-60 overflow-auto rounded-md border border-line p-1">
            {secrets.map((s) => (
              <label key={s.id} className="flex items-center gap-2 rounded px-1.5 py-1 hover:bg-raised/50">
                <input type="checkbox" checked={selected.has(s.key)} onChange={(e) => setSelected((sel) => { const n = new Set(sel); e.target.checked ? n.add(s.key) : n.delete(s.key); return n; })} />
                <span className="truncate font-mono text-xs">{s.key}</span>
              </label>
            ))}
          </div>
        </div>
        <div className="flex min-w-0 flex-1 flex-col">
          <span className="mb-1 text-xs text-muted">Preview</span>
          <pre className="selectable h-80 overflow-auto rounded-md border border-line bg-field p-3 font-mono text-xs whitespace-pre-wrap">{preview || "Nothing selected"}</pre>
          {hasSecretValues && (
            <p className="mt-2 flex items-center gap-1.5 text-xs text-warn"><AlertTriangle size={13} /> Contains secret values in plain text. Don't commit this file.</p>
          )}
        </div>
      </div>
      <ErrorLine text={error} />
    </Modal>
  );
}

// ── History ───────────────────────────────────────────────────────────────────

export function HistorySheet({ projectId, secret, readOnly, onRestored, onClose }: {
  projectId: string;
  secret: Secret;
  readOnly: boolean;
  onRestored: () => void;
  onClose: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [currentAt, setCurrentAt] = useState(secret.updatedAt);
  const [versions, setVersions] = useState<Version[]>([]);
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [pendingRestore, setPendingRestore] = useState<Version | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = () =>
    Promise.all([api.getValue(projectId, secret.id, false), api.listVersions(projectId, secret.id), api.listSecrets(secret.envId)])
      .then(([c, v, list]) => {
        setCurrent(c);
        setVersions(v);
        setCurrentAt(list.find((x) => x.id === secret.id)?.updatedAt ?? secret.updatedAt);
      })
      .catch((e) => setError(errorText(e)));
  useEffect(() => { load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const show = (id: string) => !secret.isSecret || revealed.has(id);
  const toggle = (id: string) => {
    setRevealed((r) => { const n = new Set(r); n.has(id) ? n.delete(id) : n.add(id); return n; });
    if (!revealed.has(id)) api.getValue(projectId, secret.id, true).catch(() => {});
  };
  const restore = async (v: Version) => {
    try {
      await api.restoreVersion(projectId, secret.id, v.id);
      onRestored();
      await load();
    } catch (e) {
      setError(errorText(e));
    }
  };
  const row = (id: string, value: string, caption: string, version?: Version) => (
    <div key={id} className="flex items-center gap-2 border-b border-line/60 py-2">
      <div className="min-w-0 flex-1">
        <div className="selectable truncate font-mono">{!show(id) ? MASK : value === "" ? <EmptyValue /> : value}</div>
        <div className="text-xs text-muted">{caption}</div>
      </div>
      {secret.isSecret && <IconButton title={show(id) ? "Hide value" : "Reveal value"} onClick={() => toggle(id)}>{show(id) ? <EyeOff size={15} /> : <Eye size={15} />}</IconButton>}
      {version && !readOnly && <Button onClick={() => setPendingRestore(version)}>Restore…</Button>}
    </div>
  );
  return (
    <Modal title="History" subtitle={secret.key} onClose={onClose} width={SHEET.medium} onEnter={onClose} footer={<Button variant="primary" onClick={onClose}>Done</Button>}>
      <p className="mb-1 text-xs font-semibold text-muted uppercase">Current</p>
      {row("current", current, `Set ${formatDate(currentAt)}`)}
      <p className="mt-4 mb-1 text-xs font-semibold text-muted uppercase">{versions.length ? "Earlier values" : "No earlier values"}</p>
      {versions.map((v) => row(v.id, v.value, `Replaced ${formatDate(v.changedAt)} by ${v.byMe ? "you" : "a teammate"}${v.note ? ` · ${v.note}` : ""}`, v))}
      <ErrorLine text={error} />
      {pendingRestore && (
        <Confirm
          title="Restore this value?"
          message="The current value is kept in history, so you can undo this."
          action="Restore"
          onConfirm={() => restore(pendingRestore)}
          onClose={() => setPendingRestore(null)}
        />
      )}
    </Modal>
  );
}

// ── Activity ──────────────────────────────────────────────────────────────────

const ACTIONS: Record<string, string> = {
  created_secret: "Added",
  updated_secret: "Changed value",
  deleted_secret: "Deleted",
  renamed_secret: "Renamed",
  changed_kind: "Changed type",
  changed_expiry: "Changed expiry",
  revealed_secret: "Revealed",
  synced_secret: "Synced change",
};

export function ActivitySheet({ project, onClose }: { project: Project; onClose: () => void }) {
  const [entries, setEntries] = useState<Activity[]>([]);
  const [filter, setFilter] = useState("");
  const [loadError, setLoadError] = useState<string | null>(null);
  useEffect(() => { api.listActivity(project.id).then(setEntries).catch((e) => setLoadError(errorText(e))); }, [project.id]);
  const shown = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return q ? entries.filter((a) => a.targetLabel.toLowerCase().includes(q) || (ACTIONS[a.action] ?? a.action).toLowerCase().includes(q)) : entries;
  }, [entries, filter]);
  return (
    <Modal title="Activity" onClose={onClose} width={SHEET.wide} footer={<Button variant="primary" onClick={onClose}>Done</Button>}>
      <div className="mb-3 flex items-center justify-between">
        <p className="text-muted">{project.name} · kept on this computer only</p>
        <div className="w-52"><TextInput placeholder="Filter" value={filter} onChange={(e) => setFilter(e.target.value)} /></div>
      </div>
      {loadError ? (
        <p className="py-10 text-center text-danger">Couldn't load activity: {loadError}</p>
      ) : shown.length === 0 ? (
        <p className="py-10 text-center text-muted">{entries.length ? `No results for “${filter}”` : "No activity yet"}</p>
      ) : (
        <table className="w-full table-fixed text-left">
          <thead className="text-xs text-muted">
            <tr className="border-b border-line"><th className="w-44 py-1 font-medium">When</th><th className="w-36 py-1 font-medium">What</th><th className="py-1 font-medium">Variable</th><th className="w-36 py-1 font-medium">Who</th></tr>
          </thead>
          <tbody>
            {shown.map((a) => (
              <tr key={a.id} className="h-8 border-b border-line/60">
                <td className="text-muted" title={formatDate(a.timestamp)}>{relativeTime(a.timestamp)}</td>
                <td>{ACTIONS[a.action] ?? a.action}</td>
                <td className="truncate font-mono" title={a.targetLabel}>{a.targetLabel}</td>
                <td className="text-muted">{a.device ?? (a.fromSync ? "Teammate (synced)" : a.byMe ? "You" : "Teammate")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Modal>
  );
}

// ── Compare ───────────────────────────────────────────────────────────────────

const STATUS: Record<DiffRow["status"], { label: string; cls: string }> = {
  same: { label: "Same", cls: "text-muted" },
  different: { label: "Different", cls: "text-warn" },
  only_left: { label: "Missing →", cls: "text-accent" },
  only_right: { label: "← Missing", cls: "text-violet" },
};

export function CompareSheet({ projectId, left, right, onClose }: { projectId: string; left: Environment; right: Environment; onClose: () => void }) {
  const [rows, setRows] = useState<DiffRow[]>([]);
  const [diffOnly, setDiffOnly] = useState(true);
  const [showSecrets, setShowSecrets] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { api.compareEnvironments(projectId, left.id, right.id).then(setRows).catch((e) => setError(errorText(e))); }, [projectId, left.id, right.id]);
  const shown = diffOnly ? rows.filter((r) => r.status !== "same") : rows;
  const count = (s: DiffRow["status"]) => rows.filter((r) => r.status === s).length;
  const cell = (v: string | null, secret: boolean) =>
    v === null ? (
      <span className="text-faint">—</span>
    ) : (
      <span className={`truncate font-mono ${secret && !showSecrets ? "text-muted" : ""}`}>
        {secret && !showSecrets ? MASK : v === "" ? <EmptyValue /> : v}
      </span>
    );
  return (
    <Modal title={`${left.name}  ↔  ${right.name}`} onClose={onClose} width={SHEET.wide} footer={<Button variant="primary" onClick={onClose}>Done</Button>}>
      <div className="mb-3 flex items-center gap-4">
        <span className="text-warn">{count("different")} different</span>
        <span className="text-accent">{count("only_left")} only in {left.name}</span>
        <span className="text-violet">{count("only_right")} only in {right.name}</span>
        <span className="text-muted">{count("same")} same</span>
        <span className="flex-1" />
        <label className="flex items-center gap-1.5"><input type="checkbox" checked={diffOnly} onChange={(e) => setDiffOnly(e.target.checked)} /> Differences only</label>
        <label className="flex items-center gap-1.5"><input type="checkbox" checked={showSecrets} onChange={(e) => setShowSecrets(e.target.checked)} /> Show secret values</label>
      </div>
      {shown.length === 0 ? (
        <p className="py-10 text-center text-muted">{rows.length ? "No differences" : "Both environments are empty"}</p>
      ) : (
        <table className="w-full table-fixed text-left">
          <thead className="text-xs text-muted">
            <tr className="border-b border-line"><th className="w-56 py-1 font-medium">Key</th><th className="py-1 font-medium">{left.name}</th><th className="py-1 font-medium">{right.name}</th><th className="w-24 py-1 font-medium" /></tr>
          </thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.key} className="h-8 border-b border-line/60">
                <td className="truncate pr-2 font-mono">{r.key}</td>
                <td className="truncate pr-2">{cell(r.leftValue, r.leftIsSecret)}</td>
                <td className="truncate pr-2">{cell(r.rightValue, r.rightIsSecret)}</td>
                <td className={`text-xs font-medium ${STATUS[r.status].cls}`}>{STATUS[r.status].label}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <ErrorLine text={error} />
    </Modal>
  );
}
