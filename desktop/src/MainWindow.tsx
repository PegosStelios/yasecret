import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Copy, Check, Eye, EyeOff, Folder, Users, Plus, UserPlus, Lock, KeyRound, Search, X,
  Download, Upload, History, Share2, Hammer, FlaskConical, ShieldCheck, Layers, Type, Trash2,
} from "lucide-react";
import { api, errorText, plural, relativeTime, Environment, Project, Secret, SyncStatus, Member } from "./api";
import { Button, ColumnFooter, ColumnHeader, Confirm, ContextMenu, EmptyState, FooterButton, IconButton, MenuItem } from "./ui";
import { ActivitySheet, CompareSheet, ExportSheet, HistorySheet, ImportSheet, NameSheet, NewProjectSheet, VariableEditor } from "./sheets";
import { JoinSheet, ShareSheet, sharingSummary } from "./sharing";
import { VaultSheet } from "./vault";

type Sheet =
  | { kind: "newProject" }
  | { kind: "renameProject"; project: Project }
  | { kind: "newEnv" }
  | { kind: "renameEnv"; env: Environment }
  | { kind: "cloneEnv"; env: Environment }
  | { kind: "editor"; secret: Secret | null }
  | { kind: "import" }
  | { kind: "export" }
  | { kind: "history"; secret: Secret }
  | { kind: "activity" }
  | { kind: "compare"; left: Environment; right: Environment }
  | { kind: "share" }
  | { kind: "join"; link: string }
  | { kind: "vault" }
  | { kind: "confirm"; title: string; message: string; action: string; onConfirm: () => void };

type Menu = { at: { x: number; y: number }; items: MenuItem[] };

const isMac = navigator.platform.toLowerCase().includes("mac");

export default function Main({ onLock, joinLink, onJoinLinkHandled }: { onLock: () => void; joinLink: string | null; onJoinLinkHandled: () => void }) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [sharedIds, setSharedIds] = useState<string[]>([]);
  const [projectId, setProjectId] = useState<string | null>(null);
  const [envs, setEnvs] = useState<Environment[]>([]);
  const [envId, setEnvId] = useState<string | null>(null);
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [plainValues, setPlainValues] = useState<Record<string, string>>({});
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [selection, setSelection] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<SyncStatus | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [sheet, setSheet] = useState<Sheet | null>(null);
  const [menu, setMenu] = useState<Menu | null>(null);
  const [banner, setBanner] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  // Responses for a project or environment the user already left must not land in the UI.
  const currentProject = useRef<string | null>(null);
  currentProject.current = projectId;
  const currentEnv = useRef<string | null>(null);
  currentEnv.current = envId;
  // updatedAt of each revealed variable, so a changed value is re-hidden instead of shown stale.
  const revealedAt = useRef<Record<string, number>>({});

  const project = projects.find((p) => p.id === projectId) ?? null;
  const env = envs.find((e) => e.id === envId) ?? null;
  // Right after a project switch the previous environment id lingers for one render;
  // only load variables for an environment that belongs to the current project.
  const envProject = env?.projectId ?? null;
  const shared = status?.shared ?? (projectId ? sharedIds.includes(projectId) : false);
  // Until a shared project's access level has loaded, treat it as read-only.
  const readOnly = shared && !["owner", "editor"].includes(status?.myLevel ?? "");

  const run = useCallback(async <T,>(p: Promise<T>): Promise<T | undefined> => {
    try {
      return await p;
    } catch (e) {
      setError(errorText(e));
      return undefined;
    }
  }, []);

  const loadProjects = useCallback(async () => {
    const [list, ids] = await Promise.all([api.listProjects(), api.sharedProjectIds()]);
    setProjects(list);
    setSharedIds(ids);
    setProjectId((cur) => (cur && list.some((p) => p.id === cur) ? cur : list[0]?.id ?? null));
  }, []);

  const loadEnvs = useCallback(async (pid: string) => {
    const list = await api.listEnvironments(pid);
    if (currentProject.current !== pid) return;
    setEnvs(list);
    setEnvId((cur) => (cur && list.some((e) => e.id === cur) ? cur : list[0]?.id ?? null));
  }, []);

  const loadSecrets = useCallback(async (pid: string, eid: string) => {
    const stale = () => currentProject.current !== pid || currentEnv.current !== eid;
    const list = await api.listSecrets(eid);
    if (stale()) return;
    const plain: Record<string, string> = {};
    await Promise.all(list.filter((s) => !s.isSecret).map(async (s) => { plain[s.id] = await api.getValue(pid, s.id, false); }));
    if (stale()) return;
    setSecrets(list);
    setPlainValues(plain);
    const stamps = new Map(list.filter((s) => s.isSecret).map((s) => [s.id, s.updatedAt]));
    setRevealed((r) => Object.fromEntries(Object.entries(r).filter(([id]) => stamps.get(id) !== undefined && stamps.get(id) === revealedAt.current[id])));
    setSelection((sel) => new Set([...sel].filter((id) => list.some((s) => s.id === id))));
  }, []);

  const loadSharing = useCallback(async (pid: string) => {
    const [st, ids] = await Promise.all([api.syncStatus(pid), api.sharedProjectIds()]);
    const list = st.shared ? await api.listMembers(pid) : [];
    setSharedIds(ids);
    if (currentProject.current !== pid) return;
    setStatus(st);
    setMembers(list);
  }, []);

  const reloadAll = useCallback(async () => {
    await run(loadProjects());
    if (projectId) await run(Promise.all([loadEnvs(projectId), loadSharing(projectId)]));
    if (projectId && envId && envProject === projectId) await run(loadSecrets(projectId, envId));
  }, [run, loadProjects, loadEnvs, loadSharing, loadSecrets, projectId, envId, envProject]);

  useEffect(() => { run(loadProjects()); }, [run, loadProjects]);
  useEffect(() => {
    setEnvs([]);
    setEnvId(null);
    setStatus(null);
    if (projectId) run(Promise.all([loadEnvs(projectId), loadSharing(projectId)]));
  }, [projectId, run, loadEnvs, loadSharing]);
  useEffect(() => {
    setSecrets([]);
    setSearch("");
    setSelection(new Set());
    setRevealed({});
    if (projectId && envId && envProject === projectId) run(loadSecrets(projectId, envId));
  }, [envId, envProject, projectId, run, loadSecrets]);

  // Other devices' changes: reload when the sync revision moves; refresh sharing status periodically.
  const reloadRef = useRef(reloadAll);
  reloadRef.current = reloadAll;
  useEffect(() => {
    let last = -1;
    const t = window.setInterval(async () => {
      const rev = await api.syncRevision().catch(() => last);
      if (last !== -1 && rev !== last) reloadRef.current();
      last = rev;
    }, 1500);
    return () => window.clearInterval(t);
  }, []);
  useEffect(() => {
    if (!projectId) return;
    const t = window.setInterval(() => loadSharing(projectId).catch(() => {}), 5000);
    return () => window.clearInterval(t);
  }, [projectId, loadSharing]);

  // A yasecret:// link waits until the current dialog closes, so nothing in progress is lost.
  useEffect(() => {
    if (joinLink && !sheet) {
      setSheet({ kind: "join", link: joinLink });
      onJoinLinkHandled();
    }
  }, [joinLink, sheet, onJoinLinkHandled]);

  // Expiry reminders, at most once a day per variable.
  useEffect(() => {
    api.expiringVariables(7).then(async (items) => {
      const today = new Date().toDateString();
      const fresh = items.filter((i) => {
        try { return localStorage.getItem(`expiry-reminded-${i.id}`) !== today; } catch { return true; }
      });
      if (!fresh.length) return;
      fresh.forEach((i) => { try { localStorage.setItem(`expiry-reminded-${i.id}`, today); } catch { /* reminders just repeat */ } });
      const { isPermissionGranted, requestPermission, sendNotification } = await import("@tauri-apps/plugin-notification");
      if (!(await isPermissionGranted()) && (await requestPermission()) !== "granted") return;
      const names = fresh.slice(0, 3).map((i) => i.label).join(", ") + (fresh.length > 3 ? ` and ${fresh.length - 3} more` : "");
      sendNotification({
        title: fresh.some((i) => i.expired) ? "Variables have expired" : "Variables expire soon",
        body: `${names}. Rotate them in Yasecret.`,
      });
    }).catch(() => {});
  }, []);

  const showBanner = (text: string) => {
    setBanner(text);
    window.setTimeout(() => setBanner((b) => (b === text ? null : b)), 4000);
  };

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return q ? secrets.filter((s) => s.key.toLowerCase().includes(q)) : secrets;
  }, [secrets, search]);

  // ── Variable actions ──────────────────────────────────────────────────────
  const toggleReveal = async (s: Secret) => {
    if (!project) return;
    if (revealed[s.id] !== undefined) {
      setRevealed(({ [s.id]: _, ...rest }) => rest);
    } else {
      const v = await run(api.getValue(project.id, s.id, true));
      if (v !== undefined) {
        revealedAt.current[s.id] = s.updatedAt;
        setRevealed((r) => ({ ...r, [s.id]: v }));
      }
    }
  };
  const openRowMenu = (s: Secret, x: number, y: number) => {
    const ids = selection.has(s.id) ? [...selection] : [s.id];
    if (!selection.has(s.id)) setSelection(new Set([s.id]));
    const single: MenuItem[] = ids.length === 1 ? [
      ...(readOnly ? [] : [{ label: "Edit…", onClick: () => setSheet({ kind: "editor", secret: s }) }]),
      { label: "Copy Value", onClick: () => copyValue(s) },
      { label: "Copy Key", onClick: () => run(api.copyText(s.key, false)) },
      { label: "History…", onClick: () => setSheet({ kind: "history", secret: s }) },
      ...(s.isSecret ? [{ label: revealed[s.id] !== undefined ? "Hide Value" : "Reveal Value", onClick: () => toggleReveal(s) }] : []),
      ...(readOnly ? [] : [{ label: s.isSecret ? "Mark as Plain" : "Mark as Secret", onClick: () => toggleKind(s) }]),
    ] : [];
    const del: MenuItem[] = readOnly ? [] : [{ label: ids.length > 1 ? `Delete ${ids.length} Variables…` : "Delete…", danger: true, onClick: () => askDelete(ids) }];
    setMenu({ at: { x, y }, items: [...single, ...(single.length && del.length ? (["divider"] as MenuItem[]) : []), ...del] });
  };
  const copyValue = async (s: Secret) => {
    if (!project) return;
    const v = revealed[s.id] ?? plainValues[s.id] ?? (await run(api.getValue(project.id, s.id, s.isSecret)));
    if (v === undefined) return;
    await run(api.copyText(v, s.isSecret));
    setCopiedId(s.id);
    window.setTimeout(() => setCopiedId((c) => (c === s.id ? null : c)), 1500);
  };
  const askDelete = (ids: string[]) => {
    const keys = secrets.filter((s) => ids.includes(s.id)).map((s) => s.key);
    setSheet({
      kind: "confirm",
      title: keys.length === 1 ? `Delete “${keys[0]}”?` : `Delete ${keys.length} variables?`,
      message: `${keys.length === 1 ? "It's" : "They're"} removed from ${env?.name}. Earlier values stay in history. This can't be undone.`,
      action: keys.length === 1 ? "Delete Variable" : "Delete Variables",
      onConfirm: async () => {
        await run(api.deleteSecrets(ids));
        if (project && env) {
          await run(loadSecrets(project.id, env.id));
          await run(loadEnvs(project.id));
        }
      },
    });
  };
  const toggleKind = async (s: Secret) => {
    if (!project || !env) return;
    await run(api.editSecret({ projectId: project.id, secretId: s.id, newKey: null, newValue: null, isSecret: !s.isSecret, expiryChanged: false, expiresAt: null }));
    await run(loadSecrets(project.id, env.id));
  };

  // ── Shortcuts ────────────────────────────────────────────────────────────
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = isMac ? e.metaKey : e.ctrlKey;
      // Locking always works, even with a dialog or menu open.
      if (mod && e.shiftKey && e.key.toLowerCase() === "l") { e.preventDefault(); onLock(); return; }
      if (sheet || menu) return;
      const target = e.target as HTMLElement | null;
      const typing = !!target && (["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName) || target.isContentEditable);
      if (!mod) {
        if (typing) return;
        const ordered = filtered;
        const idx = ordered.findIndex((s) => selection.has(s.id));
        if ((e.key === "Delete" || e.key === "Backspace") && selection.size && !readOnly) { e.preventDefault(); askDelete([...selection]); }
        else if ((e.key === "ArrowDown" || e.key === "ArrowUp") && ordered.length) {
          e.preventDefault();
          const next = ordered[Math.min(Math.max(idx + (e.key === "ArrowDown" ? 1 : -1), 0), ordered.length - 1)];
          setSelection(new Set([next.id]));
          document.querySelector<HTMLElement>(`[data-row="${next.id}"]`)?.focus();
        } else if (e.key === "Enter" && idx >= 0 && !readOnly) { e.preventDefault(); setSheet({ kind: "editor", secret: ordered[idx] }); }
        else if ((e.key === "ContextMenu" || (e.shiftKey && e.key === "F10")) && idx >= 0) {
          e.preventDefault();
          const r = document.querySelector(`[data-row="${ordered[idx].id}"]`)?.getBoundingClientRect();
          openRowMenu(ordered[idx], r ? r.left + 40 : 200, r ? r.bottom : 200);
        }
        return;
      }
      const k = e.key.toLowerCase();
      if (k === "f") { e.preventDefault(); searchRef.current?.focus(); }
      if (k === "n" && e.shiftKey) { e.preventDefault(); setSheet({ kind: "newProject" }); return; }
      if (!env) return;
      if (k === "n" && !readOnly) { e.preventDefault(); setSheet({ kind: "editor", secret: null }); }
      if (k === "i" && !readOnly) { e.preventDefault(); setSheet({ kind: "import" }); }
      if (k === "e" && secrets.length) { e.preventDefault(); setSheet({ kind: "export" }); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const modKey = isMac ? "⌘" : "Ctrl+";

  // ── Render ───────────────────────────────────────────────────────────────
  return (
    <div className="flex h-full">
      {/* Projects */}
      <aside className="flex w-56 shrink-0 flex-col bg-sidebar">
        <div className="h-14 px-4 pt-6 text-xs font-semibold tracking-wide text-faint uppercase">Projects</div>
        <div className="flex-1 overflow-auto px-2">
          {projects.length === 0 ? (
            <EmptyState icon={<Folder size={32} />} title="No projects" text="A project holds the environments and variables for one app.">
              <Button variant="primary" onClick={() => setSheet({ kind: "newProject" })}>New Project</Button>
              <Button onClick={() => setSheet({ kind: "join", link: "" })}>Join Shared Project</Button>
            </EmptyState>
          ) : (
            projects.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => setProjectId(p.id)}
                onContextMenu={(e) => {
                  e.preventDefault();
                  setMenu({
                    at: { x: e.clientX, y: e.clientY },
                    items: [
                      { label: "Rename…", onClick: () => setSheet({ kind: "renameProject", project: p }) },
                      "divider",
                      {
                        label: "Delete…",
                        danger: true,
                        onClick: () =>
                          setSheet({
                            kind: "confirm",
                            title: `Delete “${p.name}”?`,
                            message: sharedIds.includes(p.id)
                              ? "This project is shared. Deleting it here stops syncing it and removes it from this computer. This can't be undone."
                              : "All of its environments and variables are deleted too. This can't be undone.",
                            action: "Delete Project",
                            onConfirm: async () => { await run(api.deleteProject(p.id)); await run(loadProjects()); },
                          }),
                      },
                    ],
                  });
                }}
                aria-current={p.id === projectId ? "true" : undefined}
                className={`mb-0.5 flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-[14px] ${p.id === projectId ? "bg-raised" : "hover:bg-raised/50"}`}
              >
                {sharedIds.includes(p.id) ? <Users size={16} className="shrink-0 text-accent" /> : <Folder size={16} className="shrink-0 text-accent" />}
                <span className="truncate">{p.name}</span>
              </button>
            ))
          )}
        </div>
        <ColumnFooter>
          <FooterButton title="New project" onClick={() => setSheet({ kind: "newProject" })}><Plus size={15} /> New</FooterButton>
          <FooterButton title="Join a project someone shared with you" onClick={() => setSheet({ kind: "join", link: "" })}><UserPlus size={15} /> Join</FooterButton>
          <span className="flex-1" />
          <IconButton title="Vault: password, recovery key, backup" onClick={() => setSheet({ kind: "vault" })}><KeyRound size={15} /></IconButton>
          <IconButton title={`Lock vault (${modKey}Shift+L)`} onClick={onLock}><Lock size={15} /></IconButton>
        </ColumnFooter>
      </aside>

      {/* Environments */}
      <section className="flex w-60 shrink-0 flex-col border-x border-line bg-panel">
        {project ? (
          <>
            <ColumnHeader title={project.name} subtitle={plural(envs.length, "environment")} />
            <div className="px-4 pt-2.5 pb-2.5" title={status?.lastError ?? (shared ? "Devices sync directly whenever both are open and unlocked" : "Use Share to sync this project")}>
              <div className="flex h-7 items-center gap-2 rounded-md bg-field px-2 text-muted">
                <span className={`size-1.5 rounded-full ${shared ? ((status?.peersOnline ?? 0) > 0 ? "bg-ok" : "bg-warn") : "bg-faint"}`} />
                <span className="truncate">{sharingSummary(status, members) ?? "Not shared"}</span>
              </div>
            </div>
            <div className="flex-1 overflow-auto border-t border-line px-2 pt-2">
              {envs.length === 0 ? (
                <EmptyState icon={<Layers size={30} />} title="No environments" text="Environments keep separate values for development, staging and production.">
                  {!readOnly && (
                    <>
                      <Button
                        variant="primary"
                        onClick={async () => {
                          for (const name of ["development", "staging", "production"]) await run(api.createEnvironment(project.id, name));
                          await run(loadEnvs(project.id));
                        }}
                      >
                        Add Defaults
                      </Button>
                      <Button onClick={() => setSheet({ kind: "newEnv" })}>New Environment</Button>
                    </>
                  )}
                </EmptyState>
              ) : (
                envs.map((e) => (
                  <button
                    key={e.id}
                    type="button"
                    onClick={() => setEnvId(e.id)}
                    onContextMenu={(ev) => {
                      ev.preventDefault();
                      const others = envs.filter((o) => o.id !== e.id);
                      setMenu({
                        at: { x: ev.clientX, y: ev.clientY },
                        items: [
                          ...others.map((o) => ({ label: `Compare with ${o.name}`, onClick: () => setSheet({ kind: "compare", left: e, right: o }) })),
                          ...(others.length && !readOnly ? (["divider"] as MenuItem[]) : []),
                          ...(readOnly
                            ? []
                            : ([
                                { label: "Rename…", onClick: () => setSheet({ kind: "renameEnv", env: e }) },
                                { label: "Clone…", onClick: () => setSheet({ kind: "cloneEnv", env: e }) },
                                "divider",
                                {
                                  label: "Delete…",
                                  danger: true,
                                  onClick: () =>
                                    setSheet({
                                      kind: "confirm",
                                      title: `Delete “${e.name}”?`,
                                      message: `Its ${plural(e.secretCount, "variable")} are deleted too. This can't be undone.`,
                                      action: "Delete Environment",
                                      onConfirm: async () => { await run(api.deleteEnvironment(e.id)); await run(loadEnvs(project.id)); },
                                    }),
                                },
                              ] as MenuItem[])),
                        ],
                      });
                    }}
                    aria-current={e.id === envId ? "true" : undefined}
                    className={`mb-0.5 flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-[14px] ${e.id === envId ? "bg-accent text-white" : "hover:bg-raised/50"}`}
                  >
                    <EnvIcon name={e.name} active={e.id === envId} />
                    <span className="flex-1 truncate">{e.name}</span>
                    <span className={`text-xs tabular-nums ${e.id === envId ? "text-white/80" : "text-muted"}`}>{e.secretCount}</span>
                  </button>
                ))
              )}
            </div>
            <ColumnFooter>
              {!readOnly && <FooterButton title="New environment" onClick={() => setSheet({ kind: "newEnv" })}><Plus size={15} /> New</FooterButton>}
              <span className="flex-1" />
              <IconButton title="Activity" onClick={() => setSheet({ kind: "activity" })}><History size={15} /></IconButton>
              <FooterButton title="Share this project with teammates" onClick={() => setSheet({ kind: "share" })}><Share2 size={15} /> Share</FooterButton>
            </ColumnFooter>
          </>
        ) : (
          <EmptyState icon={<Folder size={30} />} title="Select a project" text="Pick a project on the left, or create one." />
        )}
      </section>

      {/* Variables */}
      <main className="flex min-w-0 flex-1 flex-col bg-panel">
        {project && env ? (
          <>
            <ColumnHeader
              title={env.name}
              subtitle={secrets.length ? `${plural(secrets.length, "variable")} · ${secrets.filter((s) => s.isSecret).length} secret · ${secrets.filter((s) => !s.isSecret).length} plain` : "No variables yet"}
              trailing={
                <div className="flex shrink-0 items-center gap-2">
                  {readOnly ? (
                    <span className="flex items-center gap-1.5 text-muted"><Eye size={15} /> View only</span>
                  ) : (
                    <Button onClick={() => setSheet({ kind: "import" })} title={`Import a .env or JSON file (${modKey}I)`}><Download size={15} /> Import</Button>
                  )}
                  <Button onClick={() => setSheet({ kind: "export" })} disabled={!secrets.length} title={`Export (${modKey}E)`}><Upload size={15} /> Export</Button>
                  {!readOnly && <Button variant="primary" onClick={() => setSheet({ kind: "editor", secret: null })} title={`Add variable (${modKey}N)`}><Plus size={15} /> Add Variable</Button>}
                </div>
              }
            />
            <div className="px-4 pt-2.5 pb-2.5">
              <div className="flex h-7 items-center gap-2 rounded-md bg-field px-2">
                <Search size={14} className="text-muted" />
                <input
                  ref={searchRef}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder={`Search variables  ${modKey}F`}
                  className="flex-1 bg-transparent outline-none placeholder:text-muted"
                />
                {search && <IconButton title="Clear search" onClick={() => setSearch("")}><X size={13} /></IconButton>}
              </div>
            </div>
            {banner && <div className="border-t border-line bg-ok/15 px-4 py-1.5">{banner}</div>}
            <div className="min-h-0 flex-1 overflow-auto border-t border-line">
              {secrets.length === 0 ? (
                <EmptyState icon={<KeyRound size={34} />} title={`No variables in ${env.name}`} text="Add variables one by one, or import an existing .env or JSON file.">
                  {!readOnly && (
                    <>
                      <Button variant="primary" onClick={() => setSheet({ kind: "editor", secret: null })}>Add Variable</Button>
                      <Button onClick={() => setSheet({ kind: "import" })}>Import</Button>
                    </>
                  )}
                </EmptyState>
              ) : filtered.length === 0 ? (
                <EmptyState icon={<Search size={30} />} title={`No results for “${search}”`} text="Check the spelling or try a different search." />
              ) : (
                <table className="w-full table-fixed border-collapse">
                  <thead className="sticky top-0 bg-panel text-left text-[13px] font-medium">
                    <tr className="border-b border-line">
                      <th className="w-[38%] py-1.5 pl-4 font-medium">Key</th>
                      <th className="py-1.5 pl-2 font-medium">Value</th>
                      <th className="w-32 py-1.5 pl-2 font-medium">Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((s) => {
                      const value = s.isSecret ? revealed[s.id] : plainValues[s.id];
                      const selected = selection.has(s.id);
                      const badge = expiryBadge(s);
                      return (
                        <tr
                          key={s.id}
                          onClick={(e) => {
                            if (e.metaKey || e.ctrlKey) {
                              setSelection((sel) => { const n = new Set(sel); n.has(s.id) ? n.delete(s.id) : n.add(s.id); return n; });
                            } else setSelection(new Set([s.id]));
                          }}
                          onDoubleClick={() => !readOnly && setSheet({ kind: "editor", secret: s })}
                          onContextMenu={(e) => {
                            e.preventDefault();
                            openRowMenu(s, e.clientX, e.clientY);
                          }}
                          data-row={s.id}
                          tabIndex={0}
                          aria-selected={selected}
                          onFocus={() => !selection.has(s.id) && setSelection(new Set([s.id]))}
                          className={`group h-9 border-b border-line/60 outline-none focus-visible:ring-2 focus-visible:ring-accent/60 ${selected ? "bg-accent/25" : "hover:bg-raised/40"}`}
                        >
                          <td className="truncate pl-4">
                            <span className="inline-flex max-w-full items-center gap-2">
                              {s.isSecret ? <Lock size={13} className="shrink-0 text-warn" /> : <Type size={13} className="shrink-0 text-faint" />}
                              <span className="truncate font-mono">{s.key}</span>
                              {badge && <span className={`shrink-0 rounded-full px-1.5 text-[11px] font-semibold ${badge.cls}`}>{badge.text}</span>}
                            </span>
                          </td>
                          <td className="pl-2">
                            <div className="flex items-center gap-1 pr-2">
                              <span className={`selectable min-w-0 flex-1 truncate font-mono ${value === undefined ? "text-muted" : value === "" ? "text-faint italic" : ""}`}>
                                {value === undefined ? "••••••••••••" : value === "" ? "empty" : value}
                              </span>
                              {s.isSecret && (
                                <IconButton title={revealed[s.id] !== undefined ? "Hide value" : "Reveal value"} onClick={() => toggleReveal(s)}>
                                  {revealed[s.id] !== undefined ? <EyeOff size={15} /> : <Eye size={15} />}
                                </IconButton>
                              )}
                              <IconButton title={s.isSecret ? "Copy value (clipboard clears in 60s)" : "Copy value"} onClick={() => copyValue(s)}>
                                {copiedId === s.id ? <Check size={15} /> : <Copy size={15} />}
                              </IconButton>
                            </div>
                          </td>
                          <td className="truncate pl-2 text-muted">{relativeTime(s.updatedAt)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
            <ColumnFooter>
              <span className="text-muted">
                {selection.size ? `${selection.size} selected` : search ? `${filtered.length} of ${plural(secrets.length, "variable")}` : readOnly ? "View only" : "Double-click a row to edit · right-click for more"}
              </span>
              <span className="flex-1" />
              {selection.size > 0 && !readOnly && (
                <FooterButton title="Delete the selected variables" onClick={() => askDelete([...selection])}><Trash2 size={15} /> Delete…</FooterButton>
              )}
            </ColumnFooter>
          </>
        ) : (
          <EmptyState icon={<Layers size={34} />} title={project ? "Select an environment" : "Nothing selected"} text={project ? "Pick an environment to see its variables." : "Create or pick a project to get started."} />
        )}
      </main>

      {menu && <ContextMenu at={menu.at} items={menu.items} onClose={() => setMenu(null)} />}
      {error && (
        <div className="fixed right-4 bottom-14 z-50 flex max-w-md items-start gap-3 rounded-lg border border-danger/40 bg-panel px-4 py-3 shadow-xl">
          <span className="flex-1 text-[13px]">{error}</span>
          <IconButton title="Dismiss" onClick={() => setError(null)}><X size={14} /></IconButton>
        </div>
      )}
      {sheet && renderSheet()}
    </div>
  );

  function renderSheet() {
    if (!sheet) return null;
    const close = () => setSheet(null);
    switch (sheet.kind) {
      case "confirm":
        return <Confirm title={sheet.title} message={sheet.message} action={sheet.action} onConfirm={sheet.onConfirm} onClose={close} />;
      case "newProject":
        return (
          <NewProjectSheet
            onClose={close}
            onCreate={async (name, withDefaults) => {
              const p = await api.createProject(name, withDefaults);
              await run(loadProjects());
              if (p) setProjectId(p.id);
            }}
          />
        );
      case "renameProject":
        return <NameSheet title="Rename Project" initial={sheet.project.name} action="Rename" onClose={close} onSubmit={async (n) => { await api.renameProject(sheet.project.id, n); await run(loadProjects()); }} />;
      case "newEnv":
        return project && <NameSheet title="New Environment" placeholder="e.g. qa, preview, feature-x" action="Create" onClose={close} onSubmit={async (n) => { const e = await api.createEnvironment(project.id, n); await run(loadEnvs(project.id)); setEnvId(e.id); }} />;
      case "renameEnv":
        return project && <NameSheet title="Rename Environment" initial={sheet.env.name} action="Rename" onClose={close} onSubmit={async (n) => { await api.renameEnvironment(sheet.env.id, n); await run(loadEnvs(project.id)); }} />;
      case "cloneEnv":
        return project && (
          <NameSheet
            title={`Clone “${sheet.env.name}”`}
            initial={`${sheet.env.name}-copy`}
            action="Clone"
            note={`Copies all ${plural(sheet.env.secretCount, "variable")}, values included.`}
            onClose={close}
            onSubmit={async (n) => { const e = await api.cloneEnvironment(sheet.env.id, n); await run(loadEnvs(project.id)); setEnvId(e.id); }}
          />
        );
      case "editor":
        return project && env && (
          <VariableEditor
            projectId={project.id}
            envId={env.id}
            secret={sheet.secret}
            onClose={close}
            onSaved={async () => { await run(loadSecrets(project.id, env.id)); await run(loadEnvs(project.id)); }}
          />
        );
      case "import":
        return project && env && (
          <ImportSheet
            projectId={project.id}
            env={env}
            onClose={close}
            onDone={async (s) => {
              await run(loadSecrets(project.id, env.id));
              await run(loadEnvs(project.id));
              showBanner(`Imported: ${s.added} added, ${s.updated} updated, ${s.skipped} skipped`);
            }}
          />
        );
      case "export":
        return project && env && <ExportSheet project={project} env={env} secrets={secrets} onClose={close} onSaved={(f) => showBanner(`Exported to ${f}`)} />;
      case "history":
        return project && env && <HistorySheet projectId={project.id} secret={sheet.secret} readOnly={readOnly} onClose={close} onRestored={() => run(loadSecrets(project.id, env.id))} />;
      case "activity":
        return project && <ActivitySheet project={project} onClose={close} />;
      case "compare":
        return project && <CompareSheet projectId={project.id} left={sheet.left} right={sheet.right} onClose={close} />;
      case "share":
        return project && (
          <ShareSheet
            project={project}
            status={status}
            members={members}
            onClose={close}
            onRefresh={() => loadSharing(project.id)}
            onStopped={() => reloadAll()}
          />
        );
      case "vault":
        return <VaultSheet onClose={close} onLockedOut={onLock} />;
      case "join":
        return <JoinSheet initialLink={sheet.link} onClose={close} onJoined={async (pid) => { await run(loadProjects()); setProjectId(pid); }} />;
    }
  }
}

function EnvIcon({ name, active }: { name: string; active: boolean }) {
  const n = name.toLowerCase();
  const cls = `shrink-0 ${active ? "text-white" : "text-accent"}`;
  if (n.startsWith("prod")) return <ShieldCheck size={16} className={cls} />;
  if (n.startsWith("stag")) return <FlaskConical size={16} className={cls} />;
  if (n.startsWith("dev") || n.startsWith("local")) return <Hammer size={16} className={cls} />;
  return <Layers size={16} className={cls} />;
}

function expiryBadge(s: Secret): { text: string; cls: string } | null {
  if (s.expiresAt === null) return null;
  const now = Date.now() / 1000;
  if (s.expiresAt <= now) return { text: "Expired", cls: "bg-danger/15 text-danger" };
  const days = Math.floor((s.expiresAt - now) / 86400);
  if (days < 1) return { text: "Expires today", cls: "bg-danger/15 text-danger" };
  if (days <= 14) return { text: `Expires in ${days}d`, cls: "bg-warn/15 text-warn" };
  return null;
}
