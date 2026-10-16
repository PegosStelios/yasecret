import { ReactNode, useEffect, useRef, useState } from "react";
import { X } from "lucide-react";

type ButtonProps = {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "ghost" | "danger";
  disabled?: boolean;
  title?: string;
  type?: "button" | "submit";
  className?: string;
};

export function Button({ children, onClick, variant = "secondary", disabled, title, type = "button", className = "" }: ButtonProps) {
  const styles = {
    primary: "bg-accent text-accent-fg hover:brightness-110",
    secondary: "bg-raised hover:brightness-110",
    ghost: "text-muted hover:text-fg hover:bg-raised",
    danger: "text-danger hover:bg-danger/10",
  }[variant];
  return (
    <button
      type={type}
      title={title}
      disabled={disabled}
      onClick={onClick}
      className={`inline-flex h-8 items-center gap-1.5 whitespace-nowrap rounded-md px-3 transition-colors disabled:pointer-events-none disabled:opacity-40 ${styles} ${className}`}
    >
      {children}
    </button>
  );
}

export function IconButton({ children, onClick, title, disabled }: { children: ReactNode; onClick?: () => void; title: string; disabled?: boolean }) {
  return (
    <button
      type="button"
      title={title}
      aria-label={title}
      disabled={disabled}
      onClick={(e) => {
        e.stopPropagation();
        onClick?.();
      }}
      className="inline-flex size-7 items-center justify-center rounded-md text-muted transition hover:bg-raised hover:text-fg disabled:opacity-40"
    >
      {children}
    </button>
  );
}

export function TextInput(props: React.InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }) {
  const { mono, className = "", ...rest } = props;
  return (
    <input
      {...rest}
      className={`h-8 w-full rounded-md border border-line bg-field px-2.5 outline-none focus:border-accent ${mono ? "font-mono" : ""} ${className}`}
    />
  );
}

export function Toggle({ checked, onChange, label, hint }: { checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string }) {
  return (
    <label className="flex cursor-pointer items-center justify-between gap-4">
      <span>
        <span className="block">{label}</span>
        {hint && <span className="block text-xs text-muted">{hint}</span>}
      </span>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`relative h-5 w-9 shrink-0 rounded-full transition ${checked ? "bg-accent" : "bg-raised"}`}
      >
        <span className={`absolute top-0.5 size-4 rounded-full bg-white shadow transition ${checked ? "left-4.5" : "left-0.5"}`} />
      </button>
    </label>
  );
}

export function Segmented<T extends string>({ value, options, onChange }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex rounded-md bg-field p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          className={`h-7 rounded px-3 transition ${o.value === value ? "bg-raised text-fg shadow" : "text-muted hover:text-fg"}`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Modal({ title, subtitle, onClose, children, width = 460, footer }: {
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
  width?: number;
  footer?: ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40" onMouseDown={onClose}>
      <div
        role="dialog"
        aria-label={title}
        className="flex max-h-[85vh] flex-col rounded-xl border border-line bg-panel shadow-2xl"
        style={{ width }}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4 px-5 pt-5 pb-3">
          <div>
            <h2 className="text-[17px] font-semibold">{title}</h2>
            {subtitle && <p className="mt-0.5 font-mono text-xs text-muted">{subtitle}</p>}
          </div>
          <IconButton title="Close" onClick={onClose}>
            <X size={16} />
          </IconButton>
        </div>
        <div className="min-h-0 flex-1 overflow-auto px-5 pb-4">{children}</div>
        {footer && <div className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">{footer}</div>}
      </div>
    </div>
  );
}

export function Confirm({ title, message, action, onConfirm, onClose }: {
  title: string;
  message: string;
  action: string;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Modal
      title={title}
      onClose={onClose}
      width={400}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" className="!bg-danger" onClick={() => { onConfirm(); onClose(); }}>
            {action}
          </Button>
        </>
      }
    >
      <p className="text-muted">{message}</p>
    </Modal>
  );
}

export type MenuItem = { label: string; onClick: () => void; danger?: boolean } | "divider";

/** Right-click menu; `at` is the cursor position. */
export function ContextMenu({ at, items, onClose }: { at: { x: number; y: number }; items: MenuItem[]; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState(at);
  useEffect(() => {
    const el = ref.current;
    if (el) {
      const { innerWidth, innerHeight } = window;
      setPos({ x: Math.min(at.x, innerWidth - el.offsetWidth - 8), y: Math.min(at.y, innerHeight - el.offsetHeight - 8) });
    }
    const close = () => onClose();
    window.addEventListener("mousedown", close);
    window.addEventListener("blur", close);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("blur", close);
    };
  }, [at, onClose]);
  return (
    <div
      ref={ref}
      className="fixed z-50 min-w-44 rounded-lg border border-line bg-raised p-1 shadow-xl"
      style={{ left: pos.x, top: pos.y }}
      onMouseDown={(e) => e.stopPropagation()}
    >
      {items.map((it, i) =>
        it === "divider" ? (
          <div key={i} className="my-1 h-px bg-line" />
        ) : (
          <button
            key={i}
            type="button"
            onClick={() => { it.onClick(); onClose(); }}
            className={`block w-full rounded px-2.5 py-1 text-left hover:bg-accent hover:text-white ${it.danger ? "text-danger" : ""}`}
          >
            {it.label}
          </button>
        ),
      )}
    </div>
  );
}

/** Title block shared by the environment and variable columns so they line up. */
export function ColumnHeader({ title, subtitle, trailing }: { title: string; subtitle: string; trailing?: ReactNode }) {
  return (
    <div className="flex h-14 items-center gap-3 px-4 pt-3">
      <div className="min-w-0 flex-1">
        <h1 className="truncate text-[19px] leading-6 font-semibold">{title}</h1>
        <p className="truncate text-[13px] text-muted">{subtitle}</p>
      </div>
      {trailing}
    </div>
  );
}

/** Same height in every column. */
export function ColumnFooter({ children }: { children: ReactNode }) {
  return <div className="flex h-10 shrink-0 items-center gap-3 border-t border-line px-3">{children}</div>;
}

export function FooterButton({ children, onClick, title }: { children: ReactNode; onClick: () => void; title: string }) {
  return (
    <button type="button" title={title} onClick={onClick} className="inline-flex items-center gap-1.5 whitespace-nowrap text-muted transition hover:text-fg">
      {children}
    </button>
  );
}

export function EmptyState({ icon, title, text, children }: { icon: ReactNode; title: string; text: string; children?: ReactNode }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-8 text-center">
      <div className="mb-1 text-faint">{icon}</div>
      <p className="text-[15px] font-semibold text-muted">{title}</p>
      <p className="max-w-80 text-muted">{text}</p>
      {children && <div className="mt-3 flex gap-2">{children}</div>}
    </div>
  );
}

export function ErrorLine({ text }: { text: string | null }) {
  return text ? <p className="mt-3 text-[13px] text-danger">{text}</p> : null;
}
