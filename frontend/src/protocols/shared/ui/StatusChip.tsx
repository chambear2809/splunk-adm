import {
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Minus,
  Slash,
} from "lucide-react";
import { STATUS_LABELS, type ProtocolStatus } from "../contract";

const ICONS = {
  ok: CheckCircle2,
  attention: AlertTriangle,
  not_covered: Slash,
  none_observed: Minus,
  unknown: HelpCircle,
} as const;

export function StatusChip({
  status,
  label,
  title,
  onClick,
}: {
  status: ProtocolStatus;
  label?: string;
  title?: string;
  onClick?: () => void;
}) {
  const Icon = ICONS[status];
  const resolvedLabel =
    label && label.trim() && label.trim() !== "—"
      ? label
      : STATUS_LABELS[status];
  const content =
    status === "not_covered" ? (
      <span className="pl-status-inner">
        <Icon size={12} aria-hidden="true" />
        <span>{resolvedLabel}</span>
      </span>
    ) : (
      <>
        <Icon size={13} aria-hidden="true" />
        <span>{resolvedLabel}</span>
      </>
    );
  const className = `pl-status-chip pl-status-${status}`;
  if (onClick) {
    return (
      <button
        type="button"
        className={`${className} pl-status-interactive`}
        title={title}
        onClick={onClick}
      >
        {content}
      </button>
    );
  }
  return (
    <span className={className} title={title}>
      {content}
    </span>
  );
}
