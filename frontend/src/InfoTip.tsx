import type { ReactNode, Ref } from "react";
import TooltipExport from "@splunk/react-ui/Tooltip";
import { toolkitDefault } from "./app/interop";
import { terms, type GlossaryTerm } from "./glossary";

const Tooltip = toolkitDefault(TooltipExport);

export interface InfoTipProps {
  /** The glossary entry shown when the info button receives focus or hover. */
  term: GlossaryTerm;
  /** Optional visible label to place beside the info button. */
  children?: ReactNode;
}

/** An accessible, keyboard-focusable glossary hint for a compact UI label. */
export function InfoTip({ term, children }: InfoTipProps) {
  const label = children ?? term;
  return (
    <span className="atlas-info-tip">
      <span>{label}</span>
      <Tooltip
        content={terms[term]}
        contentRelationship="description"
        wrapContent
        renderAnchor={(anchorProps) => (
          <button
            ref={anchorProps.elementRef as Ref<HTMLButtonElement>}
            aria-describedby={anchorProps["aria-describedby"]}
            onFocus={anchorProps.onFocus}
            onBlur={anchorProps.onBlur}
            onClick={anchorProps.onClick}
            onPointerDown={anchorProps.onPointerDown}
            onPointerCancel={anchorProps.onPointerCancel}
            type="button"
            aria-label={`Explain ${term}`}
            style={{
              alignItems: "center",
              background: "none",
              border: 0,
              cursor: "help",
              display: "inline-flex",
              font: "inherit",
              padding: 0,
            }}
          >
            <span aria-hidden="true">ⓘ</span>
          </button>
        )}
      />
    </span>
  );
}

export default InfoTip;
