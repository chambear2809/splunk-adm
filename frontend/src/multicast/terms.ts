import type { FlagId } from "./flags";

/** Evidence rule behind each flag; kept local so the multicast bundle stays small. */
export const MULTICAST_TERMS: Record<FlagId, string> = {
  "interest-no-sender":
    "Interest, no sender seen: IGMP reports for this group were observed, but no flow summary in this scope showed sender traffic in this window. Uncovered paths or sampling can hide senders; it is an evidence gap, not a fault.",
  "sender-no-interest":
    "Sender, no interest seen: flow records showed sender traffic for this group, but no IGMP capture in this scope observed receiver interest in this window. Receivers may sit beyond the captured segments; it is an evidence gap, not a fault.",
  "new-since-previous":
    "New since previous window: this group was observed in this window but not in the previous window of equal length, which was searched completely.",
  "leave-without-query":
    "Leave without query: a leave was observed with no later query from that capture in this window. It may be normal; it is an evidence gap, not a fault.",
  "multiple-query-senders":
    "Multiple query senders: a capture covering this group observed IGMP queries from more than one source address in this window. It may be normal; it is an evidence gap, not a fault.",
  "coverage-partial":
    "Source coverage partial: at least one stream source in this scope did not complete its search, so evidence for this group may be missing.",
};
