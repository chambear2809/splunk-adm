/**
 * Scale thresholds for the map. A graph above the display limits is reduced to
 * its heaviest relationships instead of being rejected (see truncate.ts).
 */
/** Nodes kept in one map snapshot. */
export const MAX_GRAPH_NODES = 4000;
/** Relationships kept in one map snapshot. */
export const MAX_GRAPH_EDGES = 10000;
/** Node rows the bounded graph search may return before client-side ranking. */
export const SERVER_NODE_CAP = 20000;
/** Visible cards above which the layout collapses its largest groups. */
export const LOD_CARDS = 300;
/** Routed lines above which orthogonal channel routing is skipped. */
export const STRAIGHT_ROUTE_EDGES = 1500;
/** Routed lines above which they are drawn on a canvas instead of SVG. */
export const CANVAS_EDGES = 1000;
