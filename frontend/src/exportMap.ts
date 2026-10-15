export interface MapExportOptions {
  filename?: string;
  scale?: number;
  download?: boolean;
}

export interface MapExportImage {
  svg: string;
  width: number;
  height: number;
}

const SVG_NS = "http://www.w3.org/2000/svg";
const STYLE_PROPERTIES = [
  "color",
  "fill",
  "fill-opacity",
  "stroke",
  "stroke-width",
  "stroke-opacity",
  "stroke-dasharray",
  "stroke-linecap",
  "stroke-linejoin",
  "dominant-baseline",
  "paint-order",
  "font-family",
  "font-size",
  "font-weight",
  "letter-spacing",
  "opacity",
  "text-anchor",
  "visibility",
] as const;

const finite = (value: number) => Number.isFinite(value) && value > 0;

export function exportBounds(
  viewBox: { x: number; y: number; width: number; height: number },
  box?: { x: number; y: number; width: number; height: number },
) {
  const x =
    box && Number.isFinite(box.x) ? Math.min(viewBox.x, box.x) : viewBox.x;
  const y =
    box && Number.isFinite(box.y) ? Math.min(viewBox.y, box.y) : viewBox.y;
  const right =
    box && Number.isFinite(box.x + box.width)
      ? Math.max(viewBox.x + viewBox.width, box.x + box.width)
      : viewBox.x + viewBox.width;
  const bottom =
    box && Number.isFinite(box.y + box.height)
      ? Math.max(viewBox.y + viewBox.height, box.y + box.height)
      : viewBox.y + viewBox.height;
  return {
    x,
    y,
    width: Math.max(1, right - x),
    height: Math.max(1, bottom - y),
  };
}

function inlineStyles(source: SVGSVGElement, clone: SVGSVGElement) {
  if (typeof getComputedStyle !== "function") return;
  const sourceElements = [source, ...Array.from(source.querySelectorAll("*"))];
  const cloneElements = [clone, ...Array.from(clone.querySelectorAll("*"))];
  sourceElements.forEach((element, index) => {
    const target = cloneElements[index];
    if (!target) return;
    const computed = getComputedStyle(element);
    const values = STYLE_PROPERTIES.map(
      (property) => `${property}:${computed.getPropertyValue(property)}`,
    ).join(";");
    if (values)
      target.setAttribute(
        "style",
        `${target.getAttribute("style") ?? ""};${values}`,
      );
  });
}

/** Serialize the complete SVG, including inherited theme styles and content bounds. */
export function serializeMapSvg(svg: SVGSVGElement): MapExportImage {
  const sourceBox = svg.viewBox.baseVal;
  const viewBox = {
    x: Number.isFinite(sourceBox.x) ? sourceBox.x : 0,
    y: Number.isFinite(sourceBox.y) ? sourceBox.y : 0,
    width: finite(sourceBox.width) ? sourceBox.width : svg.clientWidth || 1,
    height: finite(sourceBox.height) ? sourceBox.height : svg.clientHeight || 1,
  };
  let box: DOMRect | undefined;
  try {
    const measured = svg.getBBox();
    if (finite(measured.width) && finite(measured.height)) box = measured;
  } catch {
    // SVG getBBox is unavailable before layout; the viewBox is still complete.
  }
  const fullWidth = Number(svg.dataset.exportWidth);
  const fullHeight = Number(svg.dataset.exportHeight);
  const complete = finite(fullWidth) && finite(fullHeight);
  const bounds = complete
    ? { x: -16, y: -16, width: fullWidth + 32, height: fullHeight + 32 }
    : exportBounds(viewBox, box);
  const clone = svg.cloneNode(true) as SVGSVGElement;
  clone.setAttribute("xmlns", SVG_NS);
  clone.setAttribute("width", String(bounds.width));
  clone.setAttribute("height", String(bounds.height));
  clone.setAttribute(
    "viewBox",
    `${bounds.x} ${bounds.y} ${bounds.width} ${bounds.height}`,
  );
  inlineStyles(svg, clone);
  if (complete)
    clone.querySelector("[data-export-root]")?.removeAttribute("transform");
  const background = document.createElementNS(SVG_NS, "rect");
  background.setAttribute("x", String(bounds.x));
  background.setAttribute("y", String(bounds.y));
  background.setAttribute("width", String(bounds.width));
  background.setAttribute("height", String(bounds.height));
  background.setAttribute(
    "fill",
    getComputedStyle(svg.closest(".adm") ?? svg)
      .getPropertyValue("--adm-page")
      .trim() || "white",
  );
  clone.insertBefore(background, clone.firstChild);
  return {
    svg: new XMLSerializer().serializeToString(clone),
    width: bounds.width,
    height: bounds.height,
  };
}

export async function exportMapPng(
  svg: SVGSVGElement,
  options: MapExportOptions = {},
): Promise<Blob> {
  const image = serializeMapSvg(svg);
  // Bound canvas allocation for dense graphs, including browsers with limited GPU memory.
  const requested = Number.isFinite(options.scale) ? options.scale! : 2;
  const scale = Math.min(
    Math.max(0.1, Math.min(4, requested)),
    8192 / Math.max(image.width, image.height),
    Math.sqrt(32000000 / (image.width * image.height)),
  );
  const source = new Blob([image.svg], { type: "image/svg+xml;charset=utf-8" });
  const sourceURL = URL.createObjectURL(source);
  try {
    const bitmap = new Image();
    await new Promise<void>((resolve, reject) => {
      bitmap.onload = () => resolve();
      bitmap.onerror = () =>
        reject(new Error("SVG image could not be rendered."));
      bitmap.src = sourceURL;
    });
    const canvas = document.createElement("canvas");
    canvas.width = Math.ceil(image.width * scale);
    canvas.height = Math.ceil(image.height * scale);
    const context = canvas.getContext("2d");
    if (!context) throw new Error("Canvas 2D is unavailable.");
    context.scale(scale, scale);
    context.drawImage(bitmap, 0, 0, image.width, image.height);
    const png = await new Promise<Blob>((resolve, reject) =>
      canvas.toBlob(
        (value) =>
          value
            ? resolve(value)
            : reject(new Error("PNG encoding returned no data.")),
        "image/png",
      ),
    );
    if (options.download !== false) {
      const url = URL.createObjectURL(png);
      const link = document.createElement("a");
      link.href = url;
      link.download = options.filename ?? "application-atlas-map.png";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    return png;
  } finally {
    URL.revokeObjectURL(sourceURL);
  }
}

/** Print an isolated full-map SVG using the browser's PDF destination. */
export function printMap(svg: SVGSVGElement, title: string) {
  const image = serializeMapSvg(svg);
  const output = document.createElement("section");
  output.className = "atlas-print-output";
  const heading = document.createElement("h1");
  heading.textContent = title;
  output.append(heading);
  const parsed = new DOMParser().parseFromString(image.svg, "image/svg+xml");
  output.append(document.importNode(parsed.documentElement, true));
  document.body.append(output);
  document.body.classList.add("atlas-printing");
  try {
    window.print();
  } finally {
    output.remove();
    document.body.classList.remove("atlas-printing");
  }
}
