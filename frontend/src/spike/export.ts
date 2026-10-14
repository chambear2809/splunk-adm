/** Exercise SVG → blob image → canvas → PNG under the real Splunk page policy. */
export async function exportSpikePng(svg: SVGSVGElement): Promise<number> {
  const source = new Blob([new XMLSerializer().serializeToString(svg)], {
    type: "image/svg+xml;charset=utf-8",
  });
  const sourceURL = URL.createObjectURL(source);
  try {
    const image = new Image();
    await new Promise<void>((resolve, reject) => {
      image.onload = () => resolve();
      image.onerror = () =>
        reject(new Error("SVG image blocked or unreadable."));
      image.src = sourceURL;
    });
    const canvas = document.createElement("canvas");
    canvas.width = svg.viewBox.baseVal.width;
    canvas.height = svg.viewBox.baseVal.height;
    const context = canvas.getContext("2d");
    if (!context) throw new Error("Canvas 2D is unavailable.");
    context.drawImage(image, 0, 0);
    const png = await new Promise<Blob>((resolve, reject) => {
      canvas.toBlob(
        (blob) =>
          blob
            ? resolve(blob)
            : reject(new Error("PNG encoding returned no data.")),
        "image/png",
      );
    });
    if (png.type !== "image/png" || !png.size) throw new Error("Invalid PNG.");
    const downloadURL = URL.createObjectURL(png);
    const link = document.createElement("a");
    link.href = downloadURL;
    link.download = "atlas-toolkit-spike.png";
    link.click();
    setTimeout(() => URL.revokeObjectURL(downloadURL), 1000);
    return png.size;
  } finally {
    URL.revokeObjectURL(sourceURL);
  }
}
