// Traitement des pièces jointes image : redimensionne + compresse côté client.
// Une capture d'écran brute peut peser plusieurs Mo ; on la ramène à une taille
// raisonnable (bord max ~1600 px, JPEG qualité 0.82) pour que ça « marche toujours »,
// sans alourdir le brouillon ni le PDF. Les non-images (PDF…) sont conservées telles quelles.

export interface Att { name: string; type: string; data: string }

function readDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result));
    r.onerror = () => reject(new Error("lecture impossible"));
    r.readAsDataURL(file);
  });
}

/** Compresse une image (ou renvoie le fichier tel quel si non-image / échec). */
export async function toAttachment(file: File, opts?: { maxDim?: number; quality?: number; mime?: string }): Promise<Att> {
  const maxDim = opts?.maxDim ?? 1600;
  const quality = opts?.quality ?? 0.82;
  const src = await readDataUrl(file);
  if (!file.type.startsWith("image/")) {
    return { name: file.name, type: file.type, data: src };
  }
  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const im = new Image();
      im.onload = () => resolve(im);
      im.onerror = () => reject(new Error("image invalide"));
      im.src = src;
    });
    const scale = Math.min(1, maxDim / Math.max(img.width, img.height));
    const w = Math.max(1, Math.round(img.width * scale));
    const h = Math.max(1, Math.round(img.height * scale));
    const cv = document.createElement("canvas");
    cv.width = w; cv.height = h;
    const ctx = cv.getContext("2d");
    if (!ctx) return { name: file.name, type: file.type, data: src };
    // Fond blanc (le JPEG n'a pas de transparence — évite le noir sur PNG transparent).
    ctx.fillStyle = "#ffffff"; ctx.fillRect(0, 0, w, h);
    ctx.drawImage(img, 0, 0, w, h);
    const mime = opts?.mime ?? "image/jpeg";
    const out = cv.toDataURL(mime, quality);
    // Si la compression n'aide pas (petite image PNG déjà légère), on garde le plus léger.
    return { name: file.name.replace(/\.(png|webp|bmp)$/i, ".jpg"), type: mime, data: out.length < src.length ? out : src };
  } catch {
    return { name: file.name, type: file.type, data: src };
  }
}
