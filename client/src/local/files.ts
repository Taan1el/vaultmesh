export const REVOKE_DELAY_MS = 10_000;

export function downloadFile(name: string, content: BlobPart, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Keep the object URL alive until the browser has started reading it.
  window.setTimeout(() => URL.revokeObjectURL(url), REVOKE_DELAY_MS);
}
