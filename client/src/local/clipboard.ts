export class ClipboardGuard {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private value = '';
  private generation = 0;
  constructor(private readonly clipboard: Pick<Clipboard, 'writeText'> & Partial<Pick<Clipboard, 'readText'>>, private readonly failed: () => void) {}
  async copy(value: string) {
    const generation = ++this.generation;
    await this.clipboard.writeText(value);
    if (generation !== this.generation) { await this.clearValue(value); return; }
    clearTimeout(this.timer); this.value = value;
    this.timer = setTimeout(() => { void this.clear(); }, 30_000);
  }
  async clear() {
    ++this.generation;
    clearTimeout(this.timer); this.timer = undefined;
    const previous = this.value; this.value = '';
    await this.clearValue(previous);
  }
  private async clearValue(previous: string) {
    if (!previous) return;
    try {
      if (this.clipboard.readText) {
        try {
          // Windows clipboard text uses CRLF even when writeText receives LF.
          const current = await this.clipboard.readText();
          if (current.replace(/\r\n/g, '\n') !== previous.replace(/\r\n/g, '\n')) return;
        }
        catch { /* Some browsers permit writes but deny clipboard reads. */ }
      }
      await this.clipboard.writeText('');
    } catch { this.failed(); }
  }
}
