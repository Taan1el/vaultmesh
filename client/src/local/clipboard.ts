export const CLEAR_DELAY_MS = 30_000;

/** What the guard needs to know about the page: whether the browser lets it write to the clipboard right now. */
export interface PageState {
  active(): boolean;
  onActive(listener: () => void): () => void;
}

export function browserPage(): PageState {
  return {
    active: () => document.visibilityState === 'visible' && document.hasFocus(),
    onActive(listener) {
      const visible = () => { if (document.visibilityState === 'visible') listener(); };
      document.addEventListener('visibilitychange', visible);
      window.addEventListener('focus', listener);
      return () => { document.removeEventListener('visibilitychange', visible); window.removeEventListener('focus', listener); };
    },
  };
}

type Outcome = 'cleared' | 'denied';

/**
 * Removes a copied secret from the clipboard 30 seconds after copying. The timer is not tied to the
 * vault lock state: locking leaves it running. Browsers reject clipboard writes from a hidden or
 * unfocused page, so a clear that comes due then waits for the page to become visible and focused,
 * and only reports failure if a write is rejected while the page can write.
 */
export class ClipboardGuard {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private release: (() => void) | undefined;
  private value = '';
  private generation = 0;
  constructor(
    private readonly clipboard: Pick<Clipboard, 'writeText'> & Partial<Pick<Clipboard, 'readText'>>,
    private readonly failed: () => void,
    private readonly page: PageState = browserPage(),
  ) {}
  /** True while a copied value is still waiting to be cleared. */
  get pending() { return this.value !== ''; }
  async copy(value: string) {
    const generation = ++this.generation;
    await this.clipboard.writeText(value);
    if (generation !== this.generation) { await this.clearValue(value); return; }
    clearTimeout(this.timer); this.stopWaiting(); this.value = value;
    this.timer = setTimeout(() => { this.timer = undefined; void this.attempt(); }, CLEAR_DELAY_MS);
  }
  /** Clears right away. Locking does not call this. */
  async clear() {
    ++this.generation;
    clearTimeout(this.timer); this.timer = undefined; this.stopWaiting();
    const previous = this.value; this.value = '';
    if (await this.clearValue(previous) === 'denied') this.failed();
  }
  private async attempt() {
    const previous = this.value; const generation = this.generation;
    if (!previous) return;
    if (!this.page.active()) { this.wait(); return; }
    const outcome = await this.clearValue(previous);
    if (generation !== this.generation || this.value !== previous) return;
    if (outcome === 'cleared') { this.value = ''; return; }
    if (this.page.active()) { this.value = ''; this.failed(); } else this.wait();
  }
  private wait() {
    if (this.release) return;
    this.release = this.page.onActive(() => { if (this.page.active()) { this.stopWaiting(); void this.attempt(); } });
  }
  private stopWaiting() { this.release?.(); this.release = undefined; }
  private async clearValue(previous: string): Promise<Outcome> {
    if (!previous) return 'cleared';
    try {
      if (this.clipboard.readText) {
        try {
          // Windows clipboard text uses CRLF even when writeText receives LF.
          const current = await this.clipboard.readText();
          if (current.replace(/\r\n/g, '\n') !== previous.replace(/\r\n/g, '\n')) return 'cleared';
        }
        catch { /* Some browsers permit writes but deny clipboard reads. */ }
      }
      await this.clipboard.writeText('');
      return 'cleared';
    } catch { return 'denied'; }
  }
}
