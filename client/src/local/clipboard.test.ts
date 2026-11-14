import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ClipboardGuard, type PageState } from './clipboard';

beforeEach(() => {
  vi.useFakeTimers();
  // jsdom reports a page that is never visible or focused; the tests below describe a visible, focused page.
  vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); vi.spyOn(document, 'hasFocus').mockReturnValue(true);
});
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });
describe('temporary clipboard', () => {
  it('clears a copied value after 30 seconds, and only once', async () => {
    let text = '';
    const writeText = vi.fn(async (next: string) => { text = next; });
    const guard = new ClipboardGuard({ writeText, readText: async () => text }, vi.fn());
    await guard.copy('synthetic value');
    await vi.advanceTimersByTimeAsync(29999); expect(text).toBe('synthetic value');
    await vi.advanceTimersByTimeAsync(1); expect(text).toBe('');
    await guard.clear(); expect(writeText).toHaveBeenCalledTimes(2);
  });
  it('preserves unrelated clipboard data when it can check ownership', async () => {
    let text = '';
    const guard = new ClipboardGuard({ writeText: async (next) => { text = next; }, readText: async () => text }, vi.fn());
    await guard.copy('synthetic value'); text = 'another application';
    await vi.advanceTimersByTimeAsync(30000); expect(text).toBe('another application');
  });
  it('clears multiline values when the platform normalizes LF to CRLF', async () => {
    let text = '';
    const guard = new ClipboardGuard({ writeText: async (next) => { text = next.replace(/\r?\n/g, '\r\n'); }, readText: async () => text }, vi.fn());
    await guard.copy('synthetic first line\nsecond line');
    expect(text).toBe('synthetic first line\r\nsecond line');
    await vi.advanceTimersByTimeAsync(30000); expect(text).toBe('');
  });
  it('clears a pending write when a lock happens before copy completes', async () => {
    let resolve!: () => void; let text = '';
    const writeText = vi.fn(async (next: string) => { if (next) await new Promise<void>((done) => { resolve = done; }); text = next; });
    const guard = new ClipboardGuard({ writeText, readText: async () => text }, vi.fn());
    const copying = guard.copy('synthetic value');
    await guard.clear(); resolve(); await copying;
    expect(text).toBe('');
  });
  it('reports denied clearing without logging secret values', async () => {
    const writeText = vi.fn().mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error('Denied.'));
    const failed = vi.fn(); const guard = new ClipboardGuard({ writeText }, failed);
    await guard.copy('synthetic value'); await vi.advanceTimersByTimeAsync(30000);
    expect(failed).toHaveBeenCalledOnce(); expect(failed).toHaveBeenCalledWith();
  });
  it('does not clear early and a lock-time clear call is not needed to remove the value', async () => {
    let text = '';
    const guard = new ClipboardGuard({ writeText: async (next) => { text = next; }, readText: async () => text }, vi.fn());
    await guard.copy('synthetic value'); expect(guard.pending).toBe(true);
    await vi.advanceTimersByTimeAsync(29999); expect(text).toBe('synthetic value');
    await vi.advanceTimersByTimeAsync(1); expect(text).toBe(''); expect(guard.pending).toBe(false);
  });
  describe('hidden page', () => {
    function hiddenPage() {
      let active = false; const listeners = new Set<() => void>();
      const page: PageState = { active: () => active, onActive: (listener) => { listeners.add(listener); return () => { listeners.delete(listener); }; } };
      return { page, listeners, show() { active = true; [...listeners].forEach((listener) => listener()); }, hide() { active = false; } };
    }
    it('waits while the page is hidden and clears when it becomes visible', async () => {
      let text = ''; const state = hiddenPage(); const failed = vi.fn();
      const writeText = vi.fn(async (next: string) => { if (!state.page.active() && !next.startsWith('synthetic')) throw new Error('Document is not focused.'); text = next; });
      const guard = new ClipboardGuard({ writeText, readText: async () => text }, failed, state.page);
      state.show(); await guard.copy('synthetic value'); state.hide();
      await vi.advanceTimersByTimeAsync(60000);
      expect(text).toBe('synthetic value'); expect(failed).not.toHaveBeenCalled(); expect(guard.pending).toBe(true);
      state.show(); await vi.advanceTimersByTimeAsync(0);
      expect(text).toBe(''); expect(failed).not.toHaveBeenCalled(); expect(guard.pending).toBe(false); expect(state.listeners.size).toBe(0);
    });
    it('retries when a write is rejected as the page hides, and does not report a failure for that', async () => {
      let text = ''; const state = hiddenPage(); const failed = vi.fn(); state.show();
      let reject = true;
      const writeText = vi.fn(async (next: string) => { if (!next && reject) { state.hide(); throw new Error('Document is not focused.'); } text = next; });
      const guard = new ClipboardGuard({ writeText, readText: async () => text }, failed, state.page);
      await guard.copy('synthetic value'); await vi.advanceTimersByTimeAsync(30000);
      expect(text).toBe('synthetic value'); expect(failed).not.toHaveBeenCalled();
      reject = false; state.show(); await vi.advanceTimersByTimeAsync(0); expect(text).toBe('');
    });
    it('reports a failure when a write is rejected while the page is visible and focused', async () => {
      const state = hiddenPage(); state.show(); const failed = vi.fn();
      const guard = new ClipboardGuard({ writeText: vi.fn().mockResolvedValueOnce(undefined).mockRejectedValue(new Error('Denied.')) }, failed, state.page);
      await guard.copy('synthetic value'); await vi.advanceTimersByTimeAsync(30000);
      expect(failed).toHaveBeenCalledOnce(); expect(guard.pending).toBe(false);
    });
    it('drops the wait when a newer value is copied', async () => {
      let text = ''; const state = hiddenPage(); state.show();
      const guard = new ClipboardGuard({ writeText: async (next) => { text = next; }, readText: async () => text }, vi.fn(), state.page);
      await guard.copy('synthetic one'); state.hide(); await vi.advanceTimersByTimeAsync(30000); expect(state.listeners.size).toBe(1);
      await guard.copy('synthetic two'); expect(state.listeners.size).toBe(0);
      state.show(); await vi.advanceTimersByTimeAsync(0); expect(text).toBe('synthetic two');
      await vi.advanceTimersByTimeAsync(30000); expect(text).toBe('');
    });
  });
});
