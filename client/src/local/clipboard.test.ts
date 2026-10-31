import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ClipboardGuard } from './clipboard';

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());
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
});
