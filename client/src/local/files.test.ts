import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { downloadFile, REVOKE_DELAY_MS } from './files';

const create = vi.fn(() => 'blob:synthetic'); const revoke = vi.fn();
beforeEach(() => {
  vi.useFakeTimers(); create.mockClear(); revoke.mockClear();
  Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
});
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });
describe('file download', () => {
  it('keeps the object URL alive after the click and revokes it later', () => {
    expect(REVOKE_DELAY_MS).toBeGreaterThanOrEqual(1000);
    downloadFile('synthetic.json', '{}', 'application/json');
    expect(create).toHaveBeenCalledOnce();
    vi.advanceTimersByTime(0); expect(revoke).not.toHaveBeenCalled();
    vi.advanceTimersByTime(999); expect(revoke).not.toHaveBeenCalled();
    vi.advanceTimersByTime(REVOKE_DELAY_MS); expect(revoke).toHaveBeenCalledExactlyOnceWith('blob:synthetic');
    expect(document.querySelector('a[download]')).toBeNull();
  });
});
