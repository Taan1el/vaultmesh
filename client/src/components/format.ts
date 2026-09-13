export function maskHex(value: string): string {
  if (value.length <= 18) return value;
  return `${value.slice(0, 10)}...${value.slice(-8)}`;
}

export function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(value));
}

export function formatDateTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(value));
}

/** "42 s", "3 min 5 s" */
export function formatDuration(ms: number): string {
  const totalSeconds = Math.max(0, Math.ceil(ms / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes === 0) return `${seconds} s`;
  return seconds === 0 ? `${minutes} min` : `${minutes} min ${seconds} s`;
}

export function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

/** Reads the index from a share string such as "vmshare-03-ab12...". */
export function shareIndex(share: string): number | null {
  const match = /^vmshare-([0-9a-f]{2})-/i.exec(share.trim());
  return match ? parseInt(match[1], 16) : null;
}
