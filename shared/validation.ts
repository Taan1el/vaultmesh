import { badRequest } from './errors.js';

export const SECRET_PATH_MAX_LENGTH = 200;
export const SECRET_NAME_MAX_LENGTH = 100;
export const SECRET_DESCRIPTION_MAX_LENGTH = 500;
export const PLAINTEXT_MAX_BYTES = 32 * 1024;
export const MIN_TTL_SECONDS = 10;
export const MAX_TTL_SECONDS = 24 * 60 * 60;
export const DEFAULT_TTL_SECONDS = 60;
export const DEFAULT_MAX_TTL_FACTOR = 5;
export const DEFAULT_RENEW_INCREMENT_SECONDS = 30;
export const MAX_RENEW_INCREMENT_SECONDS = 60 * 60;
export const DEFAULT_AUDIT_LIMIT = 50;
export const MAX_AUDIT_LIMIT = 200;
export const ACTOR_MAX_LENGTH = 64;

const PATH_SEGMENT = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;

/** Secret input after validation, with defaults applied. */
export interface NewSecretInput {
  path: string;
  name: string;
  description: string;
  plaintext: string;
  isDynamic: boolean;
  ttlSeconds: number;
  maxTtlSeconds: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isWholeNumberInRange(value: unknown, min: number, max: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;
}

export function normalizeSecretPath(raw: string): string {
  return raw.trim().replace(/^\/+|\/+$/g, '');
}

/** Validates a secret path (or secret id) and strips leading and trailing slashes. */
export function parseSecretPath(raw: unknown): string {
  if (raw === undefined || raw === null || raw === '') throw badRequest('path is required');
  if (typeof raw !== 'string') throw badRequest('path must be a string');
  const path = normalizeSecretPath(raw);
  if (!path) throw badRequest('path must not be empty');
  if (path.length > SECRET_PATH_MAX_LENGTH) {
    throw badRequest(`path must be at most ${SECRET_PATH_MAX_LENGTH} characters`);
  }
  if (!path.split('/').every((segment) => PATH_SEGMENT.test(segment))) {
    throw badRequest(
      'path segments may only use letters, digits, "_", "-" and ".", and must start with a letter, digit or "_"'
    );
  }
  return path;
}

function parseText(value: unknown, field: string, maxLength: number, required: boolean): string {
  if (value === undefined || value === null) {
    if (required) throw badRequest(`${field} is required`);
    return '';
  }
  if (typeof value !== 'string') throw badRequest(`${field} must be a string`);
  const text = value.trim();
  if (required && !text) throw badRequest(`${field} must not be empty`);
  if (text.length > maxLength) throw badRequest(`${field} must be at most ${maxLength} characters`);
  return text;
}

function parsePlaintext(value: unknown): string {
  if (value === undefined || value === null) throw badRequest('plaintext is required');
  let plaintext: string;
  if (typeof value === 'string') {
    plaintext = value;
  } else if (typeof value === 'object') {
    plaintext = JSON.stringify(value);
  } else {
    throw badRequest('plaintext must be a string or a JSON object');
  }
  if (!plaintext.trim()) throw badRequest('plaintext must not be empty');
  if (new TextEncoder().encode(plaintext).length > PLAINTEXT_MAX_BYTES) {
    throw badRequest(`plaintext must be at most ${PLAINTEXT_MAX_BYTES} bytes`);
  }
  return plaintext;
}

/** Validates the body of a create-secret request. Throws a 400 VaultError on bad input. */
export function parseCreateSecretInput(body: unknown): NewSecretInput {
  if (!isRecord(body)) throw badRequest('Request body must be a JSON object');

  const path = parseSecretPath(body.path);
  const name = parseText(body.name, 'name', SECRET_NAME_MAX_LENGTH, true);
  const description = parseText(body.description, 'description', SECRET_DESCRIPTION_MAX_LENGTH, false);
  const plaintext = parsePlaintext(body.plaintext);

  if (body.isDynamic !== undefined && typeof body.isDynamic !== 'boolean') {
    throw badRequest('isDynamic must be true or false');
  }
  const isDynamic = body.isDynamic === true;
  if (!isDynamic) {
    return { path, name, description, plaintext, isDynamic, ttlSeconds: 0, maxTtlSeconds: 0 };
  }

  const ttlSeconds = body.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  if (!isWholeNumberInRange(ttlSeconds, MIN_TTL_SECONDS, MAX_TTL_SECONDS)) {
    throw badRequest(`ttlSeconds must be a whole number between ${MIN_TTL_SECONDS} and ${MAX_TTL_SECONDS}`);
  }
  const maxTtlSeconds = body.maxTtlSeconds ?? Math.min(ttlSeconds * DEFAULT_MAX_TTL_FACTOR, MAX_TTL_SECONDS);
  if (!isWholeNumberInRange(maxTtlSeconds, ttlSeconds, MAX_TTL_SECONDS)) {
    throw badRequest(`maxTtlSeconds must be a whole number between ttlSeconds and ${MAX_TTL_SECONDS}`);
  }

  return { path, name, description, plaintext, isDynamic, ttlSeconds, maxTtlSeconds };
}

export function parseRenewIncrement(value: unknown): number {
  if (value === undefined || value === null) return DEFAULT_RENEW_INCREMENT_SECONDS;
  if (!isWholeNumberInRange(value, 1, MAX_RENEW_INCREMENT_SECONDS)) {
    throw badRequest(`incrementSeconds must be a whole number between 1 and ${MAX_RENEW_INCREMENT_SECONDS}`);
  }
  return value;
}

export function parseAuditLimit(value: unknown): number {
  if (value === undefined || value === '') return DEFAULT_AUDIT_LIMIT;
  const limit = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : typeof value === 'number' ? value : NaN;
  if (!isWholeNumberInRange(limit, 1, MAX_AUDIT_LIMIT)) {
    throw badRequest(`limit must be a whole number between 1 and ${MAX_AUDIT_LIMIT}`);
  }
  return limit;
}

/** Actor names come from a self-reported header, so keep them short and printable. */
export function sanitizeActor(value: unknown, fallback: string): string {
  if (typeof value !== 'string') return fallback;
  const cleaned = value.replace(/[^\x20-\x7e]/g, '').trim().slice(0, ACTOR_MAX_LENGTH);
  return cleaned || fallback;
}
