import { expect, test } from '@playwright/test';
import fs from 'node:fs/promises';
import path from 'node:path';

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

test('operates the vault lifecycle from the dashboard', async ({ page, request }) => {
  await page.goto('/');

  await expect(page.getByRole('heading', { name: 'Secrets operations console' })).toBeVisible();
  await expect(page.getByRole('status')).toContainText('UNSEALED');
  await expect(page.getByText('Audit ledger')).toBeVisible();

  await page
    .getByRole('row', { name: /secret\/production\/database/ })
    .getByRole('button', { name: 'Inspect secret/production/database' })
    .click();
  await expect(page.getByRole('dialog')).toContainText('orders-db.example.internal');
  await page.getByRole('button', { name: 'Close' }).click();

  const pathValue = 'secret/apps/reporting-worker';
  await page.getByLabel('Path').fill(pathValue);
  await page.getByLabel('Name').fill('Reporting Worker Token');
  await page.getByLabel('Description').fill('Short-lived token for scheduled reporting jobs');
  await page.getByLabel('Plaintext').fill('{"token":"reporting_token","scope":"reports:read"}');
  await page.getByLabel('Issue a dynamic lease').check();
  await page.getByLabel('Lease TTL (seconds)').fill('120');
  await page.getByRole('button', { name: 'Encrypt secret' }).click();

  await expect(page.getByText(`Encrypted and stored ${pathValue}`)).toBeVisible();
  const createdSecretRow = page.getByRole('row', { name: new RegExp(escapeRegExp(pathValue)) });
  await expect(createdSecretRow).toBeVisible();
  await expect(createdSecretRow).toContainText(pathValue);

  await page.getByRole('button', { name: 'Seal' }).click();
  await expect(page.getByRole('status')).toContainText('SEALED');
  await expect(createdSecretRow.getByRole('button', { name: 'Inspect' })).toBeDisabled();

  const sealedRead = await request.get(`/api/secrets/${pathValue}`);
  expect(sealedRead.status()).toBe(503);
  await expect(sealedRead.json()).resolves.toMatchObject({ error: expect.stringMatching(/Vault is sealed/) });

  const shareResponse = await request.get('/api/vault/demo-shares');
  expect(shareResponse.ok()).toBeTruthy();
  const { shares } = (await shareResponse.json()) as { shares: string[] };
  expect(shares).toHaveLength(5);

  for (const share of shares.slice(0, 3)) {
    await page.getByLabel('Custodian share').fill(share);
    await page.getByRole('button', { name: 'Submit share' }).click();
  }

  await expect(page.getByRole('status')).toContainText('UNSEALED');

  await createdSecretRow.getByRole('button', { name: 'Inspect' }).click();
  await expect(page.getByRole('dialog')).toContainText('reports:read');
  await page.getByRole('button', { name: 'Close' }).click();

  await page.getByRole('button', { name: 'Rotate KEK' }).click();
  await expect(page.getByText('New KEK version created')).toBeVisible();

  await page.getByRole('button', { name: /Re-wrap secrets/ }).click();
  await expect(page.getByText(/Re-wrapped \d+ secrets? to KEK v\d+/)).toBeVisible();
  await expect(page.getByText(/KEK v\d+/).first()).toBeVisible();

  if (process.env.UPDATE_SCREENSHOTS === '1') {
    const screenshotPath = path.resolve('docs', 'screenshots', '04-browser-workflow.png');
    await fs.mkdir(path.dirname(screenshotPath), { recursive: true });
    await page.screenshot({ path: screenshotPath, fullPage: true });
  }
});
