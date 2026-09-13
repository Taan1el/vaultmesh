import type { CreateSecretDto } from './types.js';

/**
 * Sample secrets written into a new vault so the dashboard is not empty.
 * Every value is an obvious placeholder, never a real or real-looking credential.
 */
export const SAMPLE_SECRETS: CreateSecretDto[] = [
  {
    path: 'secret/production/database',
    name: 'Orders database',
    description: 'Connection settings for the orders service. Sample values only.',
    plaintext: JSON.stringify({
      host: 'orders-db.example.internal',
      port: 5432,
      database: 'orders',
      username: 'orders_app',
      password: 'example-password-not-real',
    }),
    isDynamic: false,
  },
  {
    path: 'secret/payments/gateway',
    name: 'Payment gateway keys',
    description: 'API key and webhook signing secret for a payment provider. Sample values only.',
    plaintext: JSON.stringify({
      api_key: 'example-api-key-not-real',
      webhook_secret: 'example-webhook-secret-not-real',
    }),
    isDynamic: false,
  },
  {
    path: 'secret/cloud/deploy-credential',
    name: 'Deploy credential',
    description: 'Short-lived cloud credential. Leases last 60 seconds and renew up to 5 minutes.',
    plaintext: JSON.stringify({
      access_key_id: 'EXAMPLE-ACCESS-KEY-ID',
      secret_access_key: 'example-secret-access-key-not-real',
      session_token: 'example-session-token-not-real',
    }),
    isDynamic: true,
    ttlSeconds: 60,
    maxTtlSeconds: 300,
  },
];
