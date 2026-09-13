import { createApp } from './app.js';

const PORT = Number(process.env.PORT) || 4005;
// The API has no authentication, so it listens on loopback unless HOST says otherwise.
const HOST = process.env.HOST || '127.0.0.1';
const { app } = createApp(process.env.VAULTMESH_DB_PATH || undefined);

app.listen(PORT, HOST, () => {
  console.log(`VaultMesh API listening on http://${HOST}:${PORT}`);
});
