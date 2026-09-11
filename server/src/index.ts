import { createApp } from './app.js';

const PORT = process.env.PORT || 4005;
const { app } = createApp();

app.listen(PORT, () => {
  console.log(`[VaultMesh] Server running securely on http://localhost:${PORT}`);
});