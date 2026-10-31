import React from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource-variable/fraunces';
import '@fontsource-variable/public-sans';
import '@fontsource-variable/source-code-pro';
import './styles/tokens.css';
import { WorkspaceApp } from './local/WorkspaceApp';
import { registerOffline } from './local/offline';
import './styles.css';

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <WorkspaceApp />
  </React.StrictMode>
);
registerOffline();
