/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "true" builds the dashboard with the in-browser demo backend instead of the HTTP API. */
  readonly VITE_DEMO_MODE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
