export function registerOffline(): void {
  if (import.meta.env.MODE !== 'pages' || !('serviceWorker' in navigator)) return;

  const register = () => {
    void navigator.serviceWorker.register(`${import.meta.env.BASE_URL}sw.js`, {
      scope: import.meta.env.BASE_URL,
    }).catch((error: unknown) => {
      console.error('Offline storage could not start.', error);
    });
  };

  if (document.readyState === 'complete') register();
  else window.addEventListener('load', register, { once: true });
}
