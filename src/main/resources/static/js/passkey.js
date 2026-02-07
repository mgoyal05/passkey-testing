import { encryptFetch, credentialToJSON, webauthnCreateOptionsToPublic } from './crypto.js';

const button = document.getElementById('createPasskey');
const status = document.getElementById('passkeyStatus');

button?.addEventListener('click', async () => {
  status.textContent = 'Requesting options...';
  try {
    const options = await encryptFetch('/api/webauthn/register/options', {});
    const publicOptions = webauthnCreateOptionsToPublic(options);
    status.textContent = 'Waiting for authenticator...';
    const credential = await navigator.credentials.create({ publicKey: publicOptions });
    const payload = credentialToJSON(credential);
    await encryptFetch('/api/webauthn/register/finish', payload);
    status.textContent = 'Passkey created! You can now use payments.';
    window.location.href = '/pay';
  } catch (err) {
    status.textContent = err.message;
  }
});
