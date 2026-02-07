import { encryptFetch, credentialToJSON, webauthnCreateOptionsToPublic } from './crypto.js';

const button = document.getElementById('createPasskey');
const status = document.getElementById('passkeyStatus');
const errorBox = document.getElementById('passkeyError');
const errorDetails = document.getElementById('passkeyErrorDetails');

function showError(message, details) {
  if (errorBox && errorDetails) {
    errorDetails.textContent = details || message;
    errorBox.style.display = 'block';
  }
}

function clearError() {
  if (errorBox && errorDetails) {
    errorDetails.textContent = '';
    errorBox.style.display = 'none';
  }
}

button?.addEventListener('click', async () => {
  status.textContent = 'Requesting options...';
  clearError();
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
    const message = err?.message || 'Passkey enrollment failed.';
    status.textContent = message;
    const detailPayload = err?.details ? JSON.stringify(err.details, null, 2) : err?.stack;
    showError(message, detailPayload || message);
    console.error('Passkey enrollment error:', err);
  }
});
