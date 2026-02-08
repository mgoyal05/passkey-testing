import { encryptFetch, credentialToJSON, webauthnRequestOptionsToPublic } from './crypto.js';

const createBtn = document.getElementById('createPayment');
const status = document.getElementById('paymentStatus');

createBtn?.addEventListener('click', async () => {
  status.textContent = 'Creating payment...';
  try {
    const payload = {
      payeeVpa: document.getElementById('payeeVpa').value,
      payeeName: document.getElementById('payeeName').value,
      amountMinor: Number(document.getElementById('amountMinor').value),
      currency: 'INR',
      purpose: document.getElementById('purpose').value
    };
    const result = await encryptFetch('/api/payments/initiate', payload);
    status.textContent = 'Payment initiated.';
    window.location.href = `/pay/confirm/${result.txnId}`;
  } catch (err) {
    status.textContent = err.message;
  }
});

export async function initPaymentConfirmation(txnId) {
  const payee = document.getElementById('confirmPayee');
  const amount = document.getElementById('confirmAmount');
  const purpose = document.getElementById('confirmPurpose');
  const approveBtn = document.getElementById('approvePayment');
  const approveStatus = document.getElementById('approveStatus');

  approveStatus.textContent = 'Loading payment details...';
  const details = await encryptFetch(`/api/payments/${txnId}/details`, {});
  payee.textContent = `${details.payeeName} (${details.payeeVpa})`;
  amount.textContent = `${details.amountMinor} ${details.currency}`;
  purpose.textContent = details.purpose;
  approveStatus.textContent = '';

  approveBtn.addEventListener('click', async () => {
    approveStatus.textContent = 'Requesting passkey...';
    try {
      const options = await encryptFetch(`/api/payments/${txnId}/webauthn/options`, {});
      const publicOptions = webauthnRequestOptionsToPublic(options);
      const assertion = await navigator.credentials.get({ publicKey: publicOptions });
      await encryptFetch(`/api/payments/${txnId}/webauthn/finish`, credentialToJSON(assertion));
      const executed = await encryptFetch(`/api/payments/${txnId}/execute`, {});
      approveStatus.textContent = `Payment ${executed.status} (RRN: ${executed.rrn}).`;
    } catch (err) {
      approveStatus.textContent = err.message;
    }
  });
}
