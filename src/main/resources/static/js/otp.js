import { encryptFetch } from './crypto.js';

const sendBtn = document.getElementById('sendOtp');
const verifyBtn = document.getElementById('verifyOtp');
const sendStatus = document.getElementById('sendStatus');
const verifyStatus = document.getElementById('verifyStatus');

sendBtn?.addEventListener('click', async () => {
  sendStatus.textContent = 'Sending...';
  try {
    const mobileNumber = document.getElementById('mobileNumber').value;
    const response = await encryptFetch('/api/otp/send', {
      mobileNumber,
      customerType: 'Consumer',
      otpContext: 'Register'
    });
    sendStatus.textContent = response.message || 'OTP sent.';
  } catch (err) {
    sendStatus.textContent = err.message;
  }
});

verifyBtn?.addEventListener('click', async () => {
  verifyStatus.textContent = 'Verifying...';
  try {
    const mobileNumber = document.getElementById('mobileNumber').value;
    const otp = document.getElementById('otp').value;
    await encryptFetch('/api/otp/validate', {
      mobileNumber,
      otp,
      customerType: 'Consumer'
    });
    verifyStatus.textContent = 'Verified! Redirecting...';
    window.location.href = '/passkey/enroll';
  } catch (err) {
    verifyStatus.textContent = err.message;
  }
});
