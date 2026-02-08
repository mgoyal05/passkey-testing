const inflight = new Map();
let rsaKeyPromise;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function base64UrlEncode(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const binary = atob(base64);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function base64Encode(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function base64Decode(str) {
  const binary = atob(str);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

async function importServerKey() {
  if (rsaKeyPromise) return rsaKeyPromise;
  rsaKeyPromise = fetch('/crypto/server-pubkey')
    .then((res) => res.text())
    .then((pem) => {
      const clean = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
      const bytes = base64Decode(clean);
      return crypto.subtle.importKey(
        'spki',
        bytes,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
      );
    });
  return rsaKeyPromise;
}

async function hmac(macKey, data) {
  return new Uint8Array(await crypto.subtle.sign('HMAC', macKey, data));
}

async function aesEncrypt(aesKey, iv, plaintext) {
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, plaintext));
}

async function aesDecrypt(aesKey, iv, ciphertext) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, ciphertext));
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  arrays.forEach((arr) => {
    out.set(arr, offset);
    offset += arr.length;
  });
  return out;
}

function intToBytes(value) {
  const view = new DataView(new ArrayBuffer(4));
  view.setInt32(0, value);
  return new Uint8Array(view.buffer);
}

function longToBytes(value) {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigInt64(0, BigInt(value));
  return new Uint8Array(view.buffer);
}

export async function encryptFetch(path, payload) {
  const requestId = crypto.randomUUID();
  const ts = Date.now();
  const keyMaterial = crypto.getRandomValues(new Uint8Array(64));
  const aesKeyBytes = keyMaterial.slice(0, 32);
  const macKeyBytes = keyMaterial.slice(32, 64);
  const iv = crypto.getRandomValues(new Uint8Array(16));

  const aesKey = await crypto.subtle.importKey('raw', aesKeyBytes, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
  const macKey = await crypto.subtle.importKey('raw', macKeyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

  const plaintextBytes = encoder.encode(JSON.stringify(payload));
  const ciphertext = await aesEncrypt(aesKey, iv, plaintextBytes);
  const macData = concatBytes(
    intToBytes(1),
    encoder.encode(requestId),
    encoder.encode(path),
    longToBytes(ts),
    iv,
    ciphertext
  );
  const mac = await hmac(macKey, macData);

  const serverKey = await importServerKey();
  const wrapped = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    serverKey,
    keyMaterial
  ));

  inflight.set(requestId, { aesKey, macKey, path });

  const envelope = {
    v: 1,
    requestId,
    ts,
    path,
    ek: base64Encode(wrapped),
    iv: base64Encode(iv),
    ct: base64Encode(ciphertext),
    mac: base64Encode(mac)
  };

  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(envelope)
  });
  const data = await response.json();
  if (data && data.v === 1 && data.ct && data.iv && data.mac) {
    const decrypted = await decryptResponse(data);
    if (!response.ok) {
      const message = decrypted.error || decrypted.message || `Request failed (${response.status})`;
      const err = new Error(message);
      err.details = decrypted;
      throw err;
    }
    return decrypted;
  }
  if (!response.ok) {
    throw new Error(data.error || data.message || `Request failed (${response.status})`);
  }
  return data;
}

async function decryptResponse(envelope) {
  const context = inflight.get(envelope.requestId);
  if (!context) {
    throw new Error('Missing request context');
  }
  inflight.delete(envelope.requestId);
  const iv = base64Decode(envelope.iv);
  const ct = base64Decode(envelope.ct);
  const macData = concatBytes(
    intToBytes(envelope.v),
    encoder.encode(envelope.requestId),
    encoder.encode(context.path),
    longToBytes(envelope.ts),
    iv,
    ct
  );
  const expectedMac = await hmac(context.macKey, macData);
  const actualMac = base64Decode(envelope.mac);
  if (expectedMac.length !== actualMac.length || !expectedMac.every((v, i) => v === actualMac[i])) {
    throw new Error('Invalid response MAC');
  }
  const plaintext = await aesDecrypt(context.aesKey, iv, ct);
  return JSON.parse(decoder.decode(plaintext));
}

export function webauthnCreateOptionsToPublic(options) {
  return {
    ...options,
    challenge: base64UrlDecode(options.challenge),
    user: {
      ...options.user,
      id: base64UrlDecode(options.user.id)
    }
  };
}

export function webauthnRequestOptionsToPublic(options) {
  return {
    ...options,
    challenge: base64UrlDecode(options.challenge),
    allowCredentials: []
  };
}

export function credentialToJSON(cred) {
  return {
    id: cred.id,
    rawId: base64UrlEncode(new Uint8Array(cred.rawId)),
    type: cred.type,
    response: {
      clientDataJSON: base64UrlEncode(new Uint8Array(cred.response.clientDataJSON)),
      attestationObject: cred.response.attestationObject ? base64UrlEncode(new Uint8Array(cred.response.attestationObject)) : undefined,
      authenticatorData: cred.response.authenticatorData ? base64UrlEncode(new Uint8Array(cred.response.authenticatorData)) : undefined,
      signature: cred.response.signature ? base64UrlEncode(new Uint8Array(cred.response.signature)) : undefined,
      userHandle: cred.response.userHandle ? base64UrlEncode(new Uint8Array(cred.response.userHandle)) : null
    },
    transports: cred.response.getTransports ? cred.response.getTransports() : []
  };
}
