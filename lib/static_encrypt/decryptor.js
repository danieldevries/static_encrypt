// Browser-side decryptor for static_encrypt pages.
//
// Page.script wraps this file in a function with `payload` (the encrypted
// payload) in scope, and injects it at the template's script placeholder. It finds its
// elements by data attribute, so any template works as long as it has:
//
//   [data-static-encrypt="form"]      the form; submitting it decrypts
//   [data-static-encrypt="password"]  the password input
//   [data-static-encrypt="error"]     where error messages are shown
//   [data-static-encrypt="submit"]    optional; disabled while decrypting
//
// Messages can be overridden with data attributes on the form:
// data-wrong-password-message, data-insecure-message, data-decrypting-message,
// data-decrypted-message.
//
// While decrypting, the form has aria-busy="true" and the error element shows
// the decrypting message, so templates can style that state.

const element = (name) => document.querySelector(`[data-static-encrypt="${name}"]`);

function bytes(b64) {
  if (Uint8Array.fromBase64) return Uint8Array.fromBase64(b64);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function decrypt(password) {
  const base = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: bytes(payload.salt), iterations: payload.iterations, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: bytes(payload.iv) }, key, bytes(payload.data)));
}

function reveal(plain, form) {
  if (payload.html) {
    document.open();
    document.write(new TextDecoder().decode(plain));
    document.close();
    return;
  }
  const message = document.createElement("p");
  message.textContent = form.dataset.decryptedMessage || "Decrypted successfully.";
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([plain], { type: payload.mime }));
  link.download = payload.name;
  link.textContent = "Download " + payload.name;
  form.replaceChildren(message, link);
  link.click();
}

function init() {
  const form = element("form");
  const input = element("password");
  const error = element("error");
  if (!form || !input || !error) {
    console.error('static_encrypt: the template needs [data-static-encrypt="form"], [data-static-encrypt="password"] and [data-static-encrypt="error"].');
    return;
  }
  const submit = element("submit");
  const messages = {
    wrongPassword: form.dataset.wrongPasswordMessage || "Wrong password.",
    insecure: form.dataset.insecureMessage || "This page must be opened over HTTPS to decrypt.",
    decrypting: form.dataset.decryptingMessage || "Decrypting…"
  };
  const insecure = !window.isSecureContext || !window.crypto?.subtle;
  let busy = false;

  const setBusy = (value) => {
    busy = value;
    if (submit) submit.disabled = value;
    if (value) form.setAttribute("aria-busy", "true");
    else form.removeAttribute("aria-busy");
  };
  const fail = (text) => {
    error.textContent = text;
    setBusy(false);
  };

  if (insecure) {
    error.textContent = messages.insecure;
    if (submit) submit.disabled = true;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (insecure || busy) return;
    setBusy(true);
    error.textContent = messages.decrypting;

    let plain;
    try {
      plain = await decrypt(input.value);
    } catch (e) {
      // AES-GCM reports a failed authentication check as OperationError.
      fail(e.name === "OperationError" ? messages.wrongPassword : "Could not decrypt: " + e.message);
      return;
    }

    // The password was right; anything failing from here is about showing the result.
    try {
      error.textContent = "";
      reveal(plain, form);
      form.removeAttribute("aria-busy");
    } catch (e) {
      fail("Decrypted, but could not show the result: " + e.message);
    }
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}

