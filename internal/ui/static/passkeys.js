// Passkeys for agentgate's web UI: enrolment on the Passkeys page, and
// signed answers on the Approvals page. The server sends WebAuthn options
// with binary fields in base64url; the browser API wants ArrayBuffers.
(function () {
  "use strict";

  function fromB64(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function toB64(buf) {
    var bytes = new Uint8Array(buf), bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function status(msg) {
    var el = document.getElementById("passkey-status");
    if (el) el.textContent = msg;
  }
  async function post(url, body) {
    var res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: body === undefined ? "" : JSON.stringify(body) });
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }

  async function enroll(form) {
    var data = await post("/passkeys/enroll/begin", { name: form.name.value, code: form.code.value });
    var pk = data.options.publicKey;
    pk.challenge = fromB64(pk.challenge);
    pk.user.id = fromB64(pk.user.id);
    (pk.excludeCredentials || []).forEach(function (c) { c.id = fromB64(c.id); });
    var cred = await navigator.credentials.create({ publicKey: pk });
    var out = {
      id: cred.id, rawId: toB64(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: toB64(cred.response.clientDataJSON),
        attestationObject: toB64(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : []
      }
    };
    var done = await post("/passkeys/enroll/finish?key=" + encodeURIComponent(data.key), out);
    status("Enrolled " + done.name + ".");
    setTimeout(function () { location.reload(); }, 600);
  }

  async function sign(url) {
    var data = await post(url + "/begin");
    var pk = data.options.publicKey;
    pk.challenge = fromB64(pk.challenge);
    (pk.allowCredentials || []).forEach(function (c) { c.id = fromB64(c.id); });
    var a = await navigator.credentials.get({ publicKey: pk });
    var out = {
      id: a.id, rawId: toB64(a.rawId), type: a.type,
      response: {
        clientDataJSON: toB64(a.response.clientDataJSON),
        authenticatorData: toB64(a.response.authenticatorData),
        signature: toB64(a.response.signature),
        userHandle: a.response.userHandle ? toB64(a.response.userHandle) : null
      }
    };
    var done = await post(url + "/finish", out);
    status("Signed by " + done.by + ".");
    if (window.htmx) htmx.trigger("#approval-list", "every 2s");
  }

  document.addEventListener("submit", function (e) {
    if (e.target.id !== "passkey-enroll") return;
    e.preventDefault();
    enroll(e.target).catch(function (err) { status(err.message); });
  });
  document.addEventListener("click", function (e) {
    var b = e.target.closest("button[data-sign]");
    if (!b) return;
    e.preventDefault();
    status("Waiting for the authenticator...");
    sign(b.getAttribute("data-sign")).catch(function (err) { status(err.message); });
  });
})();
