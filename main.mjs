import { create, sign, verify } from "./webauthnsig.mjs";
import { base64, bytes, utf8 } from "./encoding.mjs";

ui.create.onclick = async (event) => {
  event.preventDefault();
  const { id, key, attestation } = await create();
  ui.key.value = JSON.stringify(key);
  ui.attestation.value = attestation ? JSON.stringify(attestation) : "";
  ui.id.value = base64(id);
  render();
};

ui.sign.onclick = async (event) => {
  event.preventDefault();
  const data = bytes(ui.data.value);
  const id = bytes(ui.id.value);
  ui.signature.value = JSON.stringify(await sign(id, data));
  await render();
};

onload =
  ui.data.onkeyup =
  ui.data.onchange =
  ui.data.onpaste =
  ui.signature.onkeyup =
  ui.signature.onchange =
  ui.signature.onpaste =
  ui.key.onkeyup =
  ui.key.onchange =
  ui.key.onpaste =
  ui.attestation.onkeyup =
  ui.attestation.onchange =
  ui.attestation.onpaste =
  ui.id.onkeyup =
  ui.id.onchange =
  ui.id.onpaste =
    render;

async function render() {
  const valid = "🔒 Valid";
  const invalid = "💥 Invalid";
  const verified = "✅ Verified";
  const unverified = "⛔️ Unverified";
  const encoded = "💬 Base64-encoded";
  const garbled = "⚠️ Garbled (should be base64)";
  let data;
  let key;
  try {
    data = bytes(ui.data.value);
    ui.encoded.value = encoded;
  } catch (e) {
    ui.encoded.value = garbled;
  }
  try {
    const jwk = JSON.parse(ui.key.value);
    key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );
    ui.valid.value = valid;
  } catch (e) {
    ui.valid.value = invalid;
  }
  try {
    const signature = JSON.parse(ui.signature.value);
    const verification = await verify(key, signature, data);
    ui.verified.value = verification ? verified : unverified;
  } catch (e) {
    ui.verified.value = unverified;
  }
  try {
    const id = bytes(ui.id.value);
    if (id.length == 0) {
      ui.sign.disabled = true;
    } else {
      ui.sign.disabled = false;
    }
  } catch (e) {
    ui.sign.disabled = true;
  }
}
