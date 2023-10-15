import { utf8, bytes, base64url, jwk, p1363 } from "./encoding.mjs";

const PLACEHOLDER_USERNAME = "username";
const PLACEHOLDER_CREDENTIAL_RP = {
  name: "Signature example",
  id: location.hostname,
};

export async function create() {
  const publicKey = {
    challenge: new Uint8Array([]),
    rp: PLACEHOLDER_CREDENTIAL_RP,
    user: {
      id: new Uint8Array([1]),
      name: PLACEHOLDER_USERNAME,
      displayName: PLACEHOLDER_USERNAME,
    },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    timeout: 60000,
    attestation: "indirect",
  };
  const credential = await navigator.credentials.create({ publicKey });
  const key = jwk(credential.response.attestationObject);
  const obj = cbor.decode(credential.response.attestationObject);
  const attestation =
    obj.fmt == "packed"
      ? {
          cdh: base64url(
            await crypto.subtle.digest(
              "SHA-256",
              credential.response.clientDataJSON
            )
          ),
          att: base64url(credential.response.attestationObject),
        }
      : undefined;
  const id = credential.rawId;
  return { id, key, attestation };
}

export async function sign(id, data) {
  const challenge = await crypto.subtle.digest(
    "SHA-256",
    new Uint8Array([...utf8("WebAuthnSig\n"), ...data])
  );
  const publicKey = {
    challenge,
    allowCredentials: [{ id, type: "public-key" }],
    timeout: 60000,
  };
  const credential = await navigator.credentials.get({ publicKey });
  const dataLength = credential.response.authenticatorData.byteLength;
  if (dataLength == 37)
    return {
      adv: base64url(credential.response.authenticatorData),
      cds: base64url(credential.response.clientDataJSON.slice(36 + 43)),
      sig: base64url(p1363(credential.response.signature)),
    };
}

export async function verify(key, signature, data) {
  const challenge = await crypto.subtle.digest(
    "SHA-256",
    new Uint8Array([...utf8("WebAuthnSig\n"), ...data])
  );
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new Uint8Array([
      ...utf8('{"type":"webauthn.get","challenge":"'),
      ...utf8(base64url(challenge)),
      ...bytes(signature.cds),
    ])
  );
  return await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    bytes(signature.sig),
    new Uint8Array([...bytes(signature.adv), ...new Uint8Array(digest)])
  );
}
