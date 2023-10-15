export function utf8(string) {
  return new TextEncoder().encode(string);
}

export function base64(bytes) {
  return btoa(String.fromCodePoint(...new Uint8Array(bytes)));
}

export function base64url(bytes) {
  return base64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export function bytes(base64) {
  return Uint8Array.from(
    atob(base64.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.codePointAt(0)
  );
}

export function jwk(attestation) {
  const data = new Uint8Array(cbor.decode(attestation).authData);
  const view = new DataView(new ArrayBuffer(2));
  data.slice(53, 55).forEach((value, i) => view.setUint8(i, value));
  const length = view.getUint16();
  const publicKeyBytes = data.slice(55 + length);
  const key = cbor.decode(publicKeyBytes);
  if (key.get(1) == 2 || key.get(3) == -7 || key.get(-1) == 1) {
    return {
      kty: "EC",
      crv: "P-256",
      x: base64url(key.get(-2)),
      y: base64url(key.get(-3)),
    };
  }
}

export function p1363(der) {
  const parsed = KJUR.crypto.ECDSA.parseSigHexInHexRS(hex(der));
  const fix = (h) => {
    const b = bytes(h);
    return b.at(0) == 0 ? b.slice(1, 33) : b.slice(0, 32);
  };
  return new Uint8Array([...fix(parsed.r), ...fix(parsed.s)]);
  function hex(bytes) {
    return Array.from(new Uint8Array(bytes), function (byte) {
      return ("0" + (byte & 0xff).toString(16)).slice(-2);
    }).join("");
  }
  function bytes(hex) {
    const bytes = [];
    for (let c = 0; c < hex.length; c += 2)
      bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
  }
}
