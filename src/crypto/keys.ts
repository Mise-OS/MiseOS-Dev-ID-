import { createPublicKey, type KeyObject } from "node:crypto";
export function loadPublicKey(publicKeyDer: string): KeyObject {
  const bytes = Buffer.from(publicKeyDer, "base64");
  if (!bytes.length) throw new Error("Empty public key");
  return createPublicKey({ key: bytes, format: "der", type: "spki" });
}
