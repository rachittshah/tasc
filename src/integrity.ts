import { createHash } from "node:crypto";

/**
 * Serialize JSON-compatible data with object keys in lexical order.
 * Array order remains meaningful.
 */
export function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    const fields = Object.keys(object)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(object[key])}`);
    return `{${fields.join(",")}}`;
  }
  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw new Error("stableJson only accepts JSON-compatible values");
  }
  return serialized;
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
