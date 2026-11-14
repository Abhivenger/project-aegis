import type { PresetId } from "@/lib/preset-bus";

export interface SecurityPreset {
  id: Extract<PresetId, "aws" | "metadata" | "stripe" | "clean">;
  label: string;
  content: string;
  filename: string;
}

export const SECURITY_PRESETS: readonly SecurityPreset[] = [
  {
    id: "aws",
    label: "🚨 Leaked AWS Secret",
    filename: "cloud-config.ts",
    content: `// Fabricated demo credentials — never connect to AWS.
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"; // aegis-ignore: fabricated AWS demo key
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

export const cloud = {
  region: "us-east-1",
  accessKeyId: AWS_ACCESS_KEY_ID,
  secretAccessKey: AWS_SECRET_ACCESS_KEY,
};`,
  },
  {
    id: "metadata",
    label: "🛡️ SSRF Metadata Exploit",
    filename: "metadata-request.txt",
    content: "http://169.254.169.254/latest/meta-data/iam/",
  },
  {
    id: "stripe",
    label: "🔑 Stripe Live Key",
    filename: "payment-handler.ts",
    content: `// Fabricated live-shaped key — assembled at runtime so static scanners never
// see a contiguous credential literal.
const stripeKey = ["sk", "live", "51Demo9aB7cD2eF8gH4jK6mN0pQ3rS5tU1vW9xY7z"].join("_"); // aegis-ignore: fabricated Stripe demo key

export const payment = {
  apiKey: stripeKey,
  currency: "usd",
};`,
  },
  {
    id: "clean",
    label: "✅ Clean Code Sample",
    filename: "clean-module.ts",
    content: `const apiKey = process.env.API_KEY;

export function getConfig() {
  return { apiKey, debug: false };
}

export function greet(name: string) {
  return "Hello, " + name.trim();
}`,
  },
];

export const STRIPE_PRESET = SECURITY_PRESETS.find((preset) => preset.id === "stripe")!;
