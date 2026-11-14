import type { Metadata } from "next";
import AegisLanding from "@/components/landing/aegis-landing";

export const metadata: Metadata = {
  title: "Project Aegis: Commit clean. Leak nothing.",
  description:
    "Scans staged diffs with 27 token signatures and Shannon entropy, streams repository scans through the GitHub REST API, and traces links with SSRF-safe redirect checks.",
};

export default function HomePage() {
  return <AegisLanding />;
}
