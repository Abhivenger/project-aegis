import type { Metadata } from "next";
import { DM_Sans, DM_Serif_Display } from "next/font/google";
import AegisLanding from "@/components/landing/aegis-landing";

const dmSans = DM_Sans({
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
  variable: "--font-dm-sans",
  display: "swap",
});

const dmSerif = DM_Serif_Display({
  subsets: ["latin"],
  weight: ["400"],
  style: ["normal", "italic"],
  variable: "--font-dm-serif",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Project Aegis: Stop credential leaks before git push.",
  description:
    "Sub-millisecond Shannon entropy analysis, live GitHub repository auditing, and pre-commit defense. Built with Next.js 15, TypeScript, and Python.",
};

export default function HomePage() {
  return (
    <div className={`${dmSans.variable} ${dmSerif.variable}`}>
      <AegisLanding />
    </div>
  );
}
