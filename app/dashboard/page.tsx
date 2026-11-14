import { GithubAuditor } from "@/components/dashboard/github-auditor";

export const metadata = {
  title: "Live GitHub Repository Scanner — Project Aegis",
  description:
    "Fetch a public GitHub repository through the GitHub REST API and audit its highest-risk files for exposed secrets.",
};

export default function DashboardIndexPage() {
  return <GithubAuditor />;
}
