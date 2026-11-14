# Project Aegis Design Direction

Scope: the public marketing page only (`app/page.tsx`, `components/landing/aegis-landing.tsx`).
The dashboard console inherits this palette and typography but keeps its own information density.

Design Read: developer security landing page for engineers and security leads, in an Apple-inspired
Obsidian Glass language, dial **ENERGY 1 / RHYTHM 2 / MOTION 1**.

## 1. Identity

Aegis is an engineering instrument, not a lifestyle brand. The page should read like a control surface
someone built for their own team: near-black glass, precise hairlines, monospace measurements, and copy
that states what the code actually does. If the logo were swapped for another security tool, the page
would still be recognizable as Aegis because of the hairline-plus-telemetry motif, not because of a
gradient or a mascot.

Personality: exact, quiet, technical, unimpressed by its own features. No hype, no promises that the
code cannot back up.

## 2. Dials

| Dial | Value | What it means here |
|---|---|---|
| ENERGY | 1 | Calm surface. The working sandbox is the one loud element, and it earns the attention by running. |
| RHYTHM | 2 | Three deliberate breaks: centered hero with a live demo, asymmetric runtime-surface rows, and a pricing spec table. Everything else stays on the same hairline grid. |
| MOTION | 1 | Hover and focus transitions, plus one entrance for the live demo. No scroll-reveal on every card, no floating, no rotating decoration. |

## 3. Palette

| Role | Value | Use |
|---|---|---|
| Canvas | `#07090E` | Page background. Flat obsidian, no gradient wash, no background grid. |
| Surface | `#0C1017` | Cards and panels. One step above the canvas so hairlines stay visible. |
| Raised | `#12161F` | Menu, modal, and inset code surfaces. |
| Hairline | `rgba(255,255,255,0.08)` | Every border and divider. Exactly 1px. |
| Text primary | `#F4F4F5` (zinc-100) | Headlines and values. |
| Text secondary | `#A1A1AA` (zinc-400) | Body copy and labels. Minimum for small text on this canvas. |
| Text decorative | zinc-500/600 | Separators and non-essential glyphs only, never body copy. |
| Accent | `#67E8F9` (cyan-300) | One accent: the live demo focal point, key numbers, focus rings. |
| Verified | `#6EE7B7` (emerald-300) | Status only, never decoration. |
| Danger | `#FDA4AF` (rose-300) | Errors and blocked findings only. |

Two core colors plus one accent. Emerald is a status color, not a second brand accent. No blue-to-cyan
or purple-to-pink gradients anywhere. A single 1px top highlight on the live demo card is allowed
because it marks the focal surface, and it is the only gradient on the page.

## 4. Typography

- **Sans:** `ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`.
  Reason: a developer tool should render in the platform UI font. It loads instantly and avoids shipping
  a display face that adds no meaning.
- **Mono:** `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`. Reserved for commands,
  endpoints, thresholds, tokens, and scores. Never for headlines.
- **Numerals:** every counter, score, price, and measurement uses `tabular-nums`.
- No oversized monospace headings. No wide uppercase eyebrow labels. A short mono label is allowed when
  it names a real surface (`cli/aegis.py`, `POST /api/scan/url`), not as decoration.

## 5. Surfaces, borders, depth

- Radius scale: 8px chips, 12px controls, 16px panels. Nothing is pill-shaped except status dots.
- Hairline borders only. No colored left stripes.
- One elevation shadow on the live demo card, because it is the only element floating above the page.
- Glass (backdrop blur) on at most two elements: the live demo card and the mobile menu overlay.
- Glow on at most two elements: keyboard focus rings and the live status dot. Nothing else glows.
- No decorative blobs, orbs, conic gradients, background grids, or noise.

## 6. Layout and composition

- Content width: 1152px inside a 1280px rail. Section spacing varies (72px to 112px) so the page has
  rhythm rather than a uniform stack.
- The hero is centered because the live sandbox underneath is the focal point, and centering keeps the
  headline subordinate to the running product. This is a written reason, not an autopilot choice.
- Runtime surfaces render as asymmetric hairline rows, not three identical cards and not three numbered
  steps. The product has three real entry points: the CLI, the GitHub scan route, and the SafeLink route.
- Pricing renders as a specification table (tier, audience, what runs, price). It is not three marketing
  cards, and no tier is artificially highlighted.
- Every section exists because the product needs it. There are no testimonials, no logo bar, no FAQ, and
  no fabricated trust badges.

## 7. Copy rules

- Engineering voice. Prefer a command, an endpoint, a threshold, or a file path over an adjective.
- Ban list: Supercharge, Revolutionary, Next-Gen, Next Generation, AI-Powered, Seamless, Effortless,
  Cutting Edge, Ultimate, Powerful, Intelligent, zero-trust, mission-critical, world-class, unlock,
  empower, elevate, transform, calm, "built for teams that ship".
- No em dash characters in UI text. Use commas, periods, colons, or parentheses.
- No unmeasured numbers. Every number must trace to a file in this repository.
- No security, compliance, performance, or customer claim without evidence. Specifically, do not claim
  PR blocking, SOC 2, ISO 27001, uptime percentages, customer counts, or LLM gateways.
- CTAs name the destination: "Open the dashboard", "Open the code sandbox", "Open SafeLink". Never
  "Get Started", "Learn More", "Explore", or "Discover".
- Demo pricing is labeled as demo pricing. Checkout is simulated.

## 8. Verifiable facts allowed on the page

| Claim | Source |
|---|---|
| 27 token signatures | `lib/scanners/regex-patterns.ts` |
| Generic entropy threshold `H >= 4.55` | `lib/scanners/entropy.ts` |
| 20 highest-risk files per repository scan, 100 KB per file cap | `lib/scanners/github-auditor.ts` |
| NDJSON progress stream from the GitHub scan route | `app/api/scan/github/route.ts` |
| SafeLink validates each hop, max 5 hops, 3.5s per probe | `lib/scanners/url-analyzer.ts` |
| Blocks private, loopback, and cloud metadata addresses | `lib/scanners/ip-ranges.ts` |
| Zero-dependency Python CLI with `--install`, `--fix`, `--export` | `cli/aegis.py` |
| Honors lockfiles and inline `aegis-ignore` markers | `cli/aegis.py` |
| Free dashboard quota is 50 scans per day | `lib/quota-store.ts` |

If a fact is not in this table, it does not go on the page until it is verified and added here.

## 9. Interaction and accessibility

- Every control is a native `<a href>` or `<button>` with a real destination or visible feedback.
- Minimum 44px tap target on mobile. `cursor-pointer` on enabled controls, `cursor-not-allowed` on
  disabled ones.
- Visible `focus-visible` ring on every interactive element. No `outline: none` without a replacement.
- The sandbox keeps three states: empty prompt, loading message, and error message.
- Motion respects `prefers-reduced-motion` through `MotionConfig reducedMotion="user"`.
- Icons must denote something real. GitHub for the repository surface, Terminal for the CLI, Globe for
  SafeLink, Shield for the pre-commit guard. No sparkle, star, magic, lightning, or robot glyphs.

## 10. Decision log

- **Obsidian canvas, not white:** the product is a terminal-adjacent security tool used for long
  sessions; dark is a working condition, not a fashion choice.
- **Hairlines at 1px, not shadows:** the interface is a spec sheet, and hairlines separate data without
  adding weight.
- **Mono for measurements, sans for prose:** numbers are data; sentences are human.
- **One accent, one status color:** cyan marks the live surface; emerald confirms a clean result.
- **No CTA arrows:** destination verbs carry the action. Chevrons appear only between pipeline stages in
  the GitHub scan diagram, where they denote sequence.
- **Pricing as a table:** the product has three real tiers, but a table states the difference faster
  than three identical cards.
- **No decorative glow or orbs:** the only things that glow are focus and status, both functional.
- **Centered hero:** the running sandbox is the argument; the headline introduces it.
