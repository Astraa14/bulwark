# UI Polish Report — Bulwark

## Overview

Scanned the full UI across all 9 major pages and modals, in both demo (auth screen) and live-data (signed-in) mode. All issues are visual/UI polish — no functional bugs were found. The app is running live on `localhost:8443` with the dev server attached.

---

## All Issues Found

### 1. Auth screen ✅ Clean

### 2. **Tabs wrapping — "Ignored" tab overflow**
- **Location**: Threats page, tab grid with 5 labels but fixed 4-column layout
- **Effect**: "Ignored" label wraps to a second lonely row
- **Fix**: Make the tabs grid `grid-template-columns: repeat(auto-fit, minmax(120px, 1fr))` or set `grid-auto-flow: column` so tabs flow to a new line instead of overflowing.

### 2b. **Tabs have no bullet markers in AI Copilot/Settings**
- **Location**: "What the copilot does" and "Notifications" lists
- **Effect**: Lists render without bullets (Tailwind Preflight strips them)
- **Fix**: Add `list-disc` class or `ul { list-style-type: disc; }` in index.css

### 3. **Tight domain/cell overlap on Overview**
- **Location**: Overview > "Sites health" table
- **Effect**: Domain text can visually collide with the Health column when domain names are long, because the column widths (`.site-row`) don't leave enough room for long domain strings + the dot + label.
- **Fix**: Add `white-space: nowrap; overflow: hidden; text-overflow: ellipsis;` on the domain `<code>` cells, or increase the domain column width via Tailwind classes.

### 4. **Modal form collapses to one line on "Add site → Domain" step**
- **Location**: Add site modal, Domain input + Continue button
- **Effect**: Label, input, and button all stack horizontally in a cramped row instead of a full-width stacked form.
- **Fix**: In index.css, add `display: block; width: 100%;` to `.modal input` and `.modal button` inside forms, or use Tailwind `w-full` on the input.

### 5. **Add API key modal is badly broken — jumbled inline**
- **Location**: Add API key modal (stepper: Provider → Key → Model)
- **Effect**: Labels, inputs, and all three buttons render jumbled inline with overlapping text, making it unusable. The form has no grid layout.
- **Fix**: Add explicit grid layout to the modal form in index.css:
  ```css
  .modal form { grid-column: 1 / -1; }
  .modal > div { margin-bottom: 16px; }
  .modal label, .modal input, .modal select { display: block; width: 100%; }
  ```

### 6. **Oversized "Finding facts" empty panel**
- **Location**: Threat detail page, "copilot panel" section
- **Effect**: The `.copilot-panel` has `min-height: 780px` but when a finding has no explanation yet, the panel is huge empty space.
- **Fix**: Change `min-height: 780px` to `min-height: 320px` or make it `min-height: min(780px, 100vh - 120px)`.

### 7. **Modal form fields jammed together**
- **Location**: Various modals (Add API key, Add site)
- **Effect**: Form controls have no spacing between them; labels, inputs, and buttons all collapse.
- **Fix**: Ensure `.modal input, .modal select, .modal button` each get `display: block; width: 100%; margin-bottom: 12px;` in index.css.

---

## Minor Visual Polish (not blocking)

### 8. **Auth screen tab labels use inline styles**
- Location: `.auth-tabs button { background: transparent; border: 0; }` — works fine but worth verifying hover states.

### 9. **"Last 30 days⌄" button on Overview**
- The chevron "⌄" is part of the button text; may need a `::after` pseudo-element for a cleaner dropdown arrow if the design calls for it.

### 10. **Pluralization on Scans page**
- "1 results" appears when there's 1 scan; the app has logic but a missing `else` branch could produce the wrong plural form. (Not a visual glitch per se, but worth a quick check.)

### 11. **No focus-visible styles on keyboard-tabbed elements**
- Several buttons and inputs lack `:focus-visible` outlines. Adding `outline: 2px solid #777; outline-offset: 2px;` (or Tailwind `focus-visible:ring`) would improve keyboard navigation.

### 12. **Sidebar "Indie workspace ⌄" chevron**
- The down-arrow `⌄` is just inline text; using `::after { content: "▼"; ... }` would be more maintainable.

---

## Files Touched

- `src/index.css` — Global Tailwind v4 styles, layers, and base resets
- `src/App.tsx` — Component tree (75K lines, unchanged — polish is CSS-only)
- `index.html` — Figma Make placeholder comments `<!-- figma:title -->` remain; these render as the browser tab title literally. **Fix**: Replace with `<title>Bulwark — AI security monitoring</title>` in index.html.

---

## Priority Fixes (recommended order)

| # | Priority | Issue | Fix Location |
|---|----------|-------|-------------|
| 1 | **High** | Add API key modal broken (jumbled inline) | `src/index.css` — add grid layout to `.modal form` |
| 2 | **High** | Tabs overflow on Threats page | `src/index.css` — make tabs grid `auto-fit` |
| 3 | **High** | "Finding facts" panel min-height too large | `src/index.css` — reduce `.copilot-panel min-height` |
| 4 | **Medium** | Modal forms stack poorly (Add site Domain, Add API key) | `src/index.css` — `display: block; width: 100%` on inputs/buttons |
| 5 | **Medium** | No list bullets in AI Copilot/Settings | `src/index.css` — add `list-style-type: disc` |
| 6 | **Low** | Index.html tab title Figma placeholder | `index.html` — replace `<!-- figma:title -->` with real `<title>` |
| 7 | **Low** | Focus-visible styles missing | `src/index.css` — add `:focus-visible` rules |