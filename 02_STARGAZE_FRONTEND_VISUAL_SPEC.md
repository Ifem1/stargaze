# STARGAZE — FRONTEND VISUAL SPEC

## 1. Design goal
Stargaze must look premium, modern, and distinctive. It must not look plain, boring, or like a generic crypto dashboard.

The user has explicitly rejected:
- dull flat colors
- peach backgrounds
- black flat backgrounds
- excessive decorative icons or emojis everywhere
- overly dramatic cosmic art in every section

## 2. Core visual identity
Theme name: **Velvet Nebula**

Use a controlled dark-pink / magenta gradient system with rose-gold accents and rare silver spark details.

### Background direction
The main background should be a layered gradient, inspired by the reference image provided by the user:
- dark magenta base
- brighter pink bloom zones
- deeper plum / wine edges
- smooth gradient transitions
- no flat fill
- no overly busy space scene

This should feel luminous and premium, not noisy.

### Accent colors
Use approximately:
- background deep plum / wine / magenta spectrum
- highlight pink / fuchsia bloom
- primary accent: rose-gold / warm gold
- secondary accent: soft silver
- primary text: warm off-white
- secondary text: muted pink-gray / pale lavender-gray
- success: refined sage / emerald
- warning: amber / coral
- danger / blocked: crimson-coral

## 3. Motion
Include subtle motion only:
- slow ambient gradient drift
- sparse tiny gold/silver sparkles passing every now and then
- occasional faint streak, very infrequent
- hover glow on cards
- smooth card lift on hover
- reduced-motion support

The background must not be as dramatic as a full nebula illustration covering everything. Keep it clean.

## 4. Layout
Use a standard application layout:
- left sidebar on desktop
- top bar / header with context and wallet
- responsive mobile nav drawer

Core pages:
- Overview
- Release Registry
- Register Release
- Advisory Intelligence
- Release Lineage
- Authorization Gate
- Documentation

## 5. Logo / favicon
Do NOT use a busy icon set or many decorative symbols.
The logo should be custom and minimal.

Requirement:
- use a star shape with an `S` incorporated somewhere
- refined and modern, not childish
- suitable as both favicon and sidebar logo mark

## 6. Cards
Cards are important. They must:
- use subtle translucent or darkened panel surfaces
- have refined borders
- glow softly on hover
- animate with slight elevation on hover
- avoid clutter and oversized iconography

Use icons sparingly and only where they improve scanability.
Do NOT scatter large emojis or icons everywhere.

## 7. Wallet UX
Global wallet behavior:
- button when disconnected
- connected state shows shortened address
- clicking it opens a popover with:
  - Copy address
  - View in Explorer
  - Disconnect
- wrong network state shows a clear badge/button
- clicking wrong network triggers supported switch flow to Studionet 61999

## 8. Network presentation
Show current network clearly but elegantly.
Avoid raw technical clutter. Example:
- `Studionet`
- `Chain 61999`
- optional explorer link

## 9. Data presentation
Use real tables/cards with strong hierarchy:
- release name + version
- advisory id
- verdict class
- authorization status
- updated time
- predecessor/successor relation

No fake numeric hero stats. If no data exists, show polished empty states.

## 10. Transaction UX
Provide a proper transaction drawer or modal showing:
- wallet action initiated
- transaction hash
- pending
- accepted / finalized
- execution success / failure
- explorer link

Do not treat a hash alone as success.

## 11. Accessibility
- keyboard accessible wallet popover and menus
- clear focus states
- good contrast
- not color-only status indication
- reduced motion support

## 12. Tone
The app should feel like:
> a luxury release observatory for software risk intelligence

Not like:
- a gaming page
- a meme crypto page
- a busy sci-fi poster
