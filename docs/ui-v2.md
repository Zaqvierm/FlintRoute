# UI v2 truthfulness and responsive shell

This note describes the current UI work on the remediation branch. It is
intentionally bound to a commit when the change is committed; local edits are
not hardware evidence.

## Truthfulness rules

- First-run completion is stored in the backend `onboarding` bbolt bucket.
  Browser `localStorage` may remember the last screen and UI preferences, but
  it cannot claim that a route, source, or ChangeSet was applied.
- Hidden privacy mode is the default. Topology and device requests use the
  hidden API variant, old entity state is cleared during a reveal-to-hidden
  transition, and an explicit reveal automatically expires after ten minutes.
- A failed slice does not cancel the other dashboard slices. The alert center
  identifies the unavailable slice and permits a retry; object fallbacks are
  marked stale rather than presented as a fresh health proof.
- Service categories are exhaustive. `TELEGRAM`, `DIRECT_PREFERRED`, and
  future/unknown values do not silently become Direct; unknown values stay in
  `Не определено`.
- A service edit creates a draft ChangeSet and opens the operation/developer
  review screen. It does not validate/apply/confirm dataplane changes from a
  single card click.

## Navigation and responsive modes

The shell has five desktop sections: Overview, Network, Rules, Activity, and
System. Screen selection is reflected in a shareable `?screen=` URL and browser
Back/Forward updates the active screen. An unknown URL renders a local “page not
found” state instead of silently opening Overview.

On phones the shell uses four primary bottom-navigation actions plus an “Ещё”
sheet. The bar is attached to the viewport (not the zero-height side rail), so
it remains reachable at 360–430 px. On compact/tablet widths the side rail is
narrow and the topology is a vertical grouped view; the desktop canvas is not
forced into a horizontally scrolling mobile viewport. Desktop keeps the
detailed canvas and caps its readable width on ultrawide screens. Decorative
packet and wire animations were removed: a line is not evidence of traffic.

The Activity section has a separate Operation Center. Component, VLESS,
Zapret, Smart DNS, External SOCKS and service edits create a draft and link to
that center; they do not validate/apply/confirm a dataplane change from a card
click. `Advanced` keeps the developer JSON editor behind its own disclosure.

Browser coverage lives in `tests/browser`: deterministic API fixtures cover
privacy purge, partial API failure, navigation/back-forward and a ten-viewport
matrix (360×800 through 3840×2160). The fixture is test-only and is never
enabled by the production build.

## Scope and limits

This is a progressive-disclosure foundation, not a production-readiness claim.
The full feature-local frontend split and Linux or hardware evidence remain
separate gates. Playwright Chromium passes locally when the browser binary is
installed; its CI job remains the authoritative repeatable gate. Hardware is
deliberately not touched by the UI work.
