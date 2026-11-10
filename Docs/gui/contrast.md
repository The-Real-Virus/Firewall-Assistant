# Selected source contrast observations

The5 November source audit found six failures when the original decorative border colors also
identified interactive controls. Light borders measured1.319–1.485:1 and Dark1.548–1.903:1
against selected page/surface/raised backgrounds, below the specified3:1 control threshold.
The failed baseline log is preserved; this is an observed source defect, not a passed baseline.

Separate control borders now use Light#7A879B and Dark#6B7F9E. Their lowest selected ratios are
3.2354967475:1 and3.7373085813:1 respectively. Decorative panels/grid separators retain the
approved original colors. Native subcontrol palette roles use the control border; fields,
tables, lists, secondary buttons and author-link controls have explicit distinguishable edges.
Specific focus selectors prevent primary/nav styles from hiding the generic focus rule. Primary
focus has a contrasting dashed inner border; navigation uses the existing focus color.

scripts/check_theme_contrast.py checks38 selected sRGB pairs: normal/secondary/warning/accent
text against page/surface/raised backgrounds at4.5:1; focus/control outlines at3:1; primary text
against its accent at4.5:1. Decisions compare full values, without rounding a failure into pass.
Black/white21:1, equal-color1:1, symmetry and both-theme budgets have regression checks. The
actual numeric source results and theme digest are in contrast-20261105.json. Local quality now
includes this check. This limited token matrix is not a general WCAG conformance claim.

The method uses the W3C sRGB relative-luminance formula and contrast ratio; thresholds follow
the source build requirements and corresponding guidance:
[relative luminance](https://www.w3.org/TR/WCAG22/#dfn-relative-luminance),
[contrast ratio](https://www.w3.org/TR/WCAG22/#dfn-contrast-ratio),
[text contrast](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html),
[non-text contrast](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html).
These selected source checks do not certify a screen, OS or assistive technology.

All71 GUI source tests passed after the fix. Six actual engine-backed synthetic Qt offscreen
captures were inspected: focused primary Light/Dark, focused compact navigation Dark, policy
Light/compact Dark and source provenance compact Dark. The focus targets reported actual Qt
focus. A first private capture helper stalled because its selector omitted the shortcut marker;
it was interrupted and its exact task-owned process cleanup verified, with no unrelated process
termination. A quoting/missing-file retry also failed and was retained. The corrected callback
has explicit failure handling and20s watchdog, exited0 and produced the inspected set.

Native keyboard traversal, focus visibility with real Windows rendering, Narrator, high contrast,
large text,100/125/150/200%/mixed-monitor DPI and resource budgets remain blocked until authorized
target tests. Source captures neither invoke app.main/private startup nor collect/send anything.
Later package results must identify whether they include this theme revision; older evaluations
remain unchanged and do not implicitly acquire a newer fix.
