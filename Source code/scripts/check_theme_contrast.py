"""Check selected design-token contrast. Does not certify native accessibility or WCAG conformance."""

import json

from wfdiag.gui.theme import DARK, LIGHT


def luminance(value: str) -> float:
    components = [int(value[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in components]
    return sum(c * weight for c, weight in zip(linear, (0.2126, 0.7152, 0.0722), strict=True))


def contrast(first: str, second: str) -> float:
    high, low = sorted((luminance(first), luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def observations() -> list[dict[str, object]]:
    rows = []
    for name, theme in (("Light", LIGHT), ("Dark", DARK)):
        for background in ("background", "surface", "raised"):
            for role, threshold in (
                ("text", 4.5),
                ("secondary", 4.5),
                ("warning", 4.5),
                ("accent", 4.5),
                ("focus", 3.0),
                ("control_border", 3.0),
            ):
                foreground = getattr(theme, role)
                backdrop = getattr(theme, background)
                ratio = contrast(foreground, backdrop)
                rows.append(
                    {
                        "theme": name,
                        "role": role,
                        "background_role": background,
                        "foreground": foreground,
                        "background": backdrop,
                        "contrast_ratio": ratio,
                        "required": threshold,
                        "status": "pass" if ratio >= threshold else "fail",
                    }
                )
        ratio = contrast(theme.accent_text, theme.accent)
        rows.append(
            {
                "theme": name,
                "role": "primary_button_text",
                "background_role": "accent",
                "foreground": theme.accent_text,
                "background": theme.accent,
                "contrast_ratio": ratio,
                "required": 4.5,
                "status": "pass" if ratio >= 4.5 else "fail",
            }
        )
    return rows


def main() -> int:
    rows = observations()
    print(
        json.dumps(
            {
                "kind": "selected source sRGB tokens only",
                "pairs": rows,
                "native_accessibility": "blocked",
                "wcag_conformance_claim": False,
            },
            indent=2,
        )
    )
    return 0 if all(row["status"] == "pass" for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
