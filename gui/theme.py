"""Centralized color palette and theme switching for the Tkinter interface."""

class C:
    """Палитра оформления. Две темы: тёмная и светлая (монохром + один акцент для статусов).
    Все цвета интерфейса берутся отсюда; C.apply("light") переключает тему."""
    THEMES = {
        "dark": dict(
            BG="#09090b", SURFACE="#111113", SURFACE2="#18181b",
            ROW_A="#111113", ROW_B="#151518",
            HOVER="#232326", HOVER2="#2f2f34",
            BORDER="#222226", BORDER2="#33333a", SEL="#27272c",
            TEXT="#fafafa", MUTED="#a1a1aa", FAINT="#5a5a63",
            ACCENT="#fafafa", ACCENT_HI="#ffffff", INFO="#60a5fa",
            PRIMARY="#fafafa", PRIMARY_HI="#e4e4e7", PRIMARY_LO="#d4d4d8",
            PRIMARY_DIS="#27272a", ON_PRIMARY="#09090b",
            OK="#4ade80", WARN="#fbbf24",
            DANGER="#ef4444", DANGER_HI="#f87171", DANGER_LO="#dc2626",
            DANGER_DIS="#3b1d1d", DROP_HOT="#1c1c20"),
        "light": dict(
            BG="#f4f4f5", SURFACE="#ffffff", SURFACE2="#f4f4f5",
            ROW_A="#ffffff", ROW_B="#fafafa",
            HOVER="#e4e4e7", HOVER2="#d4d4d8",
            BORDER="#e4e4e7", BORDER2="#d4d4d8", SEL="#e4e4e7",
            TEXT="#09090b", MUTED="#71717a", FAINT="#a1a1aa",
            ACCENT="#09090b", ACCENT_HI="#27272a", INFO="#2563eb",
            PRIMARY="#18181b", PRIMARY_HI="#3f3f46", PRIMARY_LO="#09090b",
            PRIMARY_DIS="#d4d4d8", ON_PRIMARY="#fafafa",
            OK="#16a34a", WARN="#b45309",
            DANGER="#dc2626", DANGER_HI="#b91c1c", DANGER_LO="#b91c1c",
            DANGER_DIS="#fecaca", DROP_HOT="#ececee"),
    }

    @classmethod
    def apply(cls, name):
        for key, val in cls.THEMES.get(name, cls.THEMES["dark"]).items():
            setattr(cls, key, val)



C.apply("dark")
