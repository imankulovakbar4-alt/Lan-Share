"""Reusable card container for the LAN Share desktop interface."""

import tkinter as tk
from tkinter import ttk


def create_card(parent, *, theme, scale, title=None, hint=None, pad=16):
    """Create a bordered card and return its outer and content frames."""
    px = scale
    outer = tk.Frame(parent, bg=theme.SURFACE, highlightthickness=1,
                     highlightbackground=theme.BORDER,
                     highlightcolor=theme.BORDER)
    if title:
        hdr = ttk.Frame(outer, style="Card.TFrame")
        hdr.pack(fill="x", padx=px(pad), pady=(px(11), 0))
        title_label = ttk.Label(hdr, text=title, style="CardHead.TLabel")
        title_label.pack(side="left")
        if hint:
            hint_label = ttk.Label(hdr, text=hint, style="CardMuted.TLabel")
            hint_label.pack(side="right")
            shown = [True]

            def fit_hint(event, label=title_label, hint_widget=hint_label,
                         visible=shown):
                required = (label.winfo_reqwidth() + hint_widget.winfo_reqwidth()
                            + px(2 * pad + 24))
                should_show = event.width >= required
                if should_show != visible[0]:
                    visible[0] = should_show
                    if should_show:
                        hint_widget.pack(side="right")
                    else:
                        hint_widget.pack_forget()

            outer.bind("<Configure>", fit_hint, add="+")

    content = ttk.Frame(outer, style="Card.TFrame")
    content.pack(fill="both", expand=True, padx=px(pad),
                 pady=(px(8) if title else px(pad - 2), px(pad - 2)))
    return outer, content
