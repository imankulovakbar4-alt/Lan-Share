"""Reusable scrollable frame component used by GUI pages."""

import tkinter as tk
from tkinter import ttk

class ScrollFrame(ttk.Frame):
    """Прокручиваемый контейнер. Содержимое (self.inner) всегда занимает всю ширину окна
    и, если окно выше содержимого, растягивается по высоте; если не помещается —
    появляется вертикальная прокрутка (колесо мыши работает над любым местом страницы)."""

    def __init__(self, parent, bg, step=24):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0,
                                yscrollincrement=step)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = ttk.Frame(self.canvas)
        self._win = self.canvas.create_window(0, 0, window=self.inner, anchor="nw")
        self._shown = False
        self._last = (0, 0, 0)
        self.canvas.bind("<Configure>", self._fit, add="+")
        self.inner.bind("<Configure>", self._fit, add="+")
        self.after(250, self._tick)

    def _tick(self):
        """Содержимое могло вырасти/уменьшиться без события Configure (скрытая панель и т.п.)."""
        try:
            if not self.winfo_exists():
                return
            self._fit()
            self.after(250, self._tick)
        except tk.TclError:
            pass

    def _fit(self, _e=None):
        try:
            cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
            if cw < 2 or ch < 2:
                return
            req = self.inner.winfo_reqheight()
            key = (cw, ch, req)
            if key == self._last:
                return
            self._last = key
            h = max(req, ch)
            self.canvas.itemconfigure(self._win, width=cw, height=h)
            self.canvas.configure(scrollregion=(0, 0, cw, h))
            need = req > ch
            if need != self._shown:
                self._shown = need
                if need:
                    self.vsb.pack(side="right", fill="y")
                else:
                    self.vsb.pack_forget()
                    self.canvas.yview_moveto(0)
        except tk.TclError:
            pass

    def needs_scroll(self):
        return self._shown
