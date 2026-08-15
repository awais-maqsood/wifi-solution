"""Step 2 — select wireless interface."""

from __future__ import annotations

from typing import Any

import customtkinter as ctk

from app.ui.widgets import PageBase


class InterfacePage(PageBase):
    title = "2. Interface"

    def __init__(self, master: Any, app: Any) -> None:
        super().__init__(master, app)

        ctk.CTkLabel(
            self,
            text="Wireless interface",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", pady=(0, 8))

        ctk.CTkLabel(
            self,
            text="Select the Wi-Fi adapter that supports monitor mode and injection.",
            text_color="gray70",
            wraplength=640,
            justify="left",
        ).pack(anchor="w", pady=(0, 16))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, 8))

        ctk.CTkButton(btn_row, text="Refresh", width=100, command=self.refresh).pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(
            btn_row,
            text="Bring up adapter",
            width=140,
            command=self.bring_up,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row,
            text="Open Drivers",
            width=120,
            command=lambda: app.goto_step(0),
        ).pack(side="left", padx=(0, 8))
        self.status = ctk.CTkLabel(btn_row, text="", text_color="gray70")
        self.status.pack(side="left")

        self.hint = ctk.CTkLabel(
            self,
            text="",
            text_color="#c9a227",
            wraplength=640,
            justify="left",
        )
        self.hint.pack(anchor="w", pady=(0, 8))

        self.listbox = ctk.CTkScrollableFrame(self, height=220)
        self.listbox.pack(fill="both", expand=True, pady=(8, 8))

        self._selected = ctk.StringVar(value="")

        action = ctk.CTkFrame(self, fg_color="transparent")
        action.pack(fill="x", pady=(8, 0))
        ctk.CTkButton(
            action, text="Use selected →", command=self.use_selected
        ).pack(side="right")

    def on_show(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        for child in self.listbox.winfo_children():
            child.destroy()
        self.hint.configure(text="")
        self._selected.set("")

        try:
            probe = self.app.service.probe_adapter_status()
            ifaces = probe["ifaces"]
        except Exception as exc:
            self.status.configure(text=str(exc))
            self.app.log(f"Interface list error: {exc}")
            return

        if ifaces:
            self.status.configure(text=f"{len(ifaces)} interface(s)")
            current = self.app.session.interface or self.app.session.monitor_interface or ""
            for name in ifaces:
                row = ctk.CTkFrame(self.listbox, fg_color=("gray90", "gray20"))
                row.pack(fill="x", pady=4, padx=4)
                rb = ctk.CTkRadioButton(
                    row,
                    text=name,
                    variable=self._selected,
                    value=name,
                )
                rb.pack(side="left", padx=12, pady=10)
                if name == current or (not current and not self._selected.get()):
                    self._selected.set(name)
            return

        # No iface — explain USB vs network interface clearly
        self.status.configure(text="No wireless interfaces found")
        if probe["has_usb"]:
            usb_short = "; ".join(probe["usb"][:2])
            mods = ", ".join(probe["modules"]) or "none of 8188eu/8192eu loaded"
            msg = (
                f"USB Wi-Fi is plugged in ({usb_short}), but Linux has not created "
                f"a network interface (wlan0) yet. Loaded modules: {mods}. "
                "Click Bring up adapter, or Drivers → Install recommended → "
                "Blacklist + reload → unplug/replug the stick."
            )
            self.hint.configure(text=msg)
            self.app.log(
                "USB Wi-Fi detected but no wlan iface. "
                f"USB={len(probe['usb'])} modules={probe['modules'] or []}"
            )
            for line in probe["usb"]:
                row = ctk.CTkFrame(self.listbox, fg_color=("gray90", "gray20"))
                row.pack(fill="x", pady=4, padx=4)
                ctk.CTkLabel(
                    row,
                    text=f"(no iface)  {line[:90]}",
                    text_color="gray70",
                    anchor="w",
                ).pack(side="left", padx=12, pady=10)
        else:
            self.hint.configure(
                text=(
                    "No wireless USB adapter seen in lsusb. Plug in the dongle "
                    "(VirtualBox: Devices → USB → attach the Realtek/TP-Link stick), "
                    "then Refresh."
                )
            )
            self.app.log("No wireless USB devices and no wlan interfaces found.")

    def bring_up(self) -> None:
        self.status.configure(text="Trying modprobe / rfkill…")
        self.app.log("Bring up adapter: rfkill + modprobe common Wi-Fi drivers…")

        def _worker() -> None:
            try:
                notes = self.app.service.try_bring_up_wifi()
                for n in notes:
                    self.app.log(n)
            except Exception as exc:
                self.app.log(f"Bring up failed: {exc}")
            self.ui(self.refresh)

        import threading

        threading.Thread(target=_worker, daemon=True).start()

    def use_selected(self) -> None:
        name = self._selected.get().strip()
        if not name:
            self.app.log("Select an interface first.")
            return
        self.app.session.interface = name
        # If user picked a monitor iface, keep it as monitor
        if name.endswith("mon"):
            self.app.session.monitor_interface = name
        self.app.log(f"Selected interface: {name}")
        self.app.set_status(f"Interface: {name}")
        self.app.goto_step(2)
