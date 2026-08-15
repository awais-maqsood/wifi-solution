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
            text="Fix adapter (install driver)",
            width=200,
            command=self.bring_up,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row,
            text="Open Drivers",
            width=120,
            command=lambda: app.goto_step(0),
        ).pack(side="left", padx=(0, 8))
        self.status = ctk.CTkLabel(btn_row, text="", text_color="gray70")
        self.status.pack(side="left", padx=(8, 0))

        # Always-visible continue (list used to push the bottom button off-screen)
        self.btn_continue = ctk.CTkButton(
            btn_row,
            text="Use selected → Monitor",
            width=180,
            command=self.use_selected,
            state="disabled",
        )
        self.btn_continue.pack(side="right")

        self.hint = ctk.CTkLabel(
            self,
            text="",
            text_color="#c9a227",
            wraplength=640,
            justify="left",
        )
        self.hint.pack(anchor="w", pady=(0, 8))

        # Pin footer first so the scrollable list cannot hide it
        action = ctk.CTkFrame(self, fg_color="transparent")
        action.pack(side="bottom", fill="x", pady=(8, 0))
        ctk.CTkButton(
            action,
            text="Use selected → Monitor",
            width=200,
            command=self.use_selected,
        ).pack(side="right")
        ctk.CTkLabel(
            action,
            text="Or click 3. Monitor in the sidebar after selecting wlan0.",
            text_color="gray60",
        ).pack(side="left")

        self.listbox = ctk.CTkScrollableFrame(self, height=160)
        self.listbox.pack(fill="both", expand=True, pady=(8, 8))

        self._selected = ctk.StringVar(value="")
        self._selected.trace_add("write", self._on_selection_change)

    def _on_selection_change(self, *_args: Any) -> None:
        name = self._selected.get().strip()
        state = "normal" if name and not name.startswith("(") else "disabled"
        self.btn_continue.configure(state=state)

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
                    command=self._on_selection_change,
                )
                rb.pack(side="left", padx=12, pady=10)
                # Double-click row to continue
                row.bind("<Double-Button-1>", lambda _e, n=name: self._select_and_go(n))
                rb.bind("<Double-Button-1>", lambda _e, n=name: self._select_and_go(n))
                if name == current or (not current and not self._selected.get()):
                    self._selected.set(name)
            self._on_selection_change()
            return

        # No iface — explain USB vs network interface clearly
        self.status.configure(text="No wireless interfaces found")
        self.btn_continue.configure(state="disabled")
        if probe["has_usb"]:
            usb_short = "; ".join(probe["usb"][:2])
            mods = ", ".join(probe["modules"]) or "none of 8188eu/8192eu loaded"
            msg = (
                f"USB Wi-Fi is plugged in ({usb_short}), but Linux has not created "
                f"a network interface (wlan0) yet. Loaded modules: {mods}. "
                "Click Fix adapter (install driver) — this installs "
                "git DKMS (aircrack-ng/rtl8188eus), blacklists rtl8xxxu, and rebinds USB."
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

    def _select_and_go(self, name: str) -> None:
        self._selected.set(name)
        self.use_selected()

    def bring_up(self) -> None:
        self.status.configure(text="Installing driver / bringing up…")
        self.app.log(
            "Fix adapter: install DKMS if needed, modprobe, USB rebind…"
        )

        def _worker() -> None:
            try:
                notes = self.app.service.try_bring_up_wifi()
                for n in notes:
                    self.app.log(n)
            except Exception as exc:
                self.app.log(f"Fix adapter failed: {exc}")
            self.ui(self.refresh)

        import threading

        threading.Thread(target=_worker, daemon=True).start()

    def use_selected(self) -> None:
        name = self._selected.get().strip()
        if not name or name.startswith("("):
            self.app.log("Select an interface first (e.g. wlan0).")
            return
        self.app.session.interface = name
        # If user picked a monitor iface, keep it as monitor
        if name.endswith("mon"):
            self.app.session.monitor_interface = name
        self.app.log(f"Selected interface: {name}")
        self.app.set_status(f"Interface: {name}")
        self.app.goto_step(2)
