"""Step 1 — verify / install Wi-Fi drivers for monitor + injection."""

from __future__ import annotations

from typing import Any, Optional

import customtkinter as ctk

from app.core.driver_service import AdapterInfo, DriverProfile, DriverReport, DriverService
from app.ui.widgets import PageBase, make_treeview, pack_tree_with_scroll


class DriversPage(PageBase):
    title = "1. Drivers"

    def __init__(self, master: Any, app: Any) -> None:
        super().__init__(master, app)
        self.drivers = DriverService(log=self.app.log)
        self._report: Optional[DriverReport] = None
        self._selected_profile: Optional[DriverProfile] = None

        ctk.CTkLabel(
            self,
            text="Wi-Fi drivers",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", pady=(0, 8))

        self.hint = ctk.CTkLabel(
            self,
            text=(
                "Lists every wireless USB adapter (any brand). "
                "Known chipsets get a one-click install (apt DKMS or git DKMS)."
            ),
            text_color="gray70",
            wraplength=640,
            justify="left",
        )
        self.hint.pack(anchor="w", pady=(0, 12))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, 8))
        ctk.CTkButton(btn_row, text="Verify adapters", width=140, command=self.verify).pack(
            side="left", padx=(0, 8)
        )
        self.btn_install = ctk.CTkButton(
            btn_row,
            text="Install recommended",
            width=160,
            command=self.install_selected,
            state="disabled",
        )
        self.btn_install.pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row,
            text="Blacklist + reload",
            width=140,
            command=self.blacklist_reload,
            state="normal",
        ).pack(side="left", padx=(0, 8))

        self.status = ctk.CTkLabel(self, text="Click Verify adapters", text_color="gray70")
        self.status.pack(anchor="w", pady=(0, 8))

        table_frame = ctk.CTkFrame(self, fg_color="transparent")
        table_frame.pack(fill="both", expand=True, pady=4)

        self.tree = make_treeview(
            table_frame,
            [
                ("usb_ids", "USB ID", 100),
                ("iface", "Iface", 90),
                ("driver", "Driver", 90),
                ("chipset", "Device / chipset", 220),
                ("status", "Status", 100),
                ("package", "Install", 140),
            ],
            height=7,
        )
        pack_tree_with_scroll(self.tree, table_frame)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self.detail = ctk.CTkTextbox(self, height=120)
        self.detail.pack(fill="x", pady=(8, 8))

        nav = ctk.CTkFrame(self, fg_color="transparent")
        nav.pack(fill="x")
        ctk.CTkButton(
            nav, text="Continue → Interface", width=180, command=lambda: app.goto_step(1)
        ).pack(side="right")

    def on_show(self) -> None:
        if self._report is None:
            self.verify()

    def verify(self) -> None:
        if getattr(self, "_verifying", False):
            self.app.log("Verify already running…")
            return
        self._verifying = True
        self.status.configure(text="Verifying… (background)")
        self.app.log("Verifying Wi-Fi adapters / drivers…")
        self.btn_install.configure(state="disabled")

        def _worker() -> None:
            try:
                report = self.drivers.verify()
                self.ui(self._apply_report, report, None)
            except Exception as exc:
                self.ui(self._apply_report, None, str(exc))

        import threading

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_report(self, report: Optional[DriverReport], error: Optional[str]) -> None:
        self._verifying = False
        if error:
            self.app.log(f"Verify failed: {error}")
            self.status.configure(text=error)
            return
        assert report is not None
        self._report = report
        self._fill_table(report)
        self._update_hint(report)
        needs = [a for a in report.adapters if a.status == "needs_driver"]
        if needs:
            self.status.configure(
                text=f"{len(needs)} adapter(s) need a better driver — select a row and Install."
            )
            self.btn_install.configure(state="normal")
        elif report.adapters:
            self.status.configure(text="Adapters look OK for monitor/injection.")
            self.btn_install.configure(state="disabled")
        else:
            self.status.configure(text="No wireless adapters found. Plug in USB Wi-Fi.")
            self.btn_install.configure(state="disabled")

        self.detail.delete("1.0", "end")
        self.detail.insert(
            "end",
            f"Kernel: {report.kernel}\nRoot: {report.is_root}\n\n"
            "lsusb (wireless-related):\n"
            + "\n".join(
                ln
                for ln in report.lsusb.splitlines()
                if any(
                    k in ln.lower()
                    for k in ("wireless", "802.11", "realtek", "ralink", "atheros", "0bda:", "2357:")
                )
            )
            or report.lsusb[:500],
        )

    def _update_hint(self, report: DriverReport) -> None:
        base = (
            "Lists every wireless USB adapter (any brand). "
            "Known chipsets get a one-click install (apt DKMS or git DKMS)."
        )
        tips: list[str] = []
        seen: set[str] = set()
        for ad in report.adapters:
            if not ad.profile or ad.profile.id in seen:
                continue
            if ad.status != "needs_driver":
                continue
            seen.add(ad.profile.id)
            label = ad.profile.label.split("(")[0].strip()
            install = ad.profile.install_label
            if ad.iface.startswith("(") or not ad.iface:
                tips.append(
                    f"Detected {label} ({ad.usb_ids or 'USB'}) — no network iface yet; "
                    f"install {install}, then unplug/replug."
                )
            else:
                tips.append(f"Detected {label} — install {install}.")
        if not report.adapters:
            tips.append("No wireless USB adapters found. Plug in a Wi-Fi dongle and Verify.")
        self.hint.configure(text=base + (" " + " ".join(tips) if tips else ""))

    def _fill_table(self, report: DriverReport) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for ad in report.adapters:
            pkg = ad.profile.install_label if ad.profile else "—"
            self.tree.insert(
                "",
                "end",
                values=(
                    ad.usb_ids or "—",
                    ad.iface or "—",
                    ad.driver or "—",
                    (ad.chipset or "—")[:48],
                    ad.status,
                    pkg,
                ),
                tags=(ad.status,),
            )
        try:
            self.tree.tag_configure("ok", foreground="#3cb371")
            self.tree.tag_configure("needs_driver", foreground="#e0a800")
            self.tree.tag_configure("unknown", foreground="#aaa")
        except Exception:
            pass

    def _on_select(self, _event: Any = None) -> None:
        sel = self.tree.selection()
        if not sel or not self._report:
            return
        vals = self.tree.item(sel[0], "values")
        usb_id = vals[0]
        iface = vals[1]
        ad: Optional[AdapterInfo] = None
        for a in self._report.adapters:
            if (a.usb_ids or "—") == usb_id and (a.iface or "—") == iface:
                ad = a
                break
        if not ad and self._report.adapters:
            # fallback: match usb id only
            for a in self._report.adapters:
                if (a.usb_ids or "—") == usb_id:
                    ad = a
                    break
        if not ad:
            return
        self._selected_profile = ad.profile
        self.detail.delete("1.0", "end")
        lines = [
            f"USB: {ad.usb or '—'}",
            f"USB ID: {ad.usb_ids or '—'}",
            f"Interface: {ad.iface}",
            f"Driver: {ad.driver or '—'}",
            f"Chipset: {ad.chipset or '—'}",
            f"Status: {ad.status}",
            "",
            ad.detail,
        ]
        if ad.profile:
            lines += [
                "",
                f"Install: {ad.profile.install_label}",
                f"Module: {ad.profile.good_module}",
                f"Blacklist: {', '.join(ad.profile.blacklist_modules) or '(none)'}",
            ]
            if ad.profile.git_url:
                lines.append(f"Source: {ad.profile.git_url}")
            self.btn_install.configure(state="normal")
        else:
            self.btn_install.configure(state="disabled")
        self.detail.insert("end", "\n".join(lines))

    def install_selected(self) -> None:
        prof = self._selected_profile
        if not prof and self._report:
            # Prefer first needs_driver profile
            for ad in self._report.adapters:
                if ad.status == "needs_driver" and ad.profile:
                    prof = ad.profile
                    break
        if not prof:
            self.app.log("Select an adapter that has a recommended package.")
            return
        if self.drivers.installing:
            self.app.log("Install already in progress…")
            return
        self.btn_install.configure(state="disabled")
        self.status.configure(text=f"Installing {prof.install_label}… (see log)")
        self.app.log(f"Installing driver: {prof.install_label}")

        def _done(code: int) -> None:
            self.ui(self._install_done, code)

        self.drivers.install_profile(prof, on_done=_done)

    def _install_done(self, code: int) -> None:
        self.btn_install.configure(state="normal")
        if code == 0:
            self.status.configure(
                text="Install finished — unplug/replug adapter (or reboot), then Verify."
            )
        else:
            self.status.configure(text=f"Install failed (exit {code}). See log.")
        self.verify()

    def blacklist_reload(self) -> None:
        prof = self._selected_profile
        if not prof and self._report:
            for ad in self._report.adapters:
                if ad.profile:
                    prof = ad.profile
                    break
        if not prof:
            self.app.log("Select an adapter first.")
            return
        try:
            self.drivers.ensure_blacklist(prof.blacklist_modules)
            self.drivers.reload_modules(prof)
            self.app.log("Blacklist written and modules reloaded. Replug USB, then Verify.")
            self.verify()
        except Exception as exc:
            self.app.log(str(exc))
