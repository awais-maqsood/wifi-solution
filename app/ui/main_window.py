"""Main application window."""

from __future__ import annotations

import customtkinter as ctk

from app.core.aircrack_service import AircrackService
from app.core.state import SessionState
from app.ui.pages.capture_page import CapturePage
from app.ui.pages.crack_page import CrackPage
from app.ui.pages.drivers_page import DriversPage
from app.ui.pages.interface_page import InterfacePage
from app.ui.pages.monitor_page import MonitorPage
from app.ui.pages.scan_page import ScanPage
from app.ui.pages.target_page import TargetPage

STEPS = [
    "Drivers",
    "Interface",
    "Monitor",
    "Scan",
    "Target",
    "Capture",
    "Crack",
]


class MainWindow(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("Aircrack-ng GUI Wrapper")
        self.geometry("1100x720")
        self.minsize(900, 600)

        self.session = SessionState()
        self.service = AircrackService(self.session, log=self.log)

        self._step = 0
        self._step_buttons: list[ctk.CTkButton] = []
        self._pages: list[ctk.CTkFrame] = []

        self._build_layout()
        self._show_legal_banner()
        self._check_environment()
        self.goto_step(0)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------------------------------------------------------- layout
    def _build_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Top banners
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=0, column=0, columnspan=2, sticky="ew", padx=12, pady=(12, 0))
        top.grid_columnconfigure(0, weight=1)

        self.root_banner = ctk.CTkLabel(
            top,
            text="",
            anchor="w",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self.root_banner.grid(row=0, column=0, columnspan=2, sticky="ew")

        tool_row = ctk.CTkFrame(top, fg_color="transparent")
        tool_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        tool_row.grid_columnconfigure(0, weight=1)

        self.tool_banner = ctk.CTkLabel(
            tool_row,
            text="",
            anchor="w",
            text_color="#c04040",
            wraplength=780,
            justify="left",
        )
        self.tool_banner.grid(row=0, column=0, sticky="ew")

        self.btn_install_tools = ctk.CTkButton(
            tool_row,
            text="Install aircrack-ng",
            width=160,
            fg_color="#8B3A3A",
            hover_color="#6e2e2e",
            command=self._install_aircrack_tools,
        )
        # Hidden until missing tools are detected
        self.btn_install_tools.grid(row=0, column=1, padx=(8, 0))
        self.btn_install_tools.grid_remove()

        # Left nav
        nav = ctk.CTkFrame(self, width=190, corner_radius=8)
        nav.grid(row=1, column=0, sticky="nsw", padx=(12, 8), pady=12)
        nav.grid_propagate(False)

        ctk.CTkLabel(
            nav,
            text="Steps",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(12, 8))

        for idx, name in enumerate(STEPS):
            btn = ctk.CTkButton(
                nav,
                text=f"{idx + 1}. {name}",
                anchor="w",
                fg_color="transparent",
                command=lambda i=idx: self.goto_step(i),
            )
            btn.pack(fill="x", padx=8, pady=3)
            self._step_buttons.append(btn)

        ctk.CTkButton(
            nav,
            text="Stop all",
            fg_color="#8B3A3A",
            hover_color="#6e2e2e",
            command=self._stop_all,
        ).pack(side="bottom", fill="x", padx=8, pady=12)

        # Center + log
        center = ctk.CTkFrame(self, fg_color="transparent")
        center.grid(row=1, column=1, sticky="nsew", padx=(0, 12), pady=12)
        center.grid_rowconfigure(0, weight=3)
        center.grid_rowconfigure(1, weight=1)
        center.grid_columnconfigure(0, weight=1)

        self.page_host = ctk.CTkFrame(center, corner_radius=8)
        self.page_host.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
        self.page_host.grid_rowconfigure(0, weight=1)
        self.page_host.grid_columnconfigure(0, weight=1)

        # Instantiate pages
        page_classes = [
            DriversPage,
            InterfacePage,
            MonitorPage,
            ScanPage,
            TargetPage,
            CapturePage,
            CrackPage,
        ]
        for cls in page_classes:
            page = cls(self.page_host, self)
            page.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
            self._pages.append(page)

        log_frame = ctk.CTkFrame(center, corner_radius=8)
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.grid_rowconfigure(1, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(log_frame, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 0))
        ctk.CTkLabel(
            header, text="Log", font=ctk.CTkFont(size=13, weight="bold")
        ).pack(side="left")
        ctk.CTkButton(header, text="Clear", width=70, command=self._clear_log).pack(
            side="right"
        )

        self.log_box = ctk.CTkTextbox(log_frame, height=140)
        self.log_box.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)

        # Status bar
        self.status_bar = ctk.CTkLabel(self, text="Ready", anchor="w", text_color="gray70")
        self.status_bar.grid(row=2, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 8))

    # --------------------------------------------------------------- banners
    def _show_legal_banner(self) -> None:
        self.log(
            "AUTHORIZED USE ONLY — Test only networks you own or have written "
            "permission to audit. Unauthorized access is illegal."
        )

    def _check_environment(self) -> None:
        if self.service.is_root():
            self.root_banner.configure(
                text="Running as root — monitor mode available",
                text_color="#3cb371",
            )
        else:
            self.root_banner.configure(
                text="Not running as root — start with: sudo python3 main.py",
                text_color="#c9a227",
            )
            self.log("Warning: not root. airmon-ng / injection will likely fail.")

        missing = self.service.missing_binaries()
        if missing:
            self.tool_banner.configure(
                text="Missing tools: " + ", ".join(missing),
                text_color="#c04040",
            )
            self.btn_install_tools.grid()
            self.btn_install_tools.configure(state="normal", text="Install aircrack-ng")
            self.log("Missing tools: " + ", ".join(missing))
        else:
            self.tool_banner.configure(
                text="aircrack-ng tools found on PATH",
                text_color="#3cb371",
            )
            self.btn_install_tools.grid_remove()

    def _install_aircrack_tools(self) -> None:
        if self.service.installing_tools:
            self.log("Install already in progress…")
            return
        if not self.service.is_root():
            self.log("Root required. Re-launch with: sudo python3 main.py")
            self.tool_banner.configure(
                text="Root required to install — run with sudo",
                text_color="#c9a227",
            )
            return

        self.btn_install_tools.configure(state="disabled", text="Installing…")
        self.tool_banner.configure(
            text="Installing aircrack-ng via apt… (see log)",
            text_color="#c9a227",
        )
        self.log("Installing aircrack-ng…")

        def _done(code: int) -> None:
            self.after(0, self._install_aircrack_done, code)

        self.service.install_aircrack(on_done=_done)

    def _install_aircrack_done(self, code: int) -> None:
        if code == 0:
            self.set_status("aircrack-ng installed")
        else:
            self.set_status(f"aircrack-ng install failed (exit {code})")
        self._check_environment()

    # ----------------------------------------------------------------- nav
    def goto_step(self, index: int) -> None:
        if index < 0 or index >= len(self._pages):
            return
        self._step = index
        for i, page in enumerate(self._pages):
            if i == index:
                page.lift()
                if hasattr(page, "on_show"):
                    page.on_show()
            # keep all gridded; lift brings active to front

        for i, btn in enumerate(self._step_buttons):
            if i == index:
                btn.configure(fg_color=("#3a7ebf", "#1f538d"))
            else:
                btn.configure(fg_color="transparent")

        self.set_status(f"Step: {STEPS[index]}")

    # ----------------------------------------------------------------- log
    def log(self, message: str) -> None:
        def _append() -> None:
            if not message:
                return
            self.log_box.insert("end", message + "\n")
            self.log_box.see("end")

        try:
            self.after(0, _append)
        except Exception:
            pass

    def _clear_log(self) -> None:
        self.log_box.delete("1.0", "end")

    def set_status(self, text: str) -> None:
        self.status_bar.configure(text=text)

    def _stop_all(self) -> None:
        self.service.stop_all()
        self.log("Stopped all running tools.")
        self.set_status("Stopped")

    def _on_close(self) -> None:
        self.service.stop_all()
        self.destroy()
