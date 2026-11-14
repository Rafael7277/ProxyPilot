"""Lightweight GTK 4 desktop client using the same API as the headless CLI."""
from __future__ import annotations

import json
import os
import threading
import time
import sys
from pathlib import Path

try:
    import gi
    gi.require_version("Gdk", "4.0")
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gdk, Gio, GLib, Gtk
except (ImportError, ValueError) as exc:  # CLI remains usable without GTK.
    raise RuntimeError("GTK 4 bindings are unavailable. Install python3-gi and gir1.2-gtk-4.0.") from exc

from . import api


BG = "#0d1422"
CARD = "#172235"
CARD2 = "#202f47"
TEXT = "#f4f7fc"
MUTED = "#a9bad1"
BLUE = "#5b93ff"
GREEN = "#54d3a4"
AMBER = "#ffce81"
RED = "#ff929b"


def _label(value: str, *, css_class: str | None = None, wrap: bool = True) -> Gtk.Label:
    label=Gtk.Label(label=value,xalign=0,wrap=wrap,selectable=True)
    if css_class:label.add_css_class(css_class)
    return label


def _card(title: str, value: str) -> Gtk.Widget:
    box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=8)
    box.add_css_class("card")
    box.append(_label(title,css_class="muted"))
    box.append(_label(value,css_class="metric"))
    return box


class ProxyPilotWindow(Gtk.ApplicationWindow):
    def __init__(self, app: Gtk.Application):
        super().__init__(application=app,title="ProxyPilot")
        self.set_icon_name("proxypilot")
        self.set_default_size(1180,780)
        self.set_size_request(920,620)
        self.loading=False
        self.refresh_pending=0
        self.refresh_errors=[]
        self.current_status=None
        self.process_loading=False
        self.process_info={}
        self.app_limit=20
        self.groups=[]
        self.group_map={}
        self.selected_group=None
        self._build_css()
        root=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=0)
        self.set_child(root)
        header=Gtk.HeaderBar()
        header.set_title_widget(_label("ProxyPilot",css_class="title"))
        refresh=Gtk.Button(label="Refresh")
        refresh.connect("clicked",lambda *_:self.refresh())
        header.pack_end(refresh)
        root.append(header)

        body=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=0)
        root.append(body)
        self.stack=Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE,
                             transition_duration=120,hexpand=True,vexpand=True)
        self.stack.set_name("main-stack")
        self.sidebar=Gtk.StackSidebar(stack=self.stack)
        self.sidebar.set_size_request(190,-1)
        self.sidebar.add_css_class("sidebar")
        body.append(self.sidebar)
        body.append(self.stack)
        self._build_dashboard()
        self._build_apps()
        self._build_live()
        self._build_processes()
        self._build_system()
        self._build_diagnostics()
        self._build_settings()
        self._build_updates()
        self._build_about()
        self._style_navigation_rows()
        self.stack.connect("notify::visible-child-name",self._page_changed)

        self.statusbar=Gtk.Label(label="Ready",xalign=0)
        self.statusbar.add_css_class("statusbar")
        root.append(self.statusbar)
        self.refresh()
        GLib.timeout_add_seconds(15,self._periodic_refresh)

    def _build_css(self) -> None:
        css=f"""
        window, .background {{ background: {BG}; color: {TEXT}; }}
        label {{ color: {TEXT}; }}
        .title {{ font-size: 17pt; font-weight: 700; }}
        .page-title {{ font-size: 22pt; font-weight: 700; }}
        .muted {{ color: {MUTED}; }}
        .metric {{ font-size: 19pt; font-weight: 700; }}
        .card {{ background: {CARD}; border: 1px solid #2c3d58; border-radius: 12px; padding: 16px; }}
        .surface {{ background: {CARD}; border-radius: 10px; padding: 14px; }}
        headerbar {{ background: {CARD}; color: {TEXT}; border-bottom: 1px solid #2c3d58; }}
        headerbar label {{ color: {TEXT}; }}
        .sidebar, .sidebar list {{ background-color: #101a2b; padding: 10px; }}
        .sidebar row {{ background-color: #101a2b; color: {MUTED}; }}
        .sidebar row label {{ color: {MUTED}; }}
        .sidebar row:hover {{ background-color: {CARD2}; }}
        .sidebar row:selected {{ background-color: #2b4263; color: {TEXT}; }}
        .sidebar row:selected label {{ color: {TEXT}; }}
        list.navigation-sidebar row {{ background-color: #101a2b; color: {MUTED}; }}
        list.navigation-sidebar row label {{ color: {MUTED}; }}
        list.navigation-sidebar row:selected {{ background-color: #2b4263;
                                                 background-image: none; color: {TEXT}; }}
        list.navigation-sidebar row:selected label {{ color: {TEXT}; }}
        row.navigation-row {{ background-color: #101a2b; background-image: none; color: {MUTED}; }}
        row.navigation-row label {{ color: {MUTED}; }}
        row.navigation-row:selected {{ background-color: #2b4263; background-image: none; color: {TEXT}; }}
        row.navigation-row:selected label {{ color: {TEXT}; }}
        .statusbar {{ background: #101a2b; color: {MUTED}; padding: 8px 14px; }}
        scrolledwindow, viewport, .content-scroll {{ background-color: {BG}; background-image: none; color: {TEXT}; }}
        .content-scroll viewport, .content-scroll list {{ background-color: {BG}; background-image: none; color: {TEXT}; }}
        list, listview, .boxed-list {{ background-color: {BG}; background-image: none; color: {TEXT}; }}
        list row {{ background-color: {CARD}; color: {TEXT}; border-bottom: 1px solid #26364f; }}
        list row:hover {{ background-color: {CARD2}; }}
        list row:selected {{ background-color: #2b4263; color: {TEXT}; }}
        list row:selected label {{ color: {TEXT}; }}
        row.app-row, row.process-row, row.dashboard-row {{ background-color: {CARD}; background-image: none; color: {TEXT}; }}
        row.app-row label, row.process-row label, row.dashboard-row label {{ color: {TEXT}; }}
        row.app-row:selected, row.process-row:selected {{ background-color: #2b4263; background-image: none; color: {TEXT}; }}
        row.app-row:selected label, row.process-row:selected label {{ color: {TEXT}; }}
        entry, searchentry, textview, dropdown {{ background-color: {CARD2}; color: {TEXT}; }}
        textview text {{ background-color: {CARD2}; color: {TEXT}; caret-color: {TEXT}; }}
        checkbutton, checkbutton label {{ color: {TEXT}; }}
        button {{ background-color: {CARD2}; background-image: none; color: {TEXT}; border: 1px solid #374b66;
                 border-radius: 7px; padding: 7px 12px; }}
        button:hover {{ background-color: #2c4162; background-image: none; }}
        button:active {{ background-color: #334d73; background-image: none; }}
        button:disabled {{ background-color: #192438; color: #8493a9; }}
        button.suggested-action {{ background-color: {BLUE}; background-image: none; color: #ffffff; border-color: {BLUE}; }}
        button.destructive-action {{ background-color: #642c39; background-image: none; color: {TEXT}; border-color: #87404e; }}
        .warning {{ color: {AMBER}; }}
        .success {{ color: {GREEN}; }}
        .error {{ color: {RED}; }}
        """
        provider=Gtk.CssProvider()
        provider.load_from_data(css.encode())
        display=Gdk.Display.get_default()
        if display:Gtk.StyleContext.add_provider_for_display(display,provider,Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    def _page(self,name: str,title: str) -> Gtk.Box:
        page=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=14)
        page.set_margin_top(22);page.set_margin_bottom(18)
        page.set_margin_start(24);page.set_margin_end(24)
        page.append(_label(title,css_class="page-title"))
        self.stack.add_titled(page,name,title)
        return page

    def _scroll(self,child: Gtk.Widget) -> Gtk.ScrolledWindow:
        scroller=Gtk.ScrolledWindow(hexpand=True,vexpand=True)
        scroller.add_css_class("content-scroll")
        scroller.set_child(child)
        return scroller

    def _style_navigation_rows(self) -> None:
        def apply(widget: Gtk.Widget) -> None:
            if widget.get_css_name()=="row":widget.add_css_class("navigation-row")
            child=widget.get_first_child()
            while child:
                following=child.get_next_sibling();apply(child);child=following
        apply(self.sidebar)

    def _build_dashboard(self) -> None:
        page=self._page("dashboard","Dashboard")
        self.dashboard_summary=_label("Loading system status…",css_class="muted")
        page.append(self.dashboard_summary)
        row=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=12)
        page.append(row)
        self.dashboard_cards={}
        for key,title in (("service","Bridge service"),("upstream","SOCKS5 upstream"),
                          ("policy","System policy"),("apps","Running apps")):
            card=_card(title,"—");row.append(card);self.dashboard_cards[key]=card.get_last_child()
        self.conflict_list=Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.conflict_list.add_css_class("boxed-list")
        self.conflict_list.add_css_class("dashboard-list")
        page.append(_label("Needs attention",css_class="title"))
        page.append(self._scroll(self.conflict_list))

    def _build_apps(self) -> None:
        page=self._page("applications","Applications")
        split=Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL,wide_handle=True,hexpand=True,vexpand=True)
        page.append(split)
        left=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=8)
        self.app_search=Gtk.SearchEntry(placeholder_text="Search apps and services…")
        self.app_search.connect("search-changed",self._app_search_changed)
        left.append(self.app_search)
        self.app_list=Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.app_list.add_css_class("app-list")
        self.app_list.connect("row-selected",self._app_selected)
        left.append(self._scroll(self.app_list))
        self.app_more_button=Gtk.Button(label="Show more applications")
        self.app_more_button.connect("clicked",self._show_more_apps)
        self.app_more_button.set_visible(False)
        left.append(self.app_more_button)
        right=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=12)
        right.set_margin_start(18)
        self.app_detail=_label("Select an app to inspect its policy and evidence.")
        self.app_detail.add_css_class("surface")
        right.append(self.app_detail)
        self.app_mode=Gtk.DropDown.new_from_strings(["Use system settings","Direct","Proxy only","Auto"])
        right.append(_label("Requested policy",css_class="muted"));right.append(self.app_mode)
        self.manage_launchers=Gtk.CheckButton(label="Manage future desktop launches")
        right.append(self.manage_launchers)
        self.restart_services=Gtk.CheckButton(label="Restart related user services (requires confirmation)")
        right.append(self.restart_services)
        apply=Gtk.Button(label="Review and apply policy")
        apply.add_css_class("suggested-action");apply.connect("clicked",self._apply_app_policy)
        right.append(apply)
        split.set_start_child(left);split.set_end_child(right);split.set_position(430)

    def _build_live(self) -> None:
        page=self._page("live","Live Network")
        self.live_text=Gtk.TextView(editable=False,monospace=True,wrap_mode=Gtk.WrapMode.WORD_CHAR)
        self.live_buffer=self.live_text.get_buffer()
        refresh=Gtk.Button(label="Collect current evidence")
        refresh.connect("clicked",lambda *_:self._load_live())
        page.append(refresh);page.append(self._scroll(self.live_text))

    def _build_processes(self) -> None:
        page=self._page("processes","Process Manager")
        page.append(_label("Review same-user processes. SSH, shells, desktop services, and ProxyPilot are protected from cleanup.",css_class="muted"))
        split=Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL,wide_handle=True,hexpand=True,vexpand=True)
        page.append(split)
        self.process_list=Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.process_list.add_css_class("process-list")
        self.process_list.connect("row-selected",self._process_selected)
        split.set_start_child(self._scroll(self.process_list))
        panel=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=10)
        self.process_detail=_label("Select a process group.")
        panel.append(self.process_detail)
        stop=Gtk.Button(label="Stop selected group…")
        stop.add_css_class("destructive-action");stop.connect("clicked",self._stop_selected_group)
        panel.append(stop)
        panel.append(_label("Stopping is always confirmed. Reused PIDs are rejected; SIGTERM is used first.",css_class="muted"))
        split.set_end_child(panel);split.set_position(500)

    def _build_system(self) -> None:
        page=self._page("system","System Proxy")
        page.append(_label("System proxy settings are not a full tunnel. This adapter changes GNOME GSettings and the systemd user environment only.",css_class="muted"))
        self.system_detail=_label("Loading…");self.system_detail.add_css_class("surface");page.append(self.system_detail)
        controls=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=8)
        self.system_mode=Gtk.DropDown.new_from_strings(["Off / restore","Direct","Auto","Proxy only"])
        controls.append(self.system_mode)
        apply=Gtk.Button(label="Review system proxy change…")
        apply.connect("clicked",self._apply_system_mode);controls.append(apply)
        page.append(controls)

    def _build_diagnostics(self) -> None:
        page=self._page("diagnostics","Diagnostics")
        self.diag_text=Gtk.TextView(editable=False,monospace=True,wrap_mode=Gtk.WrapMode.WORD_CHAR)
        self.diag_buffer=self.diag_text.get_buffer()
        button=Gtk.Button(label="Run read-only diagnostics")
        button.connect("clicked",lambda *_:self._load_diagnostics())
        page.append(button);page.append(self._scroll(self.diag_text))

    def _build_settings(self) -> None:
        page=self._page("settings","Settings")
        page.append(_label("Network safety and evidence retention",css_class="title"))
        self.allow_fallback=Gtk.CheckButton(label="Allow AUTO to fall back to direct if SOCKS5 fails")
        self.record_metadata=Gtk.CheckButton(label="Record bridge metadata (destination host, route, PID; no payload)")
        page.append(self.allow_fallback);page.append(self.record_metadata)
        button=Gtk.Button(label="Save settings")
        button.connect("clicked",self._save_settings)
        page.append(button)

    def _build_updates(self) -> None:
        page=self._page("updates","Updates")
        from . import __version__
        page.append(_label(f"Installed version: {__version__}"))
        self.update_detail=_label("Release checks query GitHub only after you click. No update is installed automatically.",css_class="muted")
        page.append(self.update_detail)
        button=Gtk.Button(label="Check for latest stable release")
        button.connect("clicked",self._check_updates)
        page.append(button)

    def _check_updates(self,_button) -> None:
        self.update_detail.set_text("Checking the configured GitHub repository…")
        def worker():
            result=api.update_check()
            GLib.idle_add(self.update_detail.set_text,
                          json.dumps(result,ensure_ascii=False,indent=2))
        threading.Thread(target=worker,daemon=True).start()

    def _build_about(self) -> None:
        page=self._page("about","About")
        page.append(_label("ProxyPilot helps inspect proxy-aware Linux applications and route supported HTTP/HTTPS requests through a local SOCKS5 bridge."))
        page.append(_label("It does not intercept arbitrary traffic, UDP, or all system packets. Missing observations are reported as unverified.",css_class="muted"))

    def _periodic_refresh(self) -> bool:
        if self.get_visible():self.refresh()
        return True

    def refresh(self) -> None:
        if self.loading:return
        self.loading=True
        self.refresh_pending=2
        self.refresh_errors=[]
        self.statusbar.set_text("Scanning local services and same-user processes…")
        def status_worker():
            try:result=api.status();error=None
            except Exception as exc:result=None;error=f"{type(exc).__name__}: {exc}"
            GLib.idle_add(self._refresh_part_done,"status",result,error)
        def groups_worker():
            try:result=api.groups();error=None
            except Exception as exc:result=None;error=f"{type(exc).__name__}: {exc}"
            GLib.idle_add(self._refresh_part_done,"groups",result,error)
        threading.Thread(target=status_worker,daemon=True).start()
        threading.Thread(target=groups_worker,daemon=True).start()

    def _refresh_part_done(self,kind,result,error) -> bool:
        if error:
            self.refresh_errors.append(error)
        elif kind=="status":
            self.current_status=result
            self.system_detail.set_text(json.dumps(result["system_proxy"],ensure_ascii=False,indent=2))
            self.allow_fallback.set_active(result["policy"]["allow_direct_fallback"])
            try:
                import proxypilot as bridge
                cfg=bridge.load()
                self.record_metadata.set_active(cfg.get("traffic_monitor_enabled",True))
            except Exception:pass
        elif kind=="groups":
            self.groups=result;self.group_map={g["id"]:g for g in result}
            self._draw_apps();self._draw_processes()
        if self.current_status is not None:
            self._update_dashboard(self.current_status)
        self.refresh_pending-=1
        if self.refresh_pending<=0:
            self.loading=False
            if self.refresh_errors:
                self.statusbar.set_text("Partial scan: "+"; ".join(self.refresh_errors))
                if self.current_status is None:self.dashboard_summary.set_text(self.refresh_errors[0])
            else:
                self.statusbar.set_text(f"Ready · {len(self.groups)} app/process groups · read-only scan")
            if self.stack.get_visible_child_name()=="processes":self._load_process_inventory()
        return GLib.SOURCE_REMOVE

    def _update_dashboard(self,status) -> None:
        service=status["service"].get("active_state","unknown")
        self.dashboard_cards["service"].set_text(service)
        self.dashboard_cards["upstream"].set_text("Listening" if status["listeners"]["upstream"] else "Unavailable")
        self.dashboard_cards["policy"].set_text(status["policy"]["global"].upper())
        self.dashboard_cards["apps"].set_text(str(sum(bool(g.get("process_count")) for g in self.groups)))
        notes=status["system_proxy"]["notes"]
        if not notes:notes=["No known configuration mismatch was found. This does not prove every app uses the proxy."]
        self._clear_list(self.conflict_list)
        for note in notes:
            row=Gtk.ListBoxRow();row.add_css_class("dashboard-row")
            row.set_child(_label("• "+note,css_class="warning"));self.conflict_list.append(row)
        self.dashboard_summary.set_text(
            f"Bridge service: {service}. AUTO and Proxy Only listeners: "
            f"{status['listeners']['auto']} / {status['listeners']['proxy_only']}. "
            f"Upstream: {status['configured_upstream']}. No TUN is active.")

    @staticmethod
    def _clear_list(widget: Gtk.ListBox) -> None:
        child=widget.get_first_child()
        while child:
            next_child=child.get_next_sibling();widget.remove(child);child=next_child

    def _draw_apps(self) -> None:
        self._clear_list(self.app_list)
        query=self.app_search.get_text().casefold().strip()
        filtered=[group for group in sorted(self.groups,
                  key=lambda g:(not bool(g.get("process_count")),g["name"].casefold()))
                  if not query or query in (group["name"]+" "+group["id"]).casefold()]
        for group in filtered[:self.app_limit]:
            row=Gtk.ListBoxRow()
            row.add_css_class("app-row")
            content=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=12)
            content.set_margin_top(9);content.set_margin_bottom(9)
            content.set_margin_start(10);content.set_margin_end(8)
            icon=next((app.get("icon") for app in group.get("apps",[]) if app.get("icon")),None)
            if icon and Path(icon).is_absolute() and Path(icon).is_file():
                image=Gtk.Image.new_from_file(icon)
            else:
                image=Gtk.Image.new_from_icon_name(icon or "application-x-executable")
            image.set_pixel_size(36)
            content.append(image)
            label=_label(f"{group['name']}\n{group.get('mode','unmanaged')} · "
                         f"{group.get('process_count',0)} process(es)",wrap=True)
            label.set_hexpand(True)
            content.append(label)
            row.set_child(content);row.group_id=group["id"]
            self.app_list.append(row)
        remaining=max(0,len(filtered)-self.app_limit)
        self.app_more_button.set_label(f"Show next 20 applications ({remaining} remaining)")
        self.app_more_button.set_visible(remaining>0)

    def _app_search_changed(self,_entry) -> None:
        self.app_limit=20
        self._draw_apps()

    def _show_more_apps(self,_button) -> None:
        self.app_limit+=20
        self._draw_apps()

    def _app_selected(self,_list,row) -> None:
        if row is None:return
        group=self.group_map.get(row.group_id)
        if not group:return
        self.selected_group=group
        self.app_detail.set_text("Collecting policy and connection evidence…")
        def worker():
            try:
                details=api.inspect(group["id"])
                result=json.dumps({"requested_policy":details["requested_policy"],
                    "effective_configuration":details["effective_configuration"],
                    "verification":details["verification"]},ensure_ascii=False,indent=2)
            except Exception as exc:result=f"Could not inspect app: {type(exc).__name__}: {exc}"
            GLib.idle_add(self._set_app_detail,group["id"],result)
        threading.Thread(target=worker,daemon=True).start()
        mode=group.get("mode","unmanaged")
        index={"unmanaged":0,"direct":1,"proxy":2,"auto":3}.get(mode,0)
        self.app_mode.set_selected(index)
        self.manage_launchers.set_active(any(a.get("managed") for a in group.get("apps",[])))
        self.restart_services.set_active(False)

    def _set_app_detail(self,group_id,text) -> bool:
        if self.selected_group and self.selected_group.get("id")==group_id:
            self.app_detail.set_text(text)
        return GLib.SOURCE_REMOVE

    def _apply_app_policy(self,_button) -> None:
        if not self.selected_group:
            self.statusbar.set_text("Select an application first.");return
        group=self.selected_group
        mode={0:"unmanaged",1:"direct",2:"proxy",3:"auto"}.get(self.app_mode.get_selected(),"unmanaged")
        restart=self.restart_services.get_active()
        text=(f"Apply {mode.upper()} to {group['name']}?\n\n"
              f"Manage future menu launches: {self.manage_launchers.get_active()}\n"
              f"Restart related user services: {restart}\n"
              "Existing processes may keep their current route.")
        dialog=Gtk.MessageDialog(transient_for=self,modal=True,message_type=Gtk.MessageType.WARNING,
                                 buttons=Gtk.ButtonsType.OK_CANCEL,text="Confirm route change")
        dialog.set_secondary_text(text)
        dialog.connect("response",self._confirm_app_policy,group["id"],mode,
                       self.manage_launchers.get_active(),restart)
        dialog.present()

    def _confirm_app_policy(self,dialog,response,group_id,mode,manage,restart) -> None:
        dialog.destroy()
        if response!=Gtk.ResponseType.OK:return
        self.statusbar.set_text("Applying selected policy…")
        def worker():
            try:result=api.set_route(group_id,mode,apply=True,manage_launchers=manage,
                                     restart_services=restart)
            except Exception as exc:result={"error":f"{type(exc).__name__}: {exc}"}
            GLib.idle_add(self._operation_done,result)
        threading.Thread(target=worker,daemon=True).start()

    def _draw_processes(self) -> None:
        self._clear_list(self.process_list)
        for group in self.groups:
            if not group.get("process_count"):continue
            detail=self.process_info.get(group["id"],{})
            if detail.get("protected"):status="Protected"
            elif detail.get("review"):status="Review recommended"
            elif detail:status="Background/active"
            else:status="Details load on selection"
            connections=sum(len(p.get("connections",[])) for p in detail.get("process_tree",[]))
            row=Gtk.ListBoxRow();row.add_css_class("process-row");row.group_id=group["id"]
            row.set_child(_label(f"{group['name']} · {status} · {group['process_count']} process(es) · "
                                 f"{group['memory_mb']} MB · {connections} observed connection(s)"))
            self.process_list.append(row)

    def _process_selected(self,_list,row) -> None:
        if row is None:return
        group=self.group_map.get(row.group_id)
        if not group:return
        self.selected_group=group
        detail=self.process_info.get(group["id"])
        if detail:self.process_detail.set_text(json.dumps(detail,ensure_ascii=False,indent=2))
        else:
            self.process_detail.set_text("Collecting process tree and connection observations…")
            self._load_process_inventory()

    def _page_changed(self,_stack,_property) -> None:
        self._style_navigation_rows()
        if self.stack.get_visible_child_name()=="processes":self._load_process_inventory()

    def _load_process_inventory(self) -> None:
        if self.process_loading:return
        self.process_loading=True
        def worker():
            try:items=api.process_list()
            except Exception as exc:items={"error":f"{type(exc).__name__}: {exc}"}
            GLib.idle_add(self._process_inventory_done,items)
        threading.Thread(target=worker,daemon=True).start()

    def _process_inventory_done(self,items) -> bool:
        self.process_loading=False
        if isinstance(items,dict) and "error" in items:
            self.process_detail.set_text(items["error"])
            return GLib.SOURCE_REMOVE
        self.process_info={item["id"]:item for item in items}
        self._draw_processes()
        if self.selected_group and self.selected_group.get("id") in self.process_info:
            self.process_detail.set_text(json.dumps(self.process_info[self.selected_group["id"]],
                                                    ensure_ascii=False,indent=2))
        return GLib.SOURCE_REMOVE

    def _stop_selected_group(self,_button) -> None:
        group=self.selected_group
        if not group or not group.get("processes"):
            self.statusbar.set_text("Select a running process group first.");return
        dialog=Gtk.MessageDialog(transient_for=self,modal=True,message_type=Gtk.MessageType.WARNING,
                                 buttons=Gtk.ButtonsType.OK_CANCEL,text="Stop selected process group?")
        dialog.set_secondary_text(f"{group['name']}: {len(group['processes'])} PID(s). SIGTERM will be sent.\n"
            "SSH, shell, desktop, systemd and ProxyPilot processes are protected. Unsaved work may be lost.")
        dialog.connect("response",self._confirm_stop_group,group)
        dialog.present()

    def _confirm_stop_group(self,dialog,response,group) -> None:
        dialog.destroy()
        if response!=Gtk.ResponseType.OK:return
        def worker():
            import manager
            result=manager.terminate_verified(group["processes"],"TERM")
            GLib.idle_add(self._operation_done,result)
        threading.Thread(target=worker,daemon=True).start()

    def _load_live(self) -> None:
        self.statusbar.set_text("Sampling recent bridge events and same-user TCP sockets…")
        def worker():
            try:result=api.connections(200)
            except Exception as exc:result={"error":f"{type(exc).__name__}: {exc}"}
            GLib.idle_add(self._set_text_buffer,self.live_buffer,json.dumps(result,ensure_ascii=False,indent=2))
        threading.Thread(target=worker,daemon=True).start()

    def _load_diagnostics(self) -> None:
        self.statusbar.set_text("Running local read-only diagnostics…")
        def worker():
            try:result=api.doctor()
            except Exception as exc:result={"error":f"{type(exc).__name__}: {exc}"}
            GLib.idle_add(self._set_text_buffer,self.diag_buffer,json.dumps(result,ensure_ascii=False,indent=2))
        threading.Thread(target=worker,daemon=True).start()

    @staticmethod
    def _set_text_buffer(buffer,text) -> bool:
        buffer.set_text(text);return GLib.SOURCE_REMOVE

    def _apply_system_mode(self,_button) -> None:
        idx=self.system_mode.get_selected()
        mode={0:"off",1:"direct",2:"auto",3:"proxy"}.get(idx,"off")
        dialog=Gtk.MessageDialog(transient_for=self,modal=True,message_type=Gtk.MessageType.WARNING,
                                 buttons=Gtk.ButtonsType.OK_CANCEL,text="Change GNOME/systemd proxy settings?")
        dialog.set_secondary_text(f"Requested mode: {mode.upper()}. This updates only GNOME GSettings and the systemd user environment; it is not a TUN.")
        dialog.connect("response",self._confirm_system_mode,mode);dialog.present()

    def _confirm_system_mode(self,dialog,response,mode) -> None:
        dialog.destroy()
        if response!=Gtk.ResponseType.OK:return
        def worker():
            try:
                import manager
                manager.GlobalProxy().apply(mode)
                result={"applied":True,"mode":mode}
            except Exception as exc:result={"error":f"{type(exc).__name__}: {exc}"}
            GLib.idle_add(self._operation_done,result)
        threading.Thread(target=worker,daemon=True).start()

    def _save_settings(self,_button) -> None:
        try:
            import proxypilot as bridge
            cfg=bridge.load()
            cfg["allow_direct_fallback"]=self.allow_fallback.get_active()
            cfg["traffic_monitor_enabled"]=self.record_metadata.get_active()
            bridge.save(cfg)
            self.statusbar.set_text("Settings saved.")
        except Exception as exc:self.statusbar.set_text(f"Settings were not saved: {exc}")

    def _operation_done(self,result) -> bool:
        self.statusbar.set_text(json.dumps(result,ensure_ascii=False))
        self.refresh()
        return GLib.SOURCE_REMOVE


class ProxyPilotApplication(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="io.github.proxypilot.ProxyPilot",
                         flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.window=None

    def do_activate(self):
        if self.window is None:self.window=ProxyPilotWindow(self)
        self.window.present()
        if os.environ.get("PROXYPILOT_SMOKE_TEST")=="1":
            GLib.timeout_add_seconds(2,self._smoke_quit)
        return GLib.SOURCE_REMOVE

    def _smoke_quit(self) -> bool:
        self.quit()
        return GLib.SOURCE_REMOVE


def main(argv: list[str] | None = None) -> int:
    app=ProxyPilotApplication()
    try:return app.run(sys.argv if argv is None else [sys.argv[0],*argv])
    except Exception as exc:
        print(f"ProxyPilot GTK startup failed: {type(exc).__name__}: {exc}",file=sys.stderr)
        return 1


if __name__=="__main__":
    raise SystemExit(main())
