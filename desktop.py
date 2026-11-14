#!/usr/bin/env python3
"""ProxyPilot Desktop — lightweight native Tk UI for Linux / XFCE."""
from __future__ import annotations
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
import traffic
import appicons
import socketwatch
import netobserve
import checkui
import proxypilot as core
import manager
import diagnostics

BG='#0d1320'; SURFACE='#151f30'; SURFACE_2='#1e2d43'; SURFACE_3='#293b56'
TEXT='#f1f5fc'; MUTED='#a6b9d0'; BLUE='#5b93ff'; BLUE_DARK='#3159aa';
GREEN='#54d3a4'; AMBER='#ffce81'; RED='#ff929b'
FONT='DejaVu Sans'
MODES=['unmanaged','direct','auto','proxy']
ROUTES={'unmanaged':'Use Linux/app settings','direct':'Direct — Direct only','auto':'Auto — Proxy with fallback','proxy':'Proxy — Proxy only'}

class ProxyPilot(checkui.CheckUI, tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('ProxyPilot v0.8 — Actual Network Status')
        self.geometry('1260x850');self.minsize(1040,750)
        self.configure(bg=BG)
        self.groups=[];self.group_map={};self.review_map={}
        self.selected_id=None;self.current='overview';self.scanning=False;self.health_running=False
        self.icons=appicons.AppIcons(self, 36)
        self.net_recent=netobserve.RecentConnections(window_s=90)
        self.net_busy=False
        self.traffic_reader=traffic.TrafficReader()
        self.traffic_paused=False
        self._last_system_snapshot=None
        self.external_sockets=[];self.socket_running=False
        self.sampler=manager.ProcessSampler()
        self._style();self._layout();self.switch('check');self.refresh()
        self.after(9000,self._periodic)
        self.after(1200,self._traffic_tick)
        self.after(750,self._net_tick)
        self.protocol('WM_DELETE_WINDOW',self.destroy)

    def _style(self):
        sty=ttk.Style(self);sty.theme_use('clam')
        sty.configure('.',font=(FONT,10),background=BG,foreground=TEXT)
        sty.configure('TFrame',background=BG);sty.configure('Card.TFrame',background=SURFACE)
        sty.configure('TLabel',background=BG,foreground=TEXT)
        sty.configure('Card.TLabel',background=SURFACE,foreground=TEXT)
        sty.configure('Muted.TLabel',background=SURFACE,foreground=MUTED)
        sty.configure('TEntry',fieldbackground=SURFACE_2,foreground=TEXT,bordercolor=SURFACE_3,padding=9)
        sty.configure('TCombobox',fieldbackground=SURFACE_2,foreground=TEXT,padding=8)
        sty.map('TCombobox',fieldbackground=[('readonly',SURFACE_2)],foreground=[('readonly',TEXT)])
        sty.configure('TButton',background=SURFACE_3,foreground=TEXT,borderwidth=0,padding=(14,11))
        sty.map('TButton',background=[('active','#3d5375'),('disabled','#1b293d')],foreground=[('disabled','#7890aa')])
        sty.configure('Main.TButton',background=BLUE_DARK,foreground='white')
        sty.map('Main.TButton',background=[('active','#4778d9')])
        sty.configure('Danger.TButton',background='#813847',foreground='white')
        sty.map('Danger.TButton',background=[('active','#a54354')])
        sty.configure('App.Treeview',rowheight=46)
        sty.configure('Process.Treeview',rowheight=40)
        sty.configure('Treeview',background=SURFACE,fieldbackground=SURFACE,foreground=TEXT,
                      rowheight=37,borderwidth=0,relief='flat')
        sty.configure('Treeview.Heading',background=SURFACE_2,foreground=MUTED,relief='flat',padding=11)
        sty.map('Treeview',background=[('selected',SURFACE_3)],foreground=[('selected','white')])
        sty.configure('Vertical.TScrollbar',background=SURFACE_3,troughcolor=SURFACE)
        sty.configure('TCheckbutton',background=SURFACE,foreground=TEXT)
        sty.configure('TRadiobutton',background=SURFACE,foreground=TEXT)
        sty.map('TCheckbutton',background=[('active',SURFACE)],foreground=[('active',TEXT)])

    def _text(self,parent,text,size=10,bold=False,color=TEXT,bg=None,wrap=0,justify='left'):
        return tk.Label(parent,text=text,font=(FONT,size,'bold' if bold else 'normal'),
                        bg=bg or parent.cget('bg'),fg=color,justify=justify,anchor='w',
                        wraplength=wrap)

    def _button(self,parent,label,command,primary=False,danger=False):
        return ttk.Button(parent,text=label,command=command,
                          style='Danger.TButton' if danger else ('Main.TButton' if primary else 'TButton'))

    def _card(self,parent,pad=18):
        outer=tk.Frame(parent,bg=SURFACE,highlightbackground='#293951',highlightthickness=1)
        inner=tk.Frame(outer,bg=SURFACE,padx=pad,pady=pad)
        inner.pack(fill='both',expand=True)
        return outer,inner

    def _layout(self):
        self.sidebar=tk.Frame(self,bg='#10192b',width=235)
        self.sidebar.pack(side='left',fill='y');self.sidebar.pack_propagate(False)
        brand=tk.Frame(self.sidebar,bg='#10192b',padx=22,pady=30)
        brand.pack(fill='x')
        tk.Label(brand,text='◉  ProxyPilot',bg='#10192b',fg=TEXT,
                 font=(FONT,18,'bold')).pack(anchor='w')
        tk.Label(brand,text='LINUX NETWORK CONTROL',bg='#10192b',fg=MUTED,
                 font=(FONT,8)).pack(anchor='w',pady=(4,0))
        self.nav={}
        for key,title in [('check','✓   Check an app'),('apps','▦   App rules' ),
                          ('traffic','↔   Network connections'),('processes','▤   Clean up processes'),('system','◎   Linux system proxy'),
                          ('settings','⚙   Settings'),('overview','ⓘ   About & guide')]:
            b=tk.Button(self.sidebar,text=title,command=lambda x=key:self.switch(x),
                        bg='#10192b',fg=MUTED,activebackground=SURFACE_3,
                        activeforeground=TEXT,relief='flat',bd=0,anchor='w',cursor='hand2',
                        padx=24,pady=14,font=(FONT,11))
            b.pack(fill='x',padx=9,pady=2);self.nav[key]=b
        tk.Frame(self.sidebar,bg='#31415c',height=1).pack(fill='x',padx=22,pady=(30,14))
        self._text(self.sidebar,'No root access. No TUN.',size=9,color=MUTED,bg='#10192b',wrap=185).pack(padx=22,anchor='w')
        self.content=tk.Frame(self,bg=BG);self.content.pack(side='left',fill='both',expand=True)
        heading=tk.Frame(self.content,bg=BG,padx=25,pady=16);heading.pack(fill='x')
        self.page_title=self._text(heading,'Overview',size=20,bold=True)
        self.page_title.pack(side='left')
        self.health_text=self._text(heading,'● Checking v2rayN...',size=10,bold=True,color=MUTED)
        self.health_text.pack(side='right')
        self.body=tk.Frame(self.content,bg=BG,padx=22,pady=6);self.body.pack(fill='both',expand=True)
        footer=tk.Frame(self.content,bg=BG,padx=25,pady=13)
        footer.pack(fill='x',side='bottom')
        self.notice=self._text(footer,'Ready  •  Changes require your approval',size=9,color=MUTED)
        self.notice.pack(side='left',fill='x',expand=True)
        self._button(footer,'↻ Rescan',self.refresh).pack(side='right')
        self.pages={}
        for k in self.nav:
            self.pages[k]=tk.Frame(self.body,bg=BG)
        self._check_page();self._overview_page();self._apps_page();self._traffic_page();self._process_page();self._system_page();self._settings_page()

    def switch(self,key):
        self.current=key
        names={'check':'Check an app • Is the proxy actually used?', 'overview':'How ProxyPilot works','apps':'App routing · advanced settings',
               'traffic':'Network connections & bridge logs','processes':'Safe process cleanup',
               'system':'Linux system proxy · no TUN','settings':'Proxy settings'}
        self.page_title.configure(text=names[key])
        for k,b in self.nav.items():
            b.configure(bg=SURFACE_3 if k==key else '#10192b',fg=TEXT if k==key else MUTED)
        for p in self.pages.values():p.pack_forget()
        self.pages[key].pack(fill='both',expand=True)

    def _overview_page(self):
        page=self.pages['overview']
        self._text(page,'Live overview of installed apps, running processes, and connection status',color=MUTED).pack(anchor='w',pady=(8,18))
        stats=tk.Frame(page,bg=BG);stats.pack(fill='x')
        self.stat_values={}
        for i,(key,title) in enumerate([('apps','Apps & services'),('running','Running processes'),
                                         ('review','Review candidates'),('global','System-wide route'),('proxies','Proxy requests')]):
            outer,inner=self._card(stats,16);outer.grid(row=0,column=i,sticky='nsew',padx=(0 if i==0 else 7,7))
            stats.grid_columnconfigure(i,weight=1)
            self._text(inner,title,size=9,color=MUTED).pack(anchor='w')
            v=self._text(inner,'—',size=24,bold=True);v.pack(anchor='w',pady=(10,1))
            self.stat_values[key]=v
        box,p=self._card(page,22);box.pack(fill='x',pady=(24,15))
        self._text(p,'One rule per application',size=15,bold=True).pack(anchor='w')
        self._text(p,'Use Direct, Proxy, or Auto for an app. GNOME-aware apps may respond to SYSTEM proxy changes live.\nApps using process environment only need relaunch. A per-app bridge must be configured before it can switch live.',
                   size=10,color=MUTED,wrap=750).pack(anchor='w',pady=(12,18))
        controls=tk.Frame(p,bg=SURFACE);controls.pack(anchor='w')
        self._button(controls,'Browse applications',lambda:self.switch('apps'),primary=True).pack(side='left',padx=(0,9))
        self._button(controls,'Inspect background processes',lambda:self.switch('processes')).pack(side='left',padx=(0,9))
        self._button(controls,'Live traffic',lambda:self.switch('traffic')).pack(side='left')
        box,p=self._card(page,20);box.pack(fill='x')
        self._text(p,'Important: system-wide does not mean all packets',size=13,bold=True,color=AMBER).pack(anchor='w')
        self._text(p,'ProxyPilot does not create a TUN interface or intercept traffic. System-wide mode covers proxy-aware applications only.\nRouting ALL traffic requires actual TUN or privileged transparent routing.',
                   size=10,color=MUTED,wrap=770).pack(anchor='w',pady=(9,0))

    def _table(self,parent,columns,widths):
        container=tk.Frame(parent,bg=SURFACE)
        tree=ttk.Treeview(container,columns=columns,show='headings',selectmode='browse')
        for col,w in zip(columns,widths):
            tree.heading(col,text=col)
            tree.column(col,width=w,stretch=(col==columns[0]))
        sc=ttk.Scrollbar(container,orient='vertical',command=tree.yview)
        tree.configure(yscrollcommand=sc.set)
        tree.pack(side='left',fill='both',expand=True);sc.pack(side='right',fill='y')
        return container,tree

    def _apps_page(self):
        pg=self.pages['apps']
        toolbar=tk.Frame(pg,bg=BG);toolbar.pack(fill='x',pady=(5,12))
        self._text(toolbar,'Search installed apps, services, and process groups',color=MUTED).pack(side='left')
        self.app_search=tk.StringVar()
        ttk.Entry(toolbar,textvariable=self.app_search,width=29).pack(side='right')
        self.app_search.trace_add('write',lambda *_:self.draw_apps())
        holder=tk.Frame(pg,bg=SURFACE)
        self.apps_tree=ttk.Treeview(holder,columns=('Route','Running','Components','Status'),show='tree headings',selectmode='browse',style='App.Treeview')
        self.apps_tree.heading('#0',text='Application')
        self.apps_tree.column('#0',width=260,minwidth=180,stretch=True)
        for col,width in (('Route',118),('Running',90),('Components',170),('Status',145)):
            self.apps_tree.heading(col,text=col)
            self.apps_tree.column(col,width=width,stretch=False)
        sc=ttk.Scrollbar(holder,orient='vertical',command=self.apps_tree.yview)
        self.apps_tree.configure(yscrollcommand=sc.set)
        self.apps_tree.pack(side='left',fill='both',expand=True)
        sc.pack(side='right',fill='y')
        holder.pack(fill='both',expand=True)
        self.apps_tree.bind('<<TreeviewSelect>>',lambda _:self.app_selected())
        outer,p=self._card(pg,14);outer.pack(fill='x',pady=(13,0))
        self.app_detail=self._text(p,'Choose an application to configure its network route.',color=MUTED,wrap=780)
        self.app_detail.pack(anchor='w',pady=(0,12))
        row=tk.Frame(p,bg=SURFACE);row.pack(fill='x')
        self.app_mode=tk.StringVar(value=ROUTES['auto'])
        self.app_combo=ttk.Combobox(row,state='readonly',textvariable=self.app_mode,
                                     values=list(ROUTES.values()),width=22)
        self.app_combo.pack(side='left',padx=(0,10))
        self.manage_menu=tk.BooleanVar(value=False)
        self.check_menu=ttk.Checkbutton(row,variable=self.manage_menu,text='Manage menu launches')
        self.check_menu.pack(side='left',padx=(0,12))
        self.restart_services=tk.BooleanVar(value=False)
        ttk.Checkbutton(row,variable=self.restart_services,text='Restart related services').pack(side='left',padx=(0,12))
        self.apply_app=self._button(row,'Apply to whole app',self.apply_group,primary=True)
        self.apply_app.pack(side='left',padx=(0,8))
        self.run_app=self._button(row,'Launch selected app',self.launch_group)
        self.run_app.pack(side='left')
        self._text(p,'GNOME-aware apps can adapt to system proxy changes live. Env-only apps need relaunch; services restart only with approval.',
                   size=9,color=MUTED,wrap=820).pack(anchor='w',pady=(12,0))

    def _process_page(self):
        pg=self.pages['processes']
        top=tk.Frame(pg,bg=BG);top.pack(fill='x',pady=(5,11))
        self._text(top,'Inspect background apps, browser helpers, and automation runs safely',color=MUTED).pack(side='left')
        self.process_search=tk.StringVar()
        ttk.Entry(top,textvariable=self.process_search,width=27).pack(side='right')
        self.process_search.trace_add('write',lambda *_:self.draw_processes())
        bar=tk.Frame(pg,bg=BG);bar.pack(fill='x',pady=(0,10))
        self.review_only=tk.BooleanVar(value=False)
        ttk.Checkbutton(bar,text='Show review candidates only',variable=self.review_only,
                        command=self.draw_processes).pack(side='left')
        self._text(bar,'No processes are terminated automatically',size=9,color=AMBER).pack(side='right')
        holder=tk.Frame(pg,bg=SURFACE)
        self.process_tree=ttk.Treeview(holder,columns=('PIDs','RAM (MB)','CPU %','Review'),
                                      show='tree headings',selectmode='browse',style='Process.Treeview',height=7)
        self.process_tree.heading('#0',text='Application / process')
        self.process_tree.column('#0',width=265,stretch=True)
        for col,w in [('PIDs',80),('RAM (MB)',100),('CPU %',80),('Review',275)]:
            self.process_tree.heading(col,text=col)
            self.process_tree.column(col,width=w,stretch=col=='Review')
        sc=ttk.Scrollbar(holder,orient='vertical',command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=sc.set)
        self.process_tree.pack(side='left',fill='both',expand=True)
        sc.pack(side='right',fill='y')
        holder.pack(fill='both',expand=True)
        self.process_tree.bind('<<TreeviewSelect>>',lambda _:self.process_selected())
        outer,p=self._card(pg,16);outer.pack(fill='x',pady=(13,0))
        self.process_detail=self._text(p,'Select a process group to see its details and signals.',
                                        color=MUTED,wrap=820)
        self.process_detail.pack(anchor='w',pady=(0,12))
        row=tk.Frame(p,bg=SURFACE);row.pack(fill='x')
        self._button(row,'Edit route',self.edit_process_route,primary=True).pack(side='left',padx=(0,8))
        self._button(row,'Stop group (SIGTERM)',self.stop_group,danger=True).pack(side='left',padx=(0,8))
        self._button(row,'Stop automation only',self.stop_automation).pack(side='left',padx=(0,8))
        self._button(row,'Force stop (SIGKILL)',lambda:self.stop_group(force=True)).pack(side='left',padx=(0,8))
        self._button(row,'Inspect PIDs',self.inspect_pids).pack(side='left')
        self._text(p,'No window or low CPU does not mean idle. Background services and tests may be active; save your work first.',
                   color=MUTED,size=9,wrap=810).pack(anchor='w',pady=(12,0))

    def _system_page(self):
        pg=self.pages['system']
        outer,p=self._card(pg,22);outer.pack(fill='x',pady=(8,16))
        self._text(p,'System-wide proxy mode — no TUN',size=17,bold=True).pack(anchor='w')
        self._text(p,'Applies GNOME proxy settings immediately for clients that monitor them, and systemd variables for NEW processes.\nDoes not require reboot. Existing environment-only apps may need relaunch. Not a TUN.',
                   color=MUTED,wrap=760).pack(anchor='w',pady=(12,20))
        self.global_choice=tk.StringVar(value='off')
        selections=tk.Frame(p,bg=SURFACE);selections.pack(anchor='w')
        for value,label in [('off','Off — restore previous settings'),('direct','Direct'),('auto','Auto — Proxy then Direct'),('proxy','Proxy — No direct fallback')]:
            ttk.Radiobutton(selections,text=label,value=value,variable=self.global_choice,
                            style='TRadiobutton').pack(anchor='w',pady=5)
        self._button(p,'Apply system-wide mode',self.apply_global,primary=True).pack(anchor='w',pady=(19,11))
        self.global_detail=self._text(p,'—',size=10,color=MUTED)
        self.global_detail.pack(anchor='w')
        box,inner=self._card(pg,14);box.pack(fill='x',pady=(0,13))
        self._text(inner,'What Linux is REALLY configured to use',size=12,bold=True).pack(anchor='w')
        self.system_health_text=self._text(inner,'Reading settings...',size=10,color=MUTED,wrap=900)
        self.system_health_text.pack(anchor='w',pady=(8,5))
        self._button(inner,'Refresh Linux status',self.refresh_system_health).pack(anchor='w')
        outer,p=self._card(pg,18);outer.pack(fill='x')
        self._text(p,'Before enabling',size=12,bold=True,color=AMBER).pack(anchor='w')
        self._text(p,'1. Existing GNOME preferences are backed up and restored when this mode is disabled.\n2. Other files (including environment.d settings) are not deleted or overwritten.\n3. Existing apps may need to restart.\n4. A service-specific override may take precedence.',
                   color=MUTED,wrap=790).pack(anchor='w',pady=(10,0))

    def _settings_page(self):
        pg=self.pages['settings']
        outer,p=self._card(pg,22);outer.pack(fill='x',pady=(7,15))
        self._text(p,'Upstream SOCKS5 server (v2rayN / Xray)',size=15,bold=True).pack(anchor='w',pady=(0,15))
        self.host=tk.StringVar(value='127.0.0.1');self.port=tk.StringVar(value='10808')
        for lbl,var in [('Host (loopback only)',self.host),('SOCKS5 port',self.port)]:
            r=tk.Frame(p,bg=SURFACE);r.pack(fill='x',pady=6)
            self._text(r,lbl,size=10).pack(side='left',padx=(0,18))
            ttk.Entry(r,textvariable=var,width=28).pack(side='left')
        self._text(p,'Direct-bypass domains (one per line; prefix a domain with . for subdomains)',
                   size=10,color=MUTED).pack(anchor='w',pady=(19,7))
        self.bypass=tk.Text(p,height=7,relief='flat',bg=SURFACE_2,fg=TEXT,insertbackground=TEXT,
                            highlightbackground=SURFACE_3,highlightthickness=1,font=(FONT,10),padx=9,pady=9)
        self.bypass.pack(fill='x')
        self.allow_fallback=tk.BooleanVar(value=True)
        ttk.Checkbutton(p,text='Allow AUTO to fall back to direct connections if SOCKS5 fails',
                        variable=self.allow_fallback).pack(anchor='w',pady=(11,0))
        self.monitor_on=tk.BooleanVar(value=True)
        ttk.Checkbutton(p,text='Record connection metadata in Live Traffic (host, route, PID; no URL paths)',
                        variable=self.monitor_on).pack(anchor='w',pady=(13,0))
        self._button(p,'Save settings',self.save_settings,primary=True).pack(anchor='w',pady=(18,0))
        outer,p=self._card(pg,18);outer.pack(fill='x')
        self._text(p,'Coverage & safety',size=12,bold=True).pack(anchor='w')
        self._text(p,'The bridge listens on 127.0.0.1 only. Managed apps can switch routes for NEW connections.\nAUTO fallback is configurable; turn it off to fail closed when SOCKS5 is unavailable.\nApplications that ignore HTTP_PROXY/HTTPS_PROXY and system settings may bypass these rules.',
                   color=MUTED,wrap=800).pack(anchor='w',pady=(11,0))

    def _traffic_page(self):
        pg=self.pages['traffic']
        banner,p=self._card(pg,14)
        banner.pack(fill='x',pady=(3,11))
        self._text(p,'Technical connections — start with Check an app for a plain-language status',size=12,bold=True).pack(anchor='w')
        self._text(p,'BRIDGE: ProxyPilot can report a route. OTHER PROXY: only a TCP connection to Xray is visible, not the final website or egress IP. Other external TCP is shown on Check an app. This is NOT full traffic capture.',
                   color=MUTED,size=9,wrap=890).pack(anchor='w',pady=(7,0))
        statrow=tk.Frame(pg,bg=BG);statrow.pack(fill='x',pady=(0,10))
        self.traffic_stats={}
        for i,(key,label) in enumerate([('requests','Observed'),('proxy','Via SOCKS5'),('direct','Direct / bypass'),('fallback','Fallback'),('failed','Failed'),('external','Other proxy sockets')]):
            outer,inner=self._card(statrow,10);outer.grid(row=0,column=i,sticky='nsew',padx=3)
            statrow.grid_columnconfigure(i,weight=1)
            self._text(inner,label,color=MUTED,size=9).pack(anchor='w')
            val=self._text(inner,'0',size=18,bold=True);val.pack(anchor='w')
            self.traffic_stats[key]=val
        controls=tk.Frame(pg,bg=BG);controls.pack(fill='x',pady=(1,9))
        self.traffic_filter=tk.StringVar(value='All')
        ttk.Combobox(controls,textvariable=self.traffic_filter,state='readonly',
                     values=['All','Proxy','Direct','Fallback','Failed','Other proxy'],width=13).pack(side='left',padx=(0,7))
        self.traffic_filter.trace_add('write',lambda *_:self.draw_traffic())
        self.traffic_search=tk.StringVar()
        ttk.Entry(controls,textvariable=self.traffic_search,width=27).pack(side='left',padx=(0,7))
        self.traffic_search.trace_add('write',lambda *_:self.draw_traffic())
        self._button(controls,'Export CSV',self.export_traffic).pack(side='right',padx=(7,0))
        self._button(controls,'Erase logs',self.erase_traffic,danger=True).pack(side='right',padx=(7,0))
        self.pause_button=self._button(controls,'Pause view',self.toggle_traffic_pause)
        self.pause_button.pack(side='right')
        holder,self.traffic_tree=self._table(pg,
            ('Time','Application / PID','Destination','Actual route','Status','Upload','Download'),
            (90,170,220,130,105,90,90))
        holder.pack(fill='both',expand=True)
        for tag,col in [('proxy',GREEN),('fallback',AMBER),('direct',BLUE),('error',RED),('bypass',MUTED),('external',GREEN)]:
            self.traffic_tree.tag_configure(tag,foreground=col)
        self.traffic_tree.bind('<<TreeviewSelect>>',lambda _:self.traffic_selected())
        box,inner=self._card(pg,13);box.pack(fill='x',pady=(10,0))
        self.traffic_detail=self._text(inner,'Select a connection for route and attribution details.',
                                       size=9,color=MUTED,wrap=860)
        self.traffic_detail.pack(anchor='w')
        self.traffic_rows={}

    def _traffic_tick(self):
        if not self.winfo_exists():return
        if not self.traffic_paused:
            try:
                self.traffic_reader.poll()
                self.draw_traffic()
                stats=self.traffic_reader.summary()
                for k,v in self.traffic_stats.items():v.configure(text=str(stats.get(k,0)))
                self.stat_values['proxies'].configure(text=str(stats['proxy']))
                self.traffic_stats['external'].configure(text=str(len(self.external_sockets)))
                self._sample_other_proxies()
            except Exception as e:self.notice_msg('Traffic monitor: '+str(e),True)
        self.after(2500,self._traffic_tick)

    def _sample_other_proxies(self):
        """Background, read-only snapshot: can never change app proxy routing."""
        if self.socket_running:return
        self.socket_running=True
        cfg=core.load()
        socks=int(cfg.get('upstream_port',10808))
        ports={socks,int(cfg.get('auto_port',18787)),int(cfg.get('proxy_port',18789))}
        ports.update(int(v) for v in cfg.get('app_ports',{}).values())
        def work():
            try: result=socketwatch.observe(ports)
            except Exception:result=[]
            def update():
                self.socket_running=False
                self.external_sockets=result
                self.draw_traffic()
            try:self.after(0,update)
            except tk.TclError:pass
        threading.Thread(target=work,daemon=True).start()

    def _group_icon(self,group):
        icon_name=next((a.get('icon') for a in group['apps'] if a.get('icon')), '')
        if not icon_name:
            names={'firefox':'firefox','python':'python3','terminal':'utilities-terminal'}
            icon_name=names.get(group['id'],group['id'])
        photo=self.icons.load(icon_name)
        if photo:return photo
        for fallback in ('application-x-executable','application-default-icon','system-run'):
            photo=self.icons.load(fallback)
            if photo:return photo
        return None

    def draw_traffic(self):
        if not hasattr(self,'traffic_tree'):return
        self.traffic_tree.delete(*self.traffic_tree.get_children())
        filt=self.traffic_filter.get().lower()
        search=self.traffic_search.get().strip().lower()
        self.traffic_rows={}
        pid_groups={p['pid']:g['name'] for g in self.groups for p in g['processes']}
        apps={a['id']:a['name'] for g in self.groups for a in g['apps']}
        for idx,e in enumerate(self.traffic_reader.connections()):
            route=e.get('route','unknown')
            if filt=='proxy' and route!='proxy':continue
            if filt=='direct' and route not in ('direct','bypass'):continue
            if filt=='fallback' and route!='fallback':continue
            if filt=='failed' and e.get('event')!='error' and e.get('status')!='failed':continue
            if filt=='other proxy':continue
            proc=apps.get(e.get('app_id')) or e.get('process') or 'Unattributed'
            pid=e.get('pid')
            name=proc+(f'  ·  {pid}' if pid else '  ·  PID ?')
            host=e.get('host') or '?'
            dest=host+(':'+str(e.get('port')) if e.get('port') else '')
            if search not in (name+' '+dest+' '+route+' '+(e.get('scope') or '')).lower():continue
            if len(self.traffic_rows)>=320:break
            row_id='conn'+str(idx)
            self.traffic_rows[row_id]=e
            tm=datetime.fromtimestamp(e.get('ts',0)).strftime('%H:%M:%S')
            fmt=lambda v: ('—' if v is None else (f'{v/1024:.1f} KB' if v>=1024 else str(v)+' B'))
            values=(tm,name,dest,route.upper(),e.get('status','—'),fmt(e.get('bytes_up')),fmt(e.get('bytes_down')))
            tag='error' if e.get('event')=='error' or e.get('status')=='failed' else route
            self.traffic_tree.insert('','end',iid=row_id,values=values,tags=(tag,))
        # Separate LIVE socket snapshot: DO NOT claim it is a bridge request.
        # A connection to Xray may be a long-lived tunnel, not a fresh request.
        if filt in ('all','other proxy','proxy'):
            upstream=int(core.load().get('upstream_port',10808))
            for i,e in enumerate(self.external_sockets):
                if e['remote_port']!=upstream:continue
                pid=e['pid'];name=pid_groups.get(pid,e['process'])
                dest=f"{e['remote_ip']}:{e['remote_port']}"
                if search not in (name+' '+dest+' external proxy '+str(pid)).lower():continue
                iid='socket'+str(i)
                item=dict(event='socket',scope='external local SOCKS (not ProxyPilot)',
                          mode='external',route='external',status='TCP live',pid=pid,process=name,
                          host=e['remote_ip'],port=e['remote_port'],error='',duration_ms=None)
                self.traffic_rows[iid]=item
                self.traffic_tree.insert('','end',iid=iid,values=(datetime.now().strftime('%H:%M:%S'),
                    f'{name}  ·  {pid}',dest,'SOCKS (external)','TCP active','—','—'),tags=('external',))

    def traffic_selected(self):
        selected=self.traffic_tree.selection()
        if not selected:return
        e=self.traffic_rows.get(selected[0])
        if not e:return
        self.traffic_detail.configure(text=(
            f"Mode: {e.get('mode','?')}  •  Actual route: {e.get('route','unknown')}  •  "
            f"Source: {e.get('scope','?')}  •  PID: {e.get('pid') or 'unavailable'}  •  "
            f"Duration: {e.get('duration_ms','—')} ms  •  "
            f"Error: {e.get('error') or 'none'}"))

    def toggle_traffic_pause(self):
        self.traffic_paused=not self.traffic_paused
        self.pause_button.configure(text='Resume view' if self.traffic_paused else 'Pause view')

    def export_traffic(self):
        path=filedialog.asksaveasfilename(parent=self,title='Export observed proxy connections',
                                         defaultextension='.csv',filetypes=[('CSV files','*.csv')])
        if path:
            try:
                self.traffic_reader.export_csv(path)
                self.notice_msg('Exported observed bridge connections')
            except Exception as e:messagebox.showerror('Export failed',str(e),parent=self)

    def erase_traffic(self):
        if not messagebox.askyesno('Erase ProxyPilot traffic history',
                'Delete ProxyPilot traffic logs? This does NOT delete traffic from other apps.\n'
                'New connections will continue to be logged.',parent=self):return
        try:
            traffic.clear_history()
            self.traffic_reader=traffic.TrafficReader()
            self.draw_traffic()
            self.notice_msg('Traffic log erased')
        except Exception as e:messagebox.showerror('Erase failed',str(e),parent=self)

    def inspect_pids(self):
        g=self._selected_group(self.process_tree)
        if not g:return
        top=tk.Toplevel(self)
        top.title('Process detail — '+g['name'])
        top.geometry('1020x560');top.configure(bg=BG)
        self._text(top, f"{g['name']} · {len(g['processes'])} processes · confirm before stopping any PID",
                   size=12,bold=True).pack(anchor='w',padx=18,pady=14)
        frame,tree=self._table(top,('PID','Parent','Executable','CPU %','RAM MB','Age','State','Flags'),
                              (78,75,220,90,100,100,70,180))
        frame.pack(fill='both',expand=True,padx=18,pady=8)
        flagged=set(self.review_map.get(g['id'],{}).get('auto_pids',[]))
        snapshot={str(p['pid']):p for p in g['processes']}
        for p in g['processes']:
            age=p.get('age_s',0)
            age_txt=f'{age//3600}h {age%3600//60}m' if age>=3600 else f'{age//60}m'
            flags='Review automation' if p['pid'] in flagged else ('Zombie' if p.get('state')=='Z' else '—')
            tree.insert('','end',iid=str(p['pid']),values=(p['pid'],p['ppid'],p['cmd'],
                      p.get('cpu_percent','—'),round(p['rss_kb']/1024),age_txt,p['state'],flags))
        controls=tk.Frame(top,bg=BG);controls.pack(fill='x',padx=18,pady=12)
        self._text(controls,'Idle CPU or no window is not proof a process is unused.',size=9,color=AMBER).pack(side='left')
        def stop_one(force=False):
            selection=tree.selection()
            if not selection:return
            p=snapshot.get(selection[0])
            if not p:return
            if p['state']=='Z':
                messagebox.showinfo('Zombie process','A zombie cannot be terminated directly; inspect its parent.',parent=top)
                return
            if not messagebox.askyesno('Stop selected PID',
                f"Stop {p['cmd']} (PID {p['pid']}) with {'SIGKILL' if force else 'SIGTERM'}?\n"
                'Unsaved work may be lost.',parent=top):return
            if force and not messagebox.askyesno('Confirm force stop','Force stop without cleanup?',parent=top):return
            result=manager.terminate_verified([p],'KILL' if force else 'TERM')
            messagebox.showinfo('Signal result',str(result),parent=top)
            self.refresh()
        self._button(controls,'Stop selected (TERM)',lambda:stop_one(False),danger=True).pack(side='right',padx=(8,0))
        self._button(controls,'Force selected',lambda:stop_one(True)).pack(side='right')

    def notice_msg(self,text,error=False):
        self.notice.configure(text=text,fg=RED if error else (GREEN if 'successfully' in text else MUTED))

    def refresh(self):
        if self.scanning:return
        self.scanning=True
        def worker():
            try:
                groups=manager.inventory(self.sampler)
                reviews=manager.cleanup_candidates(groups)
                config=core.load()
                state=(groups,reviews,config,None)
            except Exception as ex:state=(None,None,None,str(ex))
            self.after(0,lambda:self._refresh_done(*state))
        threading.Thread(target=worker,daemon=True).start()
        self.check_health()

    def _refresh_done(self,groups,reviews,config,error):
        self.scanning=False
        if error:
            self.notice_msg('Scan failed: '+error,True);return
        self.groups=groups;self.group_map={g['id']:g for g in groups}
        self.review_map={x['id']:x for x in reviews}
        self.draw_apps();self.draw_processes();self.draw_check_apps()
        self.stat_values['apps'].configure(text=str(len(groups)))
        self.stat_values['running'].configure(text=str(sum(g['process_count'] for g in groups)))
        self.stat_values['review'].configure(text=str(len(reviews)))
        self.stat_values['global'].configure(text=config.get('global_mode','off').upper())
        self.global_choice.set(config.get('global_mode','off'))
        self.global_detail.configure(text='Current profile: '+config.get('global_mode','off').upper())
        self.host.set(config['upstream_host']);self.port.set(str(config['upstream_port']))
        self.monitor_on.set(config.get('traffic_monitor_enabled',True))
        self.allow_fallback.set(config.get('allow_direct_fallback',True))
        current='\n'.join(config['bypass_hosts'])
        if not self.bypass.edit_modified():
            self.bypass.delete('1.0','end');self.bypass.insert('1.0',current)
            self.bypass.edit_modified(False)
        self.notice_msg(f'Scanned: {len(groups)} groups and {len(reviews)} review candidates')
        self.refresh_system_health()

    def refresh_system_health(self):
        """Read GNOME and user systemd proxy settings without changing anything."""
        if getattr(self,'system_health_busy',False):return
        self.system_health_busy=True
        def work():
            try:snap=diagnostics.system_snapshot(core.load())
            except Exception as ex:snap={'error':str(ex)}
            def show():
                self.system_health_busy=False
                if not self.winfo_exists():return
                if 'error' in snap:
                    self.system_health_text.configure(text='Could not read Linux proxy settings: '+snap['error'],fg=AMBER)
                    return
                self._last_system_snapshot=snap
                gnome=', '.join(f'{k}={v}' for k,v in snap['gnome'].items()) or 'not configured'
                env=', '.join(sorted(set(v for v in snap['systemd'].values() if v))) or 'none'
                notes='\n'.join('Review: '+n for n in snap['notes'])
                self.system_health_text.configure(text=f'ProxyPilot saved: {snap["proxy_pilot_mode"]} | '
                    f'GNOME: {snap["gnome_mode"]} ({gnome})\n'
                    f'user systemd env: {env}\n'
                    f'Xray target: {snap["upstream"]} | ProxyPilot AUTO: {snap["bridge"]}'
                    +(f'\n{notes}' if notes else '\nNo known conflicts detected.'))
            try:self.after(0,show)
            except tk.TclError:pass
        threading.Thread(target=work,daemon=True).start()

    def _periodic(self):
        if self.winfo_exists():
            self.refresh();self.after(10000,self._periodic)

    def check_health(self):
        if self.health_running:return
        self.health_running=True
        def worker():
            try: ok=core.upstream_ok(core.load())
            except Exception:ok=False
            def done():
                self.health_running=False
                self.health_text.configure(text='● SOCKS5 reachable' if ok else '● SOCKS5 unavailable',
                                           fg=GREEN if ok else RED)
            self.after(0,done)
        threading.Thread(target=worker,daemon=True).start()

    def draw_apps(self):
        if not hasattr(self,'apps_tree'):return
        selected=self.apps_tree.selection()
        query=self.app_search.get().strip().casefold()
        self.apps_tree.delete(*self.apps_tree.get_children())
        for g in self.groups:
            if query not in (g['name']+' '+g['id']+' '+','.join(g['services'])).casefold():continue
            route=ROUTES.get(g['mode'],g['mode']).split(' —')[0]
            if g['mode']=='unmanaged' and g['process_count'] and core.load().get('global_mode','off') in ('auto','proxy'):
                route='System profile*'
            comps=f"{len(g['apps'])} app / {len(g['services'])} service"
            status='Live bridged' if g['bridged_count'] else ('OS proxy possible' if g['process_count'] and core.load().get('global_mode','off') in ('auto','proxy') else ('Relaunch may help' if g['process_count'] and g['mode']!='unmanaged' else ('Running' if g['process_count'] else '—')))
            photo=self._group_icon(g)
            args={'image':photo} if photo else {}
            self.apps_tree.insert('','end',iid=g['id'],text='  '+g['name'],values=(route,g['process_count'],comps,status),**args)
        if selected and self.apps_tree.exists(selected[0]):self.apps_tree.selection_set(selected[0])

    def app_selected(self):
        sel=self.apps_tree.selection()
        if not sel:return
        g=self.group_map.get(sel[0]);self.selected_id=sel[0]
        if not g:return
        self.app_mode.set(ROUTES.get(g['mode'],ROUTES['unmanaged']))
        self.manage_menu.set(any(a['managed'] for a in g['apps']))
        recent=sum(1 for e in self.traffic_reader.connections() if e.get('app_id') in {a['id'] for a in g['apps']})
        txt=(f"{g['name']}   |   {g['process_count']} processes  •  {len(g['apps'])} launchers  •  {len(g['services'])} services\n"
             f"Live bridged: {g['bridged_count']} processes  |  {g['memory_mb']} MB RAM\n"
             f"Services: {', '.join(g['services']) if g['services'] else 'none'}  |  observed app-bridge requests: {recent}")
        if g['mode']=='unmanaged':
            txt+='\nUnmanaged = no per-app ProxyPilot launcher rule; system GNOME proxy may still apply.'
        self.app_detail.configure(text=txt)

    def _selected_group(self,tree):
        sel=tree.selection()
        if not sel:
            messagebox.showinfo('ProxyPilot','Choose an application first.',parent=self);return None
        return self.group_map.get(sel[0])

    def apply_group(self):
        g=self._selected_group(self.apps_tree)
        if not g:return
        mode=next((m for m,txt in ROUTES.items() if txt==self.app_mode.get()),'unmanaged')
        manage=self.manage_menu.get()
        if not g['apps'] and not g['services']:
            messagebox.showwarning('Limited routing support',
                'This item was found in processes only and has no known desktop launcher or service.\n'
                'A known launch method is required to manage all of its network connections.',parent=self)
            return
        details=[f'App: {g["name"]}',f'Route: {ROUTES[mode]}',
                 f'Launchers: {len(g["apps"])}'+(' (manage menu launches)' if manage else ' (leave original launcher)'),
                 f'Services: {len(g["services"])}'+(' (will restart)' if self.restart_services.get() else ' (left running)'),
                 f'Existing processes: {g["process_count"]}',
                 '', 'Existing app instances may follow live GNOME changes; environment-only clients require a relaunch.',
                 'Custom launchers are backed up before modification.']
        if not messagebox.askyesno('Apply unified route','\n'.join(details)+'\n\nContinue?',parent=self):return
        self.notice_msg('Applying the rule across recognized app components...')
        def worker():
            try:result=manager.set_group_mode(g['id'],mode,manage_launchers=manage,restart_services=self.restart_services.get())
            except Exception as ex:result={'errors':[str(ex)],'changed':[]}
            self.after(0,lambda:self._after_apply(result))
        threading.Thread(target=worker,daemon=True).start()

    def _after_apply(self,result):
        if result['errors']:
            messagebox.showwarning('Partially applied','Some components were not updated:\n'+'\n'.join(result['errors']),parent=self)
        else:self.notice_msg('Route saved. New launchers use it if integrated; services require approved restart.')
        self.refresh()

    def launch_group(self):
        g=self._selected_group(self.apps_tree)
        if not g:return
        if not g['apps']:
            messagebox.showinfo('ProxyPilot','This group has no launchable desktop entry.',parent=self);return
        try:
            pid=core.launch(g['apps'][0]['id'])
            self.notice_msg(f'Launched: {g["name"]} (PID {pid})')
            self.after(1800,self.refresh)
        except Exception as ex:messagebox.showerror('Launch failed',str(ex),parent=self)

    def draw_processes(self):
        if not hasattr(self,'process_tree'):return
        selected=self.process_tree.selection()
        self.process_tree.delete(*self.process_tree.get_children())
        query=self.process_search.get().strip().casefold()
        for g in self.groups:
            if not g['process_count']:continue
            if self.review_only.get() and g['id'] not in self.review_map:continue
            if query not in (g['name']+' '+g['id']).casefold():continue
            review=self.review_map.get(g['id'])
            reason=('; '.join(review['reasons'])[:65]+'…') if review else 'No specific flags'
            photo=self._group_icon(g)
            self.process_tree.insert('','end',iid=g['id'],text='  '+g['name'],
                                     image=photo if photo else '',
                                     values=(g['process_count'],g['memory_mb'],
                                             f"{g.get('cpu_percent',0):.1f}",reason))
        if selected and self.process_tree.exists(selected[0]):self.process_tree.selection_set(selected[0])

    def process_selected(self):
        g=self._selected_group(self.process_tree)
        if not g:return
        review=self.review_map.get(g['id'])
        reasons='; '.join(review['reasons']) if review else 'No review flags detected.'
        pids=', '.join(str(p['pid']) for p in g['processes'][:20])
        if len(g['processes'])>20:pids+=f' ... and {len(g["processes"])-20} more'
        self.process_detail.configure(text=f"{g['name']} — {g['process_count']} processes — {g['memory_mb']} MB, CPU {g.get('cpu_percent',0):.1f}%\nPID: {pids}\nReview: {reasons}")

    def edit_process_route(self):
        group=self._selected_group(self.process_tree)
        if not group:return
        self.app_search.set('')
        self.switch('apps')
        if self.apps_tree.exists(group['id']):
            self.apps_tree.selection_set(group['id'])
            self.apps_tree.see(group['id'])
            self.app_selected()

    def stop_automation(self):
        g=self._selected_group(self.process_tree)
        if not g:return
        review=self.review_map.get(g['id'])
        if not review or not review['auto_pids']:
            messagebox.showinfo('ProxyPilot','No flagged headless/automation PIDs in this group.',parent=self);return
        targets=[p for p in g['processes'] if p['pid'] in review['auto_pids']]
        self._confirm_kill(g,targets,False,'automation processes')

    def stop_group(self,force=False):
        g=self._selected_group(self.process_tree)
        if not g:return
        self._confirm_kill(g,g['processes'],force,'all group processes')

    def _confirm_kill(self,g,targets,force,scope):
        sig='SIGKILL' if force else 'SIGTERM'
        if not messagebox.askyesno('Warning: process termination',
                f'{g["name"]}\n{scope}: {len(targets)} processes\nSignal: {sig}\n\n'
                'This may close tabs, tests, or unsaved data.\n'
                'Continue?',parent=self):return
        if force and not messagebox.askyesno('Final confirmation',
                'SIGKILL allows no save or cleanup. Really force stop these processes?',parent=self):return
        out=manager.terminate_verified(targets,'KILL' if force else 'TERM')
        self.notice_msg(f"Sent signal to {len(out['signaled'])} processes; protected/skipped: {len(out['skipped'])}")
        self.after(1200,self.refresh)

    def apply_global(self):
        mode=self.global_choice.get()
        detail='Restore previous settings' if mode=='off' else (
            f'Enable {mode} for proxy-aware apps (NOT all network traffic)')
        if not messagebox.askyesno('System-wide proxy mode',
                detail+'\n\nGNOME and user systemd environment settings will change.\n'
                'GNOME-aware apps can switch live; env-only apps may need relaunch. No system reboot needed.\n\nContinue?',parent=self):return
        self.notice_msg('Applying system-wide proxy profile...')
        def worker():
            try:manager.GlobalProxy().apply(mode);error=None
            except Exception as ex:error=str(ex)
            self.after(0,lambda:self._global_done(mode,error))
        threading.Thread(target=worker,daemon=True).start()

    def _global_done(self,mode,error):
        if error:messagebox.showerror('System-wide settings error',error,parent=self)
        else:self.notice_msg('System proxy changed live (GNOME). Existing env-only apps may need relaunch: '+mode)
        self.refresh()

    def save_settings(self):
        try:
            host=self.host.get().strip();port=int(self.port.get())
            if host not in ('localhost','127.0.0.1','::1') or not 1<=port<=65535:
                raise ValueError('Only a valid loopback host and port are allowed.')
            names=[x.strip() for x in self.bypass.get('1.0','end').splitlines() if x.strip()]
            import re
            if len(names)>100 or any(not re.fullmatch(r'[\w.:-]{1,253}',x) for x in names):
                raise ValueError('Invalid bypass domain list.')
            d=core.load();d.update(upstream_host=host,upstream_port=port,bypass_hosts=names,
                     traffic_monitor_enabled=self.monitor_on.get(),
                     allow_direct_fallback=self.allow_fallback.get())
            core.save(d)
            self.notice_msg('Proxy settings successfully saved')
            self.bypass.edit_modified(False)
            self.check_health()
        except Exception as ex:messagebox.showerror('Settings error',str(ex),parent=self)

if __name__=='__main__':
    try:ProxyPilot().mainloop()
    except tk.TclError as ex:
        print('Cannot open desktop: '+str(ex),file=sys.stderr)
        raise SystemExit(1)
