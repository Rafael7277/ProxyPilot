"""Friendly 'Check an app' home page for ProxyPilot desktop.

Only *observes* running sockets; never silently changes or restarts apps.
"""
from __future__ import annotations
from datetime import datetime
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
import appstatus
import diagnostics
import manager
import netobserve
import proxypilot as core

BG='#0d1320';SURFACE='#151f30';MUTED='#a6b9d0';TEXT='#f1f5fc';GREEN='#54d3a4';AMBER='#ffce81';BLUE='#5b93ff';RED='#ff929b'
LABELS = {
    'unmanaged':'Use app / Linux settings',
    'direct':'Direct (compatible apps)',
    'auto':'Auto (proxy, then direct)',
    'proxy':'Proxy only (compatible apps)',
}


class CheckUI:
    def _check_page(self):
        pg = self.pages['check']
        self._text(pg,'1. Find your app   2. Start watching   3. Use the app normally   4. Read the actual evidence',
                   color=MUTED, size=10).pack(anchor='w',pady=(3,12))
        searchrow=tk.Frame(pg,bg=BG);searchrow.pack(fill='x',pady=(0,8))
        self._text(searchrow,'Find an app:',size=11,bold=True).pack(side='left',padx=(0,10))
        self.check_search=tk.StringVar()
        ttk.Entry(searchrow,textvariable=self.check_search,width=36).pack(side='left')
        self.check_search.trace_add('write',lambda *_:self.draw_check_apps())
        self._text(searchrow,'Status shows observation, NOT a promise of full coverage.',color=MUTED,size=9).pack(side='right')
        holder=tk.Frame(pg,bg=SURFACE)
        self.check_tree=ttk.Treeview(holder,columns=('running','chosen','observed'),show='tree headings',height=7,style='App.Treeview',selectmode='browse')
        self.check_tree.heading('#0',text='Application')
        self.check_tree.column('#0',width=235,stretch=True)
        for name,width in [('running',85),('chosen',210),('observed',270)]:
            self.check_tree.heading(name,text={'running':'Running','chosen':'Setting','observed':'Network evidence'}[name])
            self.check_tree.column(name,width=width,stretch=(name=='observed'))
        sc=ttk.Scrollbar(holder,orient='vertical',command=self.check_tree.yview)
        self.check_tree.configure(yscrollcommand=sc.set)
        self.check_tree.pack(side='left',fill='both',expand=True)
        sc.pack(side='right',fill='y')
        holder.configure(height=242)
        holder.pack(fill='x',expand=False)
        holder.pack_propagate(False)
        self.check_tree.bind('<<TreeviewSelect>>',lambda _:self.check_selected())
        info,inside=self._card(pg,10);info.pack(fill='x',pady=(8,7))
        self.check_name=self._text(inside,'Choose an application above',size=15,bold=True)
        self.check_name.pack(anchor='w')
        self.check_route=self._text(inside,'Requested setting: —',size=10,color=MUTED)
        self.check_route.pack(anchor='w',pady=(6,0))
        self.check_actual=self._text(inside,'Observed network: —',size=13,bold=True,color=AMBER)
        self.check_actual.pack(anchor='w',pady=(5,1))
        self.check_explain=self._text(inside,'Select an app to inspect its policy and recent connection evidence.',
                                      color=MUTED,size=9,wrap=860)
        self.check_explain.pack(anchor='w',pady=(2,1))
        self.check_evidence=self._text(inside,'Evidence: —',color=MUTED,size=9,wrap=880)
        self.check_evidence.pack(anchor='w',pady=(4,0))
        self.check_environment=self._text(inside,'Process environment: —',color=MUTED,size=9,wrap=880)
        self.check_environment.pack(anchor='w',pady=(3,0))
        self.check_system=self._text(inside,'Linux proxy: —',color=MUTED,size=9,wrap=880)
        self.check_system.pack(anchor='w',pady=(3,0))
        self.check_next=self._text(inside,'Next step: —',color=AMBER,size=9,wrap=880)
        self.check_next.pack(anchor='w',pady=(3,0))
        controls,out=self._card(pg,9);controls.pack(fill='x')
        row=tk.Frame(out,bg=SURFACE);row.pack(fill='x')
        self._text(row,'Connection choice:',size=10,bold=True).pack(side='left',padx=(0,12))
        self.check_choice=tk.StringVar(value=LABELS['unmanaged'])
        self.check_combo=ttk.Combobox(row,state='readonly',values=list(LABELS.values()),width=28,textvariable=self.check_choice)
        self.check_combo.pack(side='left',padx=(0,9))
        self.watch_btn=self._button(row,'Watch this app · 15s',self.start_watch,primary=True)
        self.watch_btn.pack(side='right')
        self._button(row,'Test proxy IP',self.test_proxy_ip).pack(side='right',padx=(0,8))
        self._button(row,'See current connections',self.show_connection_details).pack(side='right',padx=(0,8))
        row2=tk.Frame(out,bg=SURFACE);row2.pack(fill='x',pady=(6,1))
        self.check_manage=tk.BooleanVar(value=False)
        self.check_restart=tk.BooleanVar(value=False)
        ttk.Checkbutton(row2,variable=self.check_manage,text='Manage future menu launches').pack(side='left',padx=(0,14))
        ttk.Checkbutton(row2,variable=self.check_restart,text='Restart related user services (optional)').pack(side='left',padx=(0,14))
        self._button(row2,'Save selected rule',self.apply_check_route).pack(side='right')
        self.watch_progress=self._text(out,'Watching checks traffic only; it never restarts an app.',color=MUTED,size=9)
        self.watch_progress.pack(anchor='w',pady=(4,0))
        self._text(out,'If you save a rule without managing launches or restarting services, an already-running app may keep its previous route.',
                   color=MUTED,size=9,wrap=900).pack(anchor='w',pady=(3,0))
        self.watch_until=0
        self.watch_group=None
        self.since_rule_change={}
        self.check_selected_id=None

    def _group_observation(self,g,now=None):
        sockets,events=getattr(self,'_check_batch',(None,None))
        if sockets is None:sockets=self.net_recent.recent(now=now)
        if events is None:events=self.traffic_reader.connections()
        return appstatus.group_evidence(g,sockets,events,now=now,since=self.since_rule_change.get(g['id']))

    def draw_check_apps(self):
        if not hasattr(self,'check_tree'):return
        previous=self.check_tree.selection()
        search=self.check_search.get().strip().casefold()
        self.check_tree.delete(*self.check_tree.get_children())
        cfg=core.load()
        self._check_batch=(self.net_recent.recent(),self.traffic_reader.connections())
        mode=cfg.get('global_mode','off')
        for g in sorted(self.groups,key=lambda g:(not bool(g['process_count']),g['name'].casefold())):
            if search not in (g['name']+' '+g['id']+' '+','.join(g['services'])).casefold():continue
            outcome=self._group_observation(g)
            selected=LABELS.get(g['mode'],g['mode'])
            if g['mode']=='unmanaged' and mode!='off':selected+=' *'
            photo=self._group_icon(g)
            self.check_tree.insert('','end',iid=g['id'],text='  '+g['name'],
                                   image=photo if photo else '',
                                   values=(g['process_count'],selected,outcome['title']))
        if previous and self.check_tree.exists(previous[0]):
            self.check_tree.selection_set(previous[0])
        elif self.check_selected_id and self.check_tree.exists(self.check_selected_id):
            self.check_tree.selection_set(self.check_selected_id)
        elif self.check_tree.get_children():
            self.check_tree.selection_set(self.check_tree.get_children()[0])
        self.check_selected(update_choice=False)

    def check_selected(self,update_choice=True):
        chosen=self.check_tree.selection()
        if not chosen:return
        group=self.group_map.get(chosen[0]);
        if not group:return
        if self.check_selected_id!=group['id']:
            update_choice=True
        self.check_selected_id=group['id']
        if update_choice:
            self.check_choice.set(LABELS.get(group['mode'], LABELS['unmanaged']))
            self.check_manage.set(any(a.get('managed') for a in group['apps']))
            self.check_restart.set(False)
        ev=self._group_observation(group)
        self.check_name.configure(text=group['name']+('  ·  RUNNING' if group['process_count'] else '  ·  NOT RUNNING'))
        gmode=core.load().get('global_mode','off')
        self.check_route.configure(text='Rule on file: '+appstatus.requested_label(group,gmode)+
                                       '   |   Under ProxyPilot launcher: '+('yes' if group['integrated'] else 'no'))
        self.check_actual.configure(text='Observed: '+ev['title'],fg=GREEN if ev['level']=='confirmed' else (BLUE if ev['level']=='observed' else AMBER))
        msg=ev['explanation']
        self.check_explain.configure(text=msg)
        self.check_evidence.configure(text='Seen in last 90 seconds: '+('  |  '.join(ev['lines']) if ev['lines'] else 'no attributable connection.'))
        snapshot=diagnostics.app_snapshot(group,core.load(),sockets=self.net_recent.recent(),
                                          events=self.traffic_reader.connections())
        pe=snapshot['env']
        self.check_environment.configure(text='Running process proxy settings: '+pe['status']+'  |  '+pe['detail']+
                                              f'  ({pe["sampled"]} processes sampled)')
        syscfg=getattr(self,'_last_system_snapshot',None)
        if syscfg is not None:
            gn=syscfg['gnome']
            self.check_system.configure(text='Linux configuration: GNOME '+str(syscfg['gnome_mode'])+
                                       ' '+', '.join(f'{k}={v}' for k,v in gn.items())+
                                       '  |  user systemd: '+(', '.join(sorted(set(v for v in syscfg['systemd'].values() if v))) or 'unset'))
        if snapshot['overrides']:
            self.check_explain.configure(text=msg+'  Active service proxy drop-ins: '+'; '.join(snapshot['overrides'][:3]))
        self.check_next.configure(text='Next: '+appstatus.next_step(group,ev,gmode))
        if self.watch_until>time.time() and self.watch_group==group['id']:
            self.watch_progress.configure(text=f'WATCHING {group["name"]}: {max(1,int(self.watch_until-time.time()))} seconds left. Use that app now.',fg=GREEN)
        elif self.watch_group==group['id'] and self.watch_until:
            self.watch_progress.configure(text='Observation finished. No result means no matching connection was captured, not that the app is direct.',fg=MUTED)

    def show_connection_details(self):
        """Display real same-user socket and bridge observations; never imply full capture."""
        group=self._check_current_group()
        if not group:return
        top=tk.Toplevel(self)
        top.title(f'{group["name"]} — Network evidence (read only)')
        top.geometry('1050x615');top.minsize(830,490)
        top.configure(bg=BG)
        tk.Label(top,text=f'{group["name"]} · observed connections',font=('DejaVu Sans',16,'bold'),
                 bg=BG,fg=TEXT).pack(anchor='w',padx=20,pady=(15,5))
        details=self._text(top,'Collecting observed socket data...',color=MUTED,size=10,wrap=980)
        details.pack(anchor='w',padx=20,pady=(0,10))
        holder=tk.Frame(top,bg=SURFACE)
        cols=('pid','program','connection','remote','last')
        table=ttk.Treeview(holder,columns=cols,show='headings',height=12)
        for name,w in [('pid',90),('program',160),('connection',140),('remote',290),('last',130)]:
            table.heading(name,text={'pid':'PID','program':'Process','connection':'TCP peer type',
                                     'remote':'Peer (not final website)','last':'Last seen'}[name])
            table.column(name,width=w,stretch=name=='remote')
        scroll=ttk.Scrollbar(holder,orient='vertical',command=table.yview)
        table.configure(yscrollcommand=scroll.set)
        table.pack(side='left',fill='both',expand=True);scroll.pack(side='right',fill='y')
        holder.pack(fill='both',expand=True,padx=20,pady=(0,12))
        notes=self._text(top,'',color=AMBER,size=9,wrap=960)
        notes.pack(anchor='w',padx=20,pady=(0,8))
        action=tk.Frame(top,bg=BG);action.pack(fill='x',padx=20,pady=(0,16))

        def redraw():
            if not top.winfo_exists():return
            cfg=core.load()
            sockets=self.net_recent.recent()
            events=self.traffic_reader.connections()
            snap=diagnostics.app_snapshot(group,cfg,sockets,events)
            ev=snap['observed']
            table.delete(*table.get_children())
            for i,sock in enumerate(snap['sockets'][:150]):
                try:recent=time.strftime('%H:%M:%S',time.localtime(sock['last_seen']))
                except (ValueError,OverflowError):recent='?'
                table.insert('','end',iid=str(i),values=(sock['pid'],sock['process'],sock['kind'].upper(),
                                                    sock['peer'],recent))
            proxy=(snap['routes'].get('xray',0))
            bridge=(snap['routes'].get('bridge',0))
            ext=snap['routes'].get('external',0)
            env=snap['env']
            details.configure(text=f'Xray sockets: {proxy}  |  ProxyPilot sockets: {bridge}  |  Other external TCP: {ext}  |  '
                                   f'Process environment: {env["status"]}  |  Rule: {group.get("mode","unmanaged")}')
            warning='; '.join(snap['caveats']+snap['overrides'])
            notes.configure(text=warning or 'No route is inferred when there is no socket evidence. This view samples TCP only.')

        self._button(action,'Refresh snapshot',redraw,primary=True).pack(side='left')
        self._button(action,'Close',top.destroy).pack(side='right')
        self._text(action,'No sudo; no TLS decryption; old/short-lived connections may be absent.',
                   color=MUTED,size=9).pack(side='left',padx=14)
        redraw()

    def start_watch(self):
        g=self._check_current_group()
        if not g:return
        if not g['process_count']:
            messagebox.showinfo('Not running','Start the application first, then click Watch this app.',parent=self)
            return
        self.watch_group=g['id']
        self.watch_until=time.time()+15
        # Start a new observation window; keep other app history unaffected.
        self.since_rule_change[g['id']]=time.time()
        self.watch_progress.configure(text='Watching for 15 seconds. Make a fresh network request inside the app.',fg=GREEN)
        self._sample_network_now()
        self._watch_countdown()

    def _watch_countdown(self):
        if not self.winfo_exists(): return
        if time.time() < self.watch_until:
            self.check_selected(update_choice=False)
            self.after(700,self._watch_countdown)
        else:
            self.check_selected(update_choice=False)
            self.draw_check_apps()

    def test_proxy_ip(self):
        """Explicit third-party egress check; never claim to test a chosen app."""
        if not messagebox.askyesno('Test the ProxyPilot bridge',
            'Send two IP-only requests to https://api.ipify.org?\n\n'
            'One will use direct internet and one the ProxyPilot AUTO bridge.\n'
            'This checks the bridge only, NOT whether the selected application obeys its settings.',parent=self):return
        self.notice_msg('Checking direct and ProxyPilot exit IPs ...')
        def worker():
            import urllib.request
            url='https://api.ipify.org'
            results=[]
            for name,handlers in [
                ('Direct (no proxy)', {}),
                ('ProxyPilot AUTO bridge', {'http':'http://127.0.0.1:18787',
                                            'https':'http://127.0.0.1:18787'}),
            ]:
                try:
                    opener=urllib.request.build_opener(urllib.request.ProxyHandler(handlers))
                    with opener.open(url,timeout=9) as response:
                        ip=response.read(120).decode('ascii','replace').strip()
                    results.append((name,ip))
                except Exception as ex:results.append((name,'ERROR: '+str(ex)[:140]))
            def finished():
                text='\n'.join(f'{name}: {ip}' for name,ip in results)
                text+='\n\nThis tests the ProxyPilot bridge only, not a selected application.\n'
                if all(not ip.startswith('ERROR:') for _,ip in results):
                    if results[0][1]!=results[1][1]:text+='Different exit IPs were observed.'
                    else:text+='Same IP: could be fallback or a shared exit. Not proof of routing.'
                messagebox.showinfo('Network test result',text,parent=self)
                self.notice_msg('Network test complete (app routing still needs Watch this app).')
            try:self.after(0,finished)
            except tk.TclError:pass
        threading.Thread(target=worker,daemon=True).start()

    def _check_current_group(self):
        chosen=self.check_tree.selection()
        if not chosen:
            messagebox.showinfo('Select an app','Choose an application from the list first.',parent=self)
            return None
        return self.group_map.get(chosen[0])

    def apply_check_route(self):
        group=self._check_current_group()
        if not group:return
        mode=next((k for k,v in LABELS.items() if v==self.check_choice.get()),'unmanaged')
        manage=self.check_manage.get()
        restart=self.check_restart.get()
        if mode!='unmanaged' and not manage and not restart:
            note=('The rule will be SAVED, but may not change the already-running app.\n'
                  'To manage future menu launches, select the checkbox.\n'
                  'Unrelated application and service settings remain untouched.\n\n')
        else:note=''
        if not group['apps'] and not group['services']:
            messagebox.showwarning('No supported launch method',
                'This process has no recognized desktop launcher or user service. A saved rule could not control its network.',parent=self)
            return
        if not messagebox.askyesno('Save app routing rule',
            f"Application: {group['name']}\nChosen rule: {LABELS[mode]}\n"
            f"Manage menu launches: {'YES' if manage else 'NO'}\n"
            +('Previously managed launchers will be restored.\n' if mode=='unmanaged' else '')
            + f"Restart related user services: {'YES' if restart else 'NO'}\n\n"
            +note+'Proceed?',parent=self):return
        self.notice_msg('Applying app rule...')
        def work():
            try: result=manager.set_group_mode(group['id'],mode,manage_launchers=manage,restart_services=restart)
            except Exception as ex:result={'changed':[],'errors':[str(ex)]}
            try:self.after(0,lambda:self._finish_check_route(group['id'],result))
            except tk.TclError:pass
        threading.Thread(target=work,daemon=True).start()

    def _finish_check_route(self,group_id,result):
        self.since_rule_change[group_id]=time.time()
        if result.get('errors'):
            messagebox.showwarning('Rule needs attention','\n'.join(result['errors']),parent=self)
        else:
            messagebox.showinfo('Saved — verify traffic',
                'The rule was saved. This is NOT proof that a running program changed its network path.\n\n'
                'Use Watch this app and make a new request to check observed connections.\n'
                'GNOME-aware apps may switch live; other programs may need a relaunch.',parent=self)
        self.refresh()

    def _sample_network_now(self):
        if self.net_busy:return
        self.net_busy=True
        def worker():
            try: data=netobserve.observe(core.load());err=None
            except Exception as ex: data=[];err=str(ex)
            try:self.after(0,lambda:self._network_arrived(data,err))
            except tk.TclError:pass
        threading.Thread(target=worker,daemon=True).start()

    def _network_arrived(self,data,error):
        self.net_busy=False
        self.net_recent.update(data)
        if error:self.notice_msg('Network sample: '+error,True)
        if self.current=='check':
            self.draw_check_apps()
        elif self.current=='traffic':
            self.draw_traffic()

    def _net_tick(self):
        if not self.winfo_exists():return
        self._sample_network_now()
        delay=850 if self.watch_until>time.time() else 2200
        self.after(delay,self._net_tick)
