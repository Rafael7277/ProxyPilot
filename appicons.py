"""Native desktop-entry icon resolver for Tk. Optional rsvg-convert for SVG files."""
from __future__ import annotations
import base64
import math
import os
from pathlib import Path
import shutil
import subprocess
import tkinter as tk

PREFER = ('48x48/apps', '64x64/apps', '32x32/apps', 'scalable/apps', '128x128/apps', 'apps',
          '48x48/mimetypes', '64x64/mimetypes', 'scalable/mimetypes', '32x32/mimetypes')
EXT = ('.png', '.gif', '.svg')

class AppIcons:
    def __init__(self, root, size=40):
        self.root=root
        self.size=size
        self.cache={}
        self.photo_cache={}
        self.dirs=self._dirs()

    @staticmethod
    def _dirs():
        data_home=Path(os.environ.get('XDG_DATA_HOME',Path.home()/'.local/share'))
        roots=[data_home/'icons',Path.home()/'.icons',Path('/usr/share/icons'),
               Path('/usr/local/share/icons'),Path('/var/lib/flatpak/exports/share/icons'),
               data_home/'flatpak/exports/share/icons']
        folders=[Path('/usr/share/pixmaps'), Path('/usr/local/share/pixmaps'),Path('/var/lib/snapd/desktop/icons')]
        for root in roots:
            if not root.exists():continue
            try:
                for theme in root.iterdir():
                    if not theme.is_dir():continue
                    for size in PREFER:
                        folder=theme/size
                        if folder.is_dir():folders.append(folder)
            except OSError:continue
        return folders

    def find(self, icon_name):
        if not icon_name:return None
        icon_name=icon_name.strip()
        if icon_name in self.cache:return self.cache[icon_name]
        path=Path(icon_name)
        if path.is_absolute():
            res=path if path.is_file() else None
        elif '/' in icon_name or '\x00' in icon_name:
            res=None
        else:
            bases=[icon_name]
            if icon_name.endswith(EXT):bases=[icon_name.rsplit('.',1)[0]]
            res=None
            for folder in self.dirs:
                for base in bases:
                    for ext in EXT:
                        if ext=='.svg' and not shutil.which('rsvg-convert'): continue
                        p=folder/(base+ext)
                        if p.is_file():
                            res=p;break
                    if res:break
                if res:break
        self.cache[icon_name]=res
        return res

    def load(self, icon_name):
        if icon_name in self.photo_cache:return self.photo_cache[icon_name]
        path=self.find(icon_name)
        if not path:return None
        try:
            if path.suffix.casefold() == '.svg':
                if not shutil.which('rsvg-convert'):
                    return None
                png=subprocess.run(['rsvg-convert','--width',str(self.size),'--height',str(self.size),str(path)],
                                   stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3,check=True).stdout
                photo=tk.PhotoImage(master=self.root,data=base64.b64encode(png))
            else:
                photo=tk.PhotoImage(master=self.root,file=str(path))
                ratio=max(1,math.ceil(max(photo.width(),photo.height())/self.size))
                if ratio>1:photo=photo.subsample(ratio,ratio)
            self.photo_cache[icon_name]=photo
            return photo
        except (tk.TclError, OSError, subprocess.SubprocessError):
            return None
