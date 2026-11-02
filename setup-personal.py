#!/usr/bin/env python3
"""One-time local setup. Credentials are copied only into private application data."""
import argparse
import copy
import json
import os
from pathlib import Path
import sqlite3

parser = argparse.ArgumentParser()
parser.add_argument('--warp-config', type=Path, default=Path(__file__).resolve().parent.parent / 'warp-chain/config.private.json')
parser.add_argument('--source-data', type=Path, default=Path.home() / 'Library/Application Support/v2rayN')
parser.add_argument('--data-dir', type=Path, default=Path.home() / 'Library/Application Support/v2rayN-WARP')
args = parser.parse_args()
target = args.data_dir / 'guiConfigs'
if (target / 'guiNConfig.json').exists() or (target / 'guiNDB.db').exists():
    raise SystemExit('Personal configuration already exists; nothing overwritten.')
source = args.source_data / 'guiConfigs'
config = json.loads((source / 'guiNConfig.json').read_text())
warp_source = json.loads(args.warp_config.read_text())
warp = copy.deepcopy(next(x for x in warp_source.get('outbounds', [warp_source]) if x.get('protocol') == 'masque'))
warp['tag'] = 'personal-warp-entry'
warp.get('streamSettings', {}).get('sockopt', {}).pop('dialerProxy', None)
target.mkdir(parents=True, mode=0o700)
args.data_dir.chmod(0o700)
target.chmod(0o700)
with sqlite3.connect('file:' + str(source / 'guiNDB.db') + '?mode=ro', uri=True) as src:
    with sqlite3.connect(target / 'guiNDB.db') as dst:
        src.backup(dst)
        row = dst.execute("select IndexId from ProfileItem where Port=35141 and Address='mislog.shop' limit 1").fetchone()
        if row:
            config['IndexId'] = row[0]
config['SubIndexId'] = ''
config['WarpChainItem'] = {'Enabled': False, 'ProfileFile': 'warp-entry.private.json'}
config['SystemProxyItem']['SysProxyType'] = 2
config['TunModeItem']['EnableTun'] = False
config['UiItem']['MacOSShowInDock'] = True
config['UiItem']['AutoHideStartup'] = False
config['GuiItem']['AutoRun'] = False
config['GuiItem']['AutoUpdateInterval'] = 0
for inbound in config['Inbound']:
    inbound['LocalPort'] = 10818
    inbound['AllowLANConn'] = False
config['CheckUpdateItem']['SelectedCoreTypes'] = [x for x in config['CheckUpdateItem']['SelectedCoreTypes'] if x != 'v2rayN']
for name, data in [('guiNConfig.json', config), ('warp-entry.private.json', warp)]:
    path = target / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f, indent=2)
(target / 'guiNDB.db').chmod(0o600)
print('Personal data prepared. Original app unchanged. SOCKS/HTTP: 127.0.0.1:10818. WARP checkbox starts off.')
