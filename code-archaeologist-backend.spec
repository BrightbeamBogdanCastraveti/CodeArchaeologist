# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('detectors', 'detectors'), ('core', 'core'), ('ai', 'ai'), ('owasp', 'owasp'), ('research', 'research'), ('reports', 'reports'), ('vibe', 'vibe')]
binaries = []
hiddenimports = ['uvicorn.lifespan.on', 'uvicorn.lifespan.off', 'uvicorn.protocols.websockets.auto', 'uvicorn.protocols.http.auto', 'uvicorn.protocols.websockets.websockets_impl', 'uvicorn.protocols.http.h11_impl', 'uvicorn.logging', 'fastapi', 'openai', 'anthropic', 'dotenv']
tmp_ret = collect_all('fastapi')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('uvicorn')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['api/server.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='code-archaeologist-backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
app = BUNDLE(
    exe,
    name='code-archaeologist-backend.app',
    icon=None,
    bundle_identifier=None,
)
