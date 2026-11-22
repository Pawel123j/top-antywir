# GUI screenshots

`gui-idle.png` and `gui-detection.png` come from the running CustomTkinter
application on Linux under Xvfb. The detection image shows one match from an
inert plain-text fixture; it is not a malware sample and nothing in it was
executed.

With Tk, Pillow, and a display available, capture the idle window with:

```bash
python scripts/screenshot_gui.py --output docs/screenshots/gui-idle.png
```

To show the real scan-result flow, make a static text fixture and pass its path:

```bash
cat > /tmp/top-antywir-demo.txt <<'EOF'
Static text used to demonstrate signature matching. Never execute this file.
powershell.exe -EncodedCommand NOT_EXECUTED_DEMO_VALUE
EOF

python scripts/screenshot_gui.py \
  --scan-target /tmp/top-antywir-demo.txt \
  --output docs/screenshots/gui-detection.png
```

On Linux, the helper works under `xvfb-run`; on Windows it uses the native
window bounds when available. The screenshot only records the application
window—it does not create a substitute for a running GUI.
