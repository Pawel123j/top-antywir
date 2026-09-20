"""Skrypt startowy dla builda PyInstallera (wersja konsolowa).

PyInstaller potrzebuje zwykłego skryptu, a nie modułu uruchamianego przez
`-m`. Ten plik nie zawiera żadnej logiki — tylko wywołuje CLI.
"""
from top_antywir.cli import main

raise SystemExit(main())
