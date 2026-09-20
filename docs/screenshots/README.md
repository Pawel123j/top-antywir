# Zrzuty ekranu GUI

Ten katalog jest pusty celowo.

Zrzuty interfejsu graficznego wymagają środowiska z tkinterem i serwerem
okien. `scripts/screenshot_gui.py` w obecnej postaci działa wyłącznie na
Windowsie — używa `ctypes.windll.user32.FindWindowW` do namierzenia okna
i `PIL.ImageGrab` do zrobienia zrzutu.

Wstawienie tu wizualizacji albo makiety zamiast prawdziwego zrzutu byłoby
gorsze niż brak obrazka: czytelnik nie miałby jak odróżnić jednego od
drugiego.

## Jak je zrobić (Windows)

```bash
pip install -e . pillow
python scripts/screenshot_gui.py
```

Plik ląduje w `%TEMP%\top-antywir-shot.png`. Skopiuj go tutaj i podlinkuj
w README.

## Co warto pokazać

| Nazwa pliku | Widok |
|---|---|
| `gui-idle.png` | Okno startowe |
| `gui-scan-running.png` | Skanowanie w toku, z paskiem postępu |
| `gui-detection.png` | Wykryte zagrożenie (najlepiej na pliku EICAR) |
| `gui-quarantine.png` | Zakładka kwarantanny z pozycją do przywrócenia |
| `gui-monitor.png` | Monitor katalogów w trybie aktywnym |

## Co trzeba by zmienić, żeby robić je automatycznie

`scripts/screenshot_gui.py` musiałby stracić zależność od `windll`:
na Linuksie zrzut robi się przez `PIL.ImageGrab.grab(xdisplay=":99")` pod
`xvfb-run`, na macOS przez `screencapture`. Wtedy dałoby się dołożyć zadanie
CI, które wygeneruje te obrazki przy każdym wydaniu — i przy okazji wyłapie
sytuację, w której GUI przestaje się w ogóle uruchamiać.
