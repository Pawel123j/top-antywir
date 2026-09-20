# Architektura

Dokument opisuje, jak program jest zbudowany i **dlaczego tak**. Rzeczy,
które są tu ważniejsze od listy plików, to granice odpowiedzialności
i decyzje, które da się podważyć.

> Zanim pójdziesz dalej: to **prototyp**, nie działający antywirus. Nie ma
> ochrony w czasie rzeczywistym na poziomie jądra, nie ma heurystyki
> behawioralnej, nie ma emulacji. Wykrywa to, co da się wykryć czytając
> plik: znane sumy kontrolne i wzorce tekstowe.

## Warstwy

```
                 ┌──────────────┐   ┌──────────────┐
    użytkownik → │   cli.py     │   │   gui.py     │  ← warstwa wejścia
                 └──────┬───────┘   └──────┬───────┘
                        └────────┬─────────┘
                                 ▼
          ┌──────────────────────────────────────────┐
          │  scanner.py   monitor.py   quarantine.py │  ← logika
          │  schedule.py  report.py    audit.py      │
          └──────────────────┬───────────────────────┘
                             ▼
          ┌──────────────────────────────────────────┐
          │ signatures.py  signature_store.py        │  ← dane
          │ targets.py     paths.py                  │
          └──────────────────────────────────────────┘
```

Reguła, która porządkuje całość: **warstwa logiki nie wie nic o interfejsie**.
`scanner.py` nie drukuje, nie tworzy okien i nie wie, czy uruchomił go
terminal, czy przycisk. Dzięki temu 65 testów jednostkowych chodzi bez
tkintera i bez terminala — i dlatego CI może je uruchomić na trzech systemach
naraz.

| Plik | Linie | Odpowiedzialność |
|---|---:|---|
| `cli.py` | 566 | Parsowanie argumentów, wypisywanie wyników, kody wyjścia |
| `gui.py` | 1161 | Okno CustomTkinter, wątki robocze, prezentacja |
| `scanner.py` | 293 | Obchodzenie drzewa katalogów, dopasowanie sygnatur, werdykt |
| `signature_store.py` | 294 | Wczytywanie i walidacja pakietów sygnatur użytkownika |
| `schedule.py` | 260 | Zadania cykliczne: Harmonogram Windows / systemd / launchd |
| `report.py` | 241 | Samodzielny raport HTML |
| `signatures.py` | 206 | Sygnatury wbudowane (hashe + wzorce) |
| `monitor.py` | 202 | Obserwacja katalogów, skanowanie nowych plików |
| `quarantine.py` | 176 | Przenoszenie, rozbrajanie, przywracanie, usuwanie |
| `targets.py` | 173 | Co znaczy „szybkie" i „pełne" skanowanie na danym systemie |
| `audit.py` | 77 | Dziennik zdarzeń (JSON Lines) |
| `paths.py` | 59 | Katalogi danych zgodne z konwencją systemu |

## Decyzje i ich uzasadnienia

### Wieloplatformowość jest w `paths.py` i `targets.py`, nie rozsypana po kodzie

Rozgałęzienia „jeśli Windows" mają dwa miejsca, w których wolno im być:
ustalanie katalogów (`paths.py`) i ustalanie, co skanować (`targets.py`).
Reszta kodu operuje na `Path` i nie pyta o system. Gdyby te `if`-y siedziały
w skanerze, każda zmiana zachowania wymagałaby testowania na trzech
systemach zamiast na jednym.

Wyjątkiem świadomym są `quarantine._disarm/_rearm` i `schedule.py` — tam
różnica **jest** istotą zadania (atrybuty plików Windows kontra tryby uprawnień
POSIX; Harmonogram zadań kontra jednostki systemd kontra launchd).

### Kwarantanna rozbraja plik, zamiast liczyć na przypadek

Plik trafiający do kwarantanny dostaje nazwę z UUID i **bez rozszerzenia**,
ląduje w prywatnym katalogu, a następnie:

- na Windowsie: atrybuty `HIDDEN | SYSTEM` (celowo **bez** `READONLY` — inaczej
  program nie mógłby go potem przywrócić ani usunąć),
- na POSIX: `chmod 0400`, czyli zdjęte wszystkie bity wykonywania.

Trzy niezależne warstwy, z których każda sama w sobie by wystarczyła.
Niepowodzenie rozbrojenia nie przerywa operacji: plik i tak leży pod nazwą,
której system nie uruchomi dwuklikiem.

### Skaner ma twarde limity i to jest cecha, nie brak

- `max_file_size` domyślnie 100 MB — plik obrazu dysku nie ma zablokować skanu.
- `MAX_TEXT_SCAN_BYTES` = 2 MB — wzorce sprawdzane są na początku pliku.
- `MAX_ENTROPY_BYTES` = 1 MB — liczenie entropii na całym pliku byłoby
  kosztowne bez zysku informacyjnego.

Te progi są jawne i nazwane, żeby dało się je podważyć. Ukryte byłyby
gorsze: skan, który „czasem nie wykrywa", bez widocznego powodu.

### Pakiety sygnatur to dane, nigdy kod

Wczytywanie pakietu nie wykonuje niczego z pliku — parsuje JSON, kompiluje
wyrażenia regularne i odrzuca wpisy, które się nie kompilują. Honorowany jest
tylko wybrany podzbiór flag `re`. Uszkodzony wpis jest pomijany z zapisanym
powodem, a nie wywraca skanowania: pakiet od osoby trzeciej nie może położyć
skanera.

Sygnatury wbudowane mają pierwszeństwo — pakiet użytkownika może dodać nową
sygnaturę, ale nie podmieni po cichu tej dostarczonej z programem.
Szczegóły formatu: [SIGNATURE-PACKS.md](SIGNATURE-PACKS.md).

### Dziennik zdarzeń w JSON Lines, nie w bazie

`audit.py` dopisuje jedną linię JSON na zdarzenie. Dopisywanie jest odporne
na przerwanie w połowie (stracisz najwyżej ostatnią linię), plik czyta się
`grep`-em, a projekt nie potrzebuje z tego powodu żadnej bazy.

### Raport HTML jest samodzielny

`report.py` produkuje jeden plik bez odwołań do zasobów zewnętrznych —
style są wbudowane. Raport wysłany mailem wygląda tak samo u odbiorcy jak
u nadawcy, także bez internetu.

## Przepływ pojedynczego skanowania

```
cli.scan / gui „Skanuj"
   └─ targets.quick_scan_targets()        ← co skanować
   └─ Scanner(all_signatures())           ← czym skanować
        └─ dla każdego pliku:
             pomiń wykluczone katalogi i nazwy
             pomiń pliki > max_file_size
             sha256  → dopasowanie do sygnatur hashowych
             pierwsze 2 MB → dopasowanie wzorców
             entropia → przesłanka, nie werdykt
             → ScanResult(verdict, findings)
   └─ opcjonalnie Quarantine.add()        ← przeniesienie + rozbrojenie
   └─ opcjonalnie report.write_html_report()
   └─ AuditLog.log()                      ← ślad zdarzenia
```

## Testy

65 testów jednostkowych, żaden nie wymaga interfejsu graficznego ani sieci.
Pokryte: skaner (w tym obchodzenie drzewa i wykluczenia), kwarantanna,
dziennik, harmonogram, cele skanowania, raport, wczytywanie pakietów sygnatur.

**Czego testy nie pokrywają:** `gui.py`. To 1161 linii kodu okna, którego nie
da się uruchomić w CI bez tkintera i serwera X. Zamiast udawać pokrycie,
jest to powiedziane wprost — a CI buduje i **uruchamia** binarkę CLI na
trzech systemach, więc regresja w warstwie logiki wychodzi niezależnie od
interfejsu.
