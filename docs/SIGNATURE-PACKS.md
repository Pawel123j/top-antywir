# Pakiety sygnatur

Wbudowany zestaw sygnatur jest celowo mały. Pakiet sygnatur pozwala go
rozszerzyć bez dotykania kodu: to **zwykły plik JSON**, który wrzuca się do
katalogu danych aplikacji i który jest doczytywany przy każdym skanowaniu.

> **Pakiet to dane, nigdy kod.** Nic z pliku nie jest wykonywane —
> wczytywane są wyłącznie sumy kontrolne i wyrażenia regularne. Nie ma
> serwera, nie ma automatycznego pobierania: plik dodaje człowiek.

## Format

```json
{
  "name": "nazwa-pakietu",
  "hashes": [
    {
      "name": "Nazwa-Sygnatury",
      "sha256": "<64 znaki szesnastkowe>",
      "severity": "high",
      "description": "Co to jest i dlaczego jest groźne."
    }
  ],
  "patterns": [
    {
      "name": "Nazwa-Wzorca",
      "regex": "wyrażenie regularne w składni Pythona",
      "flags": ["IGNORECASE", "DOTALL"],
      "severity": "medium",
      "description": "Co ten wzorzec wyłapuje."
    }
  ]
}
```

### Pola

| Pole | Gdzie | Wymagane | Uwagi |
|---|---|---|---|
| `name` | najwyższy poziom | nie | Domyślnie nazwa pliku. |
| `name` | wpis | tak | Widoczna w wyniku skanowania. |
| `sha256` | `hashes` | tak | Dokładnie 64 znaki szesnastkowe, wielkość liter bez znaczenia. |
| `regex` | `patterns` | tak | Składnia `re` Pythona. Wyrażenie, które się nie kompiluje, jest odrzucane. |
| `flags` | `patterns` | nie | Tylko: `IGNORECASE`/`I`, `DOTALL`/`S`, `MULTILINE`/`M`, `VERBOSE`/`X`. |
| `severity` | wpis | nie | `low`, `medium` albo `high`. Domyślnie `medium`. |
| `description` | wpis | nie | Tekst pokazywany użytkownikowi. |

### Co się dzieje z błędnym wpisem

Pojedynczy uszkodzony wpis **nie wywraca skanowania** — jest pomijany,
a powód trafia do listy błędów. To świadoma decyzja: pakiet od osoby
trzeciej nie może położyć skanera.

Wywrócić się może natomiast **import** pakietu, w którym nie ma ani jednej
użytecznej sygnatury — wtedy lepiej powiedzieć wprost, że plik jest do
niczego, niż zainstalować pusty pakiet.

### Pierwszeństwo

Sygnatury wbudowane mają pierwszeństwo: pakiet użytkownika może **dodać**
nową sygnaturę, ale nie podmieni po cichu tej dostarczonej z programem.
Duplikaty są odrzucane po `sha256` (dla hashy) i po `name` (dla wzorców).

## Użycie

```bash
# Podgląd, co program aktualnie widzi
top-antywir signatures list

# Import pakietu (plik zostaje znormalizowany i zapisany w katalogu danych)
top-antywir signatures import examples/example-pack.json

# Gdzie leżą pakiety
top-antywir signatures dir
```

Przykładowy, gotowy do zaimportowania plik: [`examples/example-pack.json`](../examples/example-pack.json).
Zawiera cztery wpisy demonstrujące wszystkie warianty — w tym jeden
celowo duplikujący sygnaturę wbudowaną, żeby pokazać zasadę pierwszeństwa.

## Pisanie własnych wzorców

Dwie rzeczy, o które łatwo się potknąć:

1. **JSON wymaga podwójnego ukośnika.** `\s` w wyrażeniu regularnym zapisuje
   się w JSON-ie jako `\\s`. Pojedynczy ukośnik to błąd składni JSON-a albo,
   gorzej, cichy escape czegoś innego.
2. **Wzorzec dopasowywany jest do treści pliku**, a nie do jego nazwy.
   Wyrażenie kotwiczone na `^` bez flagi `MULTILINE` trafi wyłącznie
   w początek całego pliku.
