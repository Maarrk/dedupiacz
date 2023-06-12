# dedupiacz

dedupiacz to program do znajdowania i usuwania zduplikowanych plików i folderów

## Instalacja

Pobierz którąś z [wydanych wersji](https://github.com/Maarrk/dedupiacz/releases), lub zbuduj ze źródeł:

```bash
zig build
```

## Użycie

```bash
# przeskanuj obecny folder
dedupiacz

# wyświetl pomoc
dedupiacz --help

# przeskanuj ścieżki (relatywne lub całkowite)
dedupiacz ./folder1 C:/folder2
```

## Planowany rozwój

- Lokalizacja na inne języki
- Zapis wyników skanowania do pliku, tryb interaktywnego usuwania z zapisu

## Licencja

[MIT](https://choosealicense.com/licenses/mit/)
