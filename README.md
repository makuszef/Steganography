# Stego-Tool CLI

Konsolidowany zestaw metod steganograficznych w jednym narzędziu wiersza poleceń.

---

## Spis treści

* [Opis](#opis)
* [Wymagania](#wymagania)
* [Instalacja](#instalacja)
* [Struktura repozytorium](#struktura-repozytorium)
* [Użycie](#uzycie)

  * [PM1 (Hamming syndromy)](#pm1-hamming-syndromy)
  * [Linguistic (steganografia lingwistyczna)](#linguistic-steganografia-lingwistyczna)
  * [IP (nagłówki IPv4)](#ip-naglowki-ipv4)
  * [Audio (WAV, parzystość grupowa)](#audio-wav-parzystosc-grupowa)
  * [Simple LSB](#simple-lsb)
  * [LSB Detection](#lsb-detection)
* [Rozszerzenia i wkład](#rozszerzenia-i-wklad)
* [Licencja](#licencja)

---

## Opis

`stego_cli.py` to wszechstronne narzędzie CLI integrujące różne techniki steganograficzne:

* **PM1**: ukrywanie danych w najmniej znaczących bitach pikseli z minimalną korekcją wykorzystującą kody Hamminga.
* **Linguistic**: steganografia lingwistyczna przez dobór synonimów i manipulację pierwszą literą słów lub zdań.
* **IP**: kodowanie wiadomości w polu `id` nagłówka IPv4, wysyłane na interfejsie loopback.
* **Audio**: ukrywanie bitów w parzystości grup próbek WAV (LSB parity).
* **Simple LSB**: klasyczne podstawianie LSB w pikselach.
* **LSB Detection**: detekcja śladów LSB w obrazie.

---

## Wymagania

* Python 3.8+
* Pakiety PIP:

  ```bash
  pip install numpy Pillow scapy
  ```
* (opcjonalnie) `sox` lub inny odtwarzacz WAV do testów audio

---

## Instalacja

1. Sklonuj repozytorium:

   ```bash
   git clone https://github.com/<użytkownik>/stego-tool.git
   cd stego-tool
   ```
2. (Opcjonalnie) utwórz i aktywuj wirtualne środowisko:

   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   ```
3. Zainstaluj zależności:

   ```bash
   pip install -r requirements.txt
   ```

---

## Struktura repozytorium

```
.
├── adaptiveRGB.py       # (placeholder) adaptacyjne LSB w RGB
├── Simple_LSB.py        # prosta LSB steganografia w obrazach
├── LSBDetection.py      # detekcja LSB w obrazach
├── modifiedPM1.py       # PM1 z kodami Hamminga
├── linguistic_steg.py   # steganografia lingwistyczna
├── ip_steg.py           # steganografia w nagłówkach IPv4
├── audio_steg.py        # steganografia w plikach WAV
├── stego_cli.py         # moduł CLI łączący wszystkie powyższe
├── requirements.txt     # zależności Pythona
└── README.md            # ten plik
```

---

## Użycie

Wszystkie komendy wywołujemy przez:

```bash
python stego_cli.py <podkomenda> [opcje]
```

### PM1 (Hamming syndromy)

* Ukrywanie wiadomości:

  ```bash
  python stego_cli.py pm1 hide \
    -i input.png \
    -o output.png \
    -m "Twoja tajna wiadomość" \
    -r 3 \
    -c 0
  ```
* Ekstrakcja:

  ```bash
  python stego_cli.py pm1 extract \
    -i output.png \
    -r 3 \
    -c 0
  ```

### Linguistic (steganografia lingwistyczna)

* Ukrywanie:

  ```bash
  python stego_cli.py linguistic hide \
    -s source.txt \
    -m "ukryta treść" \
    --lang pl \
    --method sentences
  ```
* Ekstrakcja:

  ```bash
  python stego_cli.py linguistic extract \
    -s modified.txt \
    --method words
  ```

### IP (nagłówki IPv4)

* Wysyłanie:

  ```bash
  python stego_cli.py ip send \
    -m "Więcej ram niż serca" \
    -d 127.0.0.1
  ```
* Odbieranie:

  ```bash
  python stego_cli.py ip receive \
    --timeout 5
  ```

### Audio (WAV, parzystość grupowa)

* Kodowanie:

  ```bash
  python stego_cli.py audio encode \
    -i input.wav \
    -o stego.wav \
    -m "Sekret w dźwięku"
  ```
* Dekodowanie:

  ```bash
  python stego_cli.py audio decode \
    -i stego.wav
  ```

### Simple LSB

* Ukrywanie:

  ```bash
  python stego_cli.py simple_lsb hide \
    -i input.png \
    -o output.png \
    -m "LSB secret" \
    -c 2
  ```
* Ekstrakcja:

  ```bash
  python stego_cli.py simple_lsb extract \
    -i output.png \
    -c 2
  ```

### LSB Detection

* Wykrywanie ingerencji LSB:

  ```bash
  python stego_cli.py lsb_detect \
    -i input.png \
    -c 0
  ```

---
Wszelkie pull requesty i zgłoszenia issue są mile widziane!

---

## Licencja

Ten projekt jest udostępniony na licencji MIT.
See [LICENSE](LICENSE) for details.
