**Steganografia - Wielofunkcyjne Narzędzie CLI**

## Opis

Ten projekt to złożone narzędzie wiersza poleceń do ukrywania i wykrywania danych (stekanografii) w różnych nośnikach:

* **IP Steganografia** (ukrywanie tekstów w polu `ID` i `TTL` pakietów IP)
* **Steganografia lingwistyczna** (ukrywanie liter wiadomości poprzez dobór synonimów w tekście)
* **Detekcja LSB** (analiza najmłodszego bitu obrazu)
* **Metoda PM1** (ukrywanie danych w obrazie z korekcją Hamming)
* **Prosta steganografia LSB** (ukrywanie tekstu bit-po-bicie w pikselach)
* **Adaptacyjna steganografia RGB** (kodowanie danych w oparciu o lokalną wariancję obrazu)
* **Steganografia audio** (ukrywanie wiadomości w plikach WAV przez parzystość grup próbek)

## Wymagania

* Python 3.7+
* Moduły Pythona:

  * `numpy`
  * `opencv-python`
  * `Pillow`
  * `matplotlib`
  * `scapy` (dla modułu IP Steganografia)

## Instalacja

1. Sklonuj repozytorium:

   ```bash
   git clone https://github.com/makuszef/Steganography.git
   cd Steganography
   ```
2. Zainstaluj wymagane pakiety:

   ```bash
   pip install -r requirements.txt
   ```

   *Jeżeli nie ma pliku `requirements.txt`, zainstaluj ręcznie:*

   ```bash
   pip install numpy opencv-python Pillow matplotlib scapy
   ```

## Użycie

Wszystkie funkcje dostępne są przez główny skrypt `steganography.py`. Wywołaj go z flagą odpowiadającą konkretnej metodzie.

### IP Steganografia

```bash
python steganography.py ip-steg send "Sekret" 192.168.1.10
python steganography.py ip-steg receive --timeout 5
```

* **send**: wysyła wiadomość do podanego adresu IP.
* **receive**: nasłuchuje pakietów na interfejsie loopback przez określony czas.

### Steganografia lingwistyczna

```bash
python steganography.py linguistic hide tekst.txt wiadomosc.txt wynik.txt --lang pl
python steganography.py linguistic extract wynik.txt --method auto
```

* **hide**: ukrywa wiadomość z pliku w podanym tekście.
* **extract**: wydobywa ukrytą wiadomość.

### Detekcja LSB

```bash
python steganography.py lsb-detection --generate-test
python steganography.py lsb-detection --image stego_image.png
```

* **--generate-test**: tworzy dwa obrazy testowe (czysty i steganowany).
* **--image**: analizuje wybraną warstwę bitową i wyświetla wykresy.

### Metoda PM1

```bash
python steganography.py pm1 hide obraz.png wiadomosc.txt stego.png --r 3 --channel 0
python steganography.py pm1 extract stego.png --r 3 --channel 0
```

* Pozwala ukrywać i wydobywać tekst w obrazie z korekcją Hamming.

### Prosta steganografia LSB

```bash
python steganography.py simple-lsb embed oryginal.png stego.png "Ukryty tekst"
python steganography.py simple-lsb extract stego.png
```

* Dodatkowe komendy: `embedMax`, `variousChars`.

### Adaptacyjna steganografia RGB

```bash
python steganography.py adaptive-rgb encode nośnik.png sekret.bin wynik.png --max-mode
python steganography.py adaptive-rgb decode wynik.png --output-file dane.bin
```

* Wariant max-mode powtarza dane, by wypełnić nośnik maksymalnie.

### Steganografia audio

```bash
python steganography.py audio-steg encode input.wav wiadomosc.txt stego.wav --group-size 8
python steganography.py audio-steg decode stego.wav --output-file odkryta.txt
```

* Ukrywanie tekstu w plikach WAV przez parzystość grup próbek.

## Struktura katalogu

```
Steganography/
├── steganography.py   # Główny skrypt CLI
├── ip_steg.py         # Moduł IP Steganografia
├── Linguistic_steg.py # Moduł steganografia lingwistyczna
├── LSBDetection.py    # Moduł detekcji LSB
├── ModifiedPM1.py     # Moduł metody PM1
├── Simple_LSB.py      # Prosta steganografia LSB
├── adaptiveRGB.py     # Adaptacyjna steganografia RGB
├── audio_steg.py      # Moduł steganografia audio
└── README.md          # Dokumentacja
```

Autor
a------
makuszef

## Licencja

MIT License
