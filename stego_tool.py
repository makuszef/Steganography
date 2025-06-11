import argparse
import sys
import platform
import random
import re
import cv2
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
import struct
import wave
import math
import string

# ==================================================================
# Funkcje z ip_steg.py
# ==================================================================
def ip_steg_get_loopback_iface():
    system = platform.system().lower()
    if system == "linux":
        return "lo"
    elif system == "darwin":
        return "lo0"
    elif system == "windows":
        return "Loopback Pseudo-Interface 1"
    else:
        raise RuntimeError(f"Nieznany system: {system}")

def ip_steg_encode(message: str, dest_ip: str):
    if not message:
        raise ValueError("Wiadomość nie może być pusta")
    msg_bytes = message.encode('utf-8')
    total_length = len(msg_bytes)
    if total_length > 1000:
        raise ValueError("Wiadomość zbyt długa (max 1000 bajtów)")

    packets = []
    packets.append(IP(dst=dest_ip, id=total_length, ttl=0))

    for idx, b in enumerate(msg_bytes, start=1):
        rand_b = random.randrange(0, 256)
        id_field = (b << 8) | rand_b
        pkt = IP(dst=dest_ip, id=id_field, ttl=idx)
        packets.append(pkt)

    for pkt in packets:
        send(pkt, verbose=False)

    return len(packets)

def ip_steg_decode(packets):
    if not packets:
        return "", 0

    length_pkt = next((p[IP] for p in packets if IP in p and p[IP].ttl == 0), None)
    if length_pkt is None:
        raise ValueError("Brak pakietu z długością (ttl=0)")
    total_length = length_pkt.id

    data_pkts = [(p[IP].ttl, p[IP].id)
                 for p in packets if IP in p and p[IP].ttl > 0]
    if not data_pkts:
        return "", 0

    data_pkts.sort(key=lambda x: x[0])
    byte_arr = bytearray()
    for _, ident in data_pkts:
        high_byte = (ident >> 8) & 0xFF
        byte_arr.append(high_byte)

    if len(byte_arr) < total_length:
        raise ValueError(f"Odebrano zbyt mało pakietów: oczekiwano {total_length}, otrzymano {len(byte_arr)}")

    raw = bytes(byte_arr[:total_length])
    try:
        return raw.decode('utf-8'), len(data_pkts) + 1
    except UnicodeDecodeError as e:
        raise ValueError(f"Błąd dekodowania UTF-8: {e}")

def ip_steg_capture_packets(timeout=10, filter_expr="ip"):
    iface = ip_steg_get_loopback_iface()
    print(f"Sniffowanie na interfejsie loopback: {iface}")
    return sniff(iface=iface, timeout=timeout, filter=filter_expr)

def handle_ip_steg(args):
    if args.mode == "send":
        if not args.message or not args.dest_ip:
            raise ValueError("Brakujące argumenty dla trybu send")
        count = ip_steg_encode(args.message, args.dest_ip)
        print(f"Wysłano {count} pakietów do {args.dest_ip}")

    elif args.mode == "receive":
        pkts = ip_steg_capture_packets(timeout=args.timeout)
        msg, count = ip_steg_decode(pkts)
        print(f"Odebrano pakietów: {len(pkts)} (danych: {count})")
        print("Odkryta wiadomość:", msg)

# ==================================================================
# Funkcje z Linguistic_steg.py
# ==================================================================
def linguistic_get_synonym(word, target_char, lang='en'):
    if target_char == ' ':
        return word

    target_char = target_char.lower()
    mock_synonyms = {
        'en': {
            'dog': ['hound', 'pooch', 'puppy'],
            'quick': ['fast', 'rapid', 'speedy'],
            'lazy': ['sluggish', 'idle'],
            'happy': ['joyful', 'cheerful'],
            'big': ['large', 'huge']
        },
        'pl': {
            'pies': ['kundel', 'szczeniak'],
            'szybki': ['błyskawiczny', 'prędki'],
            'duży': ['ogromny', 'wielki'],
            'miły': ['uprzejmy', 'sympatyczny'],
            'wojna': ['konflikt', 'walka', 'batalia'],
            'granic': ['rubieży', 'kresów', 'pogranicza']
        }
    }

    lang_dict = mock_synonyms.get(lang, {})
    lowercase_word = word.lower()

    for synonym in lang_dict.get(lowercase_word, []):
        if synonym[0].lower() == target_char:
            return adjust_case(synonym, word)

    return adjust_case(target_char.upper() + word[1:], word)

def linguistic_adjust_case(synonym, original_word):
    if original_word.istitle():
        return synonym.capitalize()
    return synonym.lower()

def linguistic_hide_message(source_text, message, lang='pl'):
    processed_msg = message.upper().replace(' ', 'ˍ')
    try:
        return linguistic_hide_message_in_sentences(source_text, processed_msg, lang)
    except ValueError:
        return linguistic_hide_message_in_words(source_text, processed_msg, lang)

def linguistic_hide_message_in_sentences(source_text, message, lang):
    sentences = re.split(r'(?<=[.!?])\s+', source_text)
    message = message[:50]

    if len(sentences) < len(message) + 1:
        raise ValueError("Niewłaściwa liczba zdań")

    modified_sentences = []
    for i, char in enumerate(message):
        sentence = sentences[i]
        first_word = re.search(r'\b\w+\b', sentence)
        if not first_word:
            modified_sentences.append(sentence)
            continue

        original_word = first_word.group()
        if original_word[0].upper() == char:
            modified_sentences.append(sentence)
        else:
            synonym = linguistic_get_synonym(original_word, char, lang)
            modified_sentences.append(sentence.replace(original_word, synonym, 1))

    modified_sentences.extend(sentences[len(message):])
    return ' '.join(modified_sentences)

def linguistic_hide_message_in_words(source_text, message, lang):
    words = re.findall(r'\b\w+\b', source_text)
    message = message[:50]

    if len(words) < len(message):
        raise ValueError("Tekst źródłowy za krótki")

    modified_words = []
    for i, char in enumerate(message):
        original_word = words[i]
        if original_word[0].upper() == char:
            modified_words.append(original_word)
        else:
            modified_words.append(linguistic_get_synonym(original_word, char, lang))

    modified_text = []
    word_iter = iter(modified_words + words[len(message):])
    for fragment in re.split(r'(\b\w+\b)', source_text):
        modified_text.append(next(word_iter) if re.match(r'\b\w+\b', fragment) else fragment)
    return ''.join(modified_text)

def linguistic_extract_message(modified_text, method='auto'):
    raw = linguistic_extract_message_from_sentences(modified_text) if method == 'sentences' else \
        linguistic_extract_message_from_words(modified_text) if method == 'words' else \
            linguistic_try_extract_message(modified_text)
    return raw.replace('ˍ', ' ')

def linguistic_try_extract_message(modified_text):
    try:
        msg = linguistic_extract_message_from_sentences(modified_text)
        if len(msg) > 0:
            return msg
    except:
        pass
    return linguistic_extract_message_from_words(modified_text)

def linguistic_extract_message_from_sentences(modified_text):
    sentences = re.split(r'(?<=[.!?])\s+', modified_text)
    result = ''.join([re.search(r'\b\w', s).group()[0] if re.search(r'\b\w', s) else 'ˍ' for s in sentences])[:50]
    return result.replace('ˍ', ' ')

def linguistic_extract_message_from_words(modified_text):
    words = re.findall(r'\b\w+\b', modified_text)
    return ''.join([w[0] for w in words])[:50].replace('ˍ', ' ').title()

def handle_linguistic(args):
    if args.command == 'hide':
        with open(args.source_text, 'r', encoding='utf-8') as f:
            source_text = f.read()
        
        with open(args.message_file, 'r', encoding='utf-8') as f:
            message = f.read()
        
        result = linguistic_hide_message(source_text, message, args.lang)
        
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(result)
        print(f"Zapisano zmodyfikowany tekst do: {args.output}")

    elif args.command == 'extract':
        with open(args.input_file, 'r', encoding='utf-8') as f:
            text = f.read()
        
        method = args.method if args.method else 'auto'
        message = linguistic_extract_message(text, method)
        print("Odkryta wiadomość:", message)

# ==================================================================
# Funkcje z LSBDetection.py
# ==================================================================
def lsb_generate_test_images():
    clean_img = np.zeros((512, 512), dtype=np.uint8)
    for i in range(512):
        clean_img[i, :] = i // 2
    
    stego_img = clean_img.copy()
    secret_message = np.random.randint(0, 2, (512, 512), dtype=np.uint8)
    stego_img = (stego_img & 0xFE) | secret_message
    
    cv2.imwrite('clean_image.png', clean_img)
    cv2.imwrite('stego_image.png', stego_img)
    return clean_img, stego_img

def lsb_extract_lsb_layers(img):
    layers = []
    for i in range(8):
        layer = (img >> i) & 1
        layers.append(layer * 255)
    return layers

def lsb_visualize_layers(layers, title):
    plt.figure(figsize=(15, 10))
    plt.suptitle(title, fontsize=16)
    
    for i in range(8):
        plt.subplot(2, 4, i+1)
        plt.imshow(layers[i], cmap='gray')
        plt.title(f'Bit {i} {"(LSB)" if i==0 else ""}')
        plt.axis('off')
    
    plt.tight_layout()
    plt.show()

def lsb_analyze_lsb_distribution(lsb_layer):
    binary_data = lsb_layer // 255
    total_pixels = binary_data.size
    ones = np.sum(binary_data)
    zeros = total_pixels - ones
    ones_percent = (ones / total_pixels) * 100
    
    print("\nAnaliza warstwy LSB:")
    print(f"- Procent bitów 1: {ones_percent:.2f}%")
    print(f"- Procent bitów 0: {100 - ones_percent:.2f}%")
    
    plt.figure(figsize=(8, 5))
    plt.bar(['0', '1'], [zeros, ones], color=['blue', 'red'])
    plt.title('Rozkład bitów w warstwie LSB')
    plt.ylabel('Liczba pikseli')
    plt.show()

def lsb_analyze_image(image_path):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        print(f"Błąd: Nie można wczytać obrazu {image_path}")
        return
    
    layers = lsb_extract_lsb_layers(img)
    title = f'Analiza warstw bitowych: {image_path}'
    lsb_visualize_layers(layers, title)
    lsb_analyze_lsb_distribution(layers[0])

def handle_lsb_detection(args):
    if args.generate_test:
        print("Generowanie obrazów testowych...")
        lsb_generate_test_images()
        print("Wygenerowano: clean_image.png i stego_image.png")
    
    if args.image:
        lsb_analyze_image(args.image)

# ==================================================================
# Funkcje z ModifiedPM1.py
# ==================================================================
def pm1_build_hamming_H(r):
    n = 2**r - 1
    H = np.zeros((r, n), dtype=int)
    for i in range(1, n + 1):
        bits = [(i >> (r - 1 - j)) & 1 for j in range(r)]
        H[:, i - 1] = bits
    return H

def pm1_compute_syndrome(block_bits, H):
    return (H.dot(block_bits) % 2)

def pm1_hide_message(image_path, output_path, message, r=3, channel=0):
    img = Image.open(image_path)
    arr = np.array(img)
    msg_bytes = message.encode('utf-8')
    msg_len = len(msg_bytes)
    header = msg_len.to_bytes(2, 'big')
    data = header + msg_bytes
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    H = pm1_build_hamming_H(r)
    n = H.shape[1]

    if arr.ndim == 2:
        chan = arr
    else:
        chan = arr[..., channel]

    flat = chan.flatten()
    num_blocks = flat.size // n

    if len(bits) > num_blocks * r:
        raise ValueError("Wiadomość jest za długa dla tej pojemności obrazu.")

    bit_idx = 0
    for i in range(num_blocks):
        if bit_idx >= len(bits):
            break

        block_inds = np.arange(i * n, (i + 1) * n)
        block = flat[block_inds]
        block_bits = block & 1
        s = pm1_compute_syndrome(block_bits, H)
        m = bits[bit_idx:bit_idx + r]
        bit_idx += r
        delta = (s ^ m)

        if np.any(delta):
            for j in range(n):
                if np.array_equal(H[:, j], delta):
                    pix_idx = block_inds[j]
                    if flat[pix_idx] == 255:
                        flat[pix_idx] -= 1
                    else:
                        flat[pix_idx] += 1
                    break

    if arr.ndim == 2:
        stego_arr = flat.reshape(chan.shape)
    else:
        stego_arr = arr.copy()
        stego_arr[..., channel] = flat.reshape(chan.shape)

    stego_img = Image.fromarray(stego_arr)
    stego_img.save(output_path)
    print(f"Wiadomość ukryta i zapisano do: {output_path}")

def pm1_extract_message(stego_path, r=3, channel=0):
    img = Image.open(stego_path)
    arr = np.array(img)
    if arr.ndim == 2:
        chan = arr
    else:
        chan = arr[..., channel]

    flat = chan.flatten()
    H = pm1_build_hamming_H(r)
    n = H.shape[1]
    num_blocks = flat.size // n

    syndromes = []
    for i in range(num_blocks):
        block = flat[i*n:(i+1)*n]
        block_bits = block & 1
        s = pm1_compute_syndrome(block_bits, H)
        syndromes.extend(s.tolist())

    header_bits = np.array(syndromes[:16], dtype=np.uint8)
    msg_len = int(''.join(header_bits.astype(str)), 2)
    total_bits = 16 + msg_len * 8

    if total_bits > len(syndromes):
        raise ValueError("Brak pełnej wiadomości lub zły klucz/parametry.")

    data_bits = np.array(syndromes[16:total_bits], dtype=np.uint8)
    bytes_arr = np.packbits(data_bits)
    return bytes_arr.tobytes().decode('utf-8')

def handle_pm1(args):
    if args.command == 'hide':
        with open(args.message_file, 'r', encoding='utf-8') as f:
            message = f.read()
        
        pm1_hide_message(
            args.input_image,
            args.output_image,
            message,
            r=args.r,
            channel=args.channel
        )
    
    elif args.command == 'extract':
        message = pm1_extract_message(
            args.stego_image,
            r=args.r,
            channel=args.channel
        )
        print("Odkryta wiadomość:", message)

# ==================================================================
# Funkcje z Simple_LSB.py
# ==================================================================
def lsb_to_bit_stream(data: bytes):
    bit_stream = []
    for byte in data:
        bits = [(byte >> i) & 1 for i in range(7, -1, -1)]
        bit_stream.extend(bits)
    return bit_stream

def lsb_compute_psnr(img1, img2):
    arr1 = np.array(img1, dtype=np.float64)
    arr2 = np.array(img2, dtype=np.float64)
    mse = np.mean((arr1 - arr2) ** 2)
    if mse == 0:
        return float('inf')
    return 10 * np.log10((255 ** 2) / mse)

def lsb_embed_text(orig, pixels, bit_stream):
    new_pixels = []
    bit_idx = 0
    for r, g, b in pixels:
        if bit_idx < len(bit_stream):
            r = (r & ~1) | bit_stream[bit_idx]
            bit_idx += 1
        new_pixels.append((r, g, b))
    stego = Image.new(orig.mode, orig.size)
    stego.putdata(new_pixels)
    return stego

def lsb_embed_command(input_path, output_path, text):
    delimiter = "<<END>>"
    orig = Image.open(input_path).convert('RGB')
    pixels = list(orig.getdata())
    data = (text + delimiter).encode('utf-8')
    bit_stream = lsb_to_bit_stream(data)
    if len(bit_stream) > len(pixels):
        raise ValueError('Data too large for image capacity.')
    stego = lsb_embed_text(orig, pixels, bit_stream)
    stego.save(output_path, 'PNG')
    print(f"PSNR: {lsb_compute_psnr(orig, stego):.2f} dB")

def lsb_embed_max_command(input_path, output_path, pattern):
    delimiter = "<<END>>"
    orig = Image.open(input_path).convert('RGB')
    pixels = list(orig.getdata())
    capacity = len(pixels)
    delim_bits = len(delimiter.encode('utf-8')) * 8
    max_bits = capacity - delim_bits
    pat_bytes = pattern.encode('utf-8')
    rep = max_bits // (len(pat_bytes) * 8)
    if rep < 1:
        raise ValueError('Pattern too large to fit.')
    data_bytes = pat_bytes * rep + delimiter.encode('utf-8')
    bit_stream = lsb_to_bit_stream(data_bytes)[:capacity]
    stego = lsb_embed_text(orig, pixels, bit_stream)
    stego.save(output_path, 'PNG')
    print(f"Embedded pattern repeated {rep} times.")
    print(f"PSNR: {lsb_compute_psnr(orig, stego):.2f} dB")

def lsb_embed_various_command(input_path, output_path):
    delimiter = "<<END>>"
    orig = Image.open(input_path).convert('RGB')
    pixels = list(orig.getdata())
    capacity = len(pixels)
    special = list(string.punctuation)
    digits = list(string.digits)
    ascii_letters = list(string.ascii_letters)
    greek = [chr(c) for c in range(0x0391, 0x03A9+1)] + [chr(c) for c in range(0x03B1, 0x03C9+1)]
    cyrillic = [chr(c) for c in range(0x0410, 0x042F+1)] + [chr(c) for c in range(0x0430, 0x044F+1)]
    pattern = ''.join(special + digits + ascii_letters + greek + cyrillic)
    delim_bits = len(delimiter.encode('utf-8')) * 8
    max_bits = capacity - delim_bits
    pat_bytes = pattern.encode('utf-8')
    rep = 1
    data_bytes = pat_bytes * rep + delimiter.encode('utf-8')
    bit_stream = lsb_to_bit_stream(data_bytes)[:capacity]
    stego = lsb_embed_text(orig, pixels, bit_stream)
    stego.save(output_path, 'PNG')
    print(f"Embedded various chars repeated {rep} times.")
    print(f"PSNR: {lsb_compute_psnr(orig, stego):.2f} dB")

def lsb_extract_text(input_path):
    delimiter = "<<END>>"
    img = Image.open(input_path).convert('RGB')
    bits = [r & 1 for r, g, b in list(img.getdata())]
    data_bytes = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        data_bytes.append(byte)
        text = data_bytes.decode('utf-8', errors='ignore')
        if delimiter in text:
            return text.split(delimiter)[0]
    raise ValueError('Delimiter not found.')

def handle_simple_lsb(args):
    if args.command == 'embed':
        lsb_embed_command(args.input, args.output, args.text)
    elif args.command == 'embedMax':
        lsb_embed_max_command(args.input, args.output, args.pattern)
    elif args.command == 'variousChars':
        lsb_embed_various_command(args.input, args.output)
    elif args.command == 'extract':
        print(f"Hidden message: {lsb_extract_text(args.input)}")

# ==================================================================
# Funkcje z adaptiveRGB.py
# ==================================================================
def adaptive_calculate_psnr(original, modified):
    mse = np.mean((original - modified) ** 2)
    if mse == 0:
        return float('inf')
    return 10 * math.log10(255 ** 2 / mse)

def adaptive_compute_variance(block):
    gray = 0.299 * block[:, :, 0] + 0.587 * block[:, :, 1] + 0.114 * block[:, :, 2]
    mean = np.mean(gray)
    variance = np.mean((gray - mean) ** 2)
    return variance

def adaptive_compute_threshold(variance):
    if variance < 20:
        return 1
    elif variance < 80:
        return 2
    elif variance < 160:
        return 3
    else:
        return 4

def adaptive_adjust_pixel(pixel, bit, x):
    r, g, b = pixel
    current_diff = int(r) - int(g)
    target_diff = x + 1 if bit else x

    if (bit and current_diff > x) or (not bit and current_diff <= x):
        return (r, g, b)

    if bit:
        required = target_diff - current_diff
        new_r = r + required
        if new_r <= 255:
            return (new_r, g, b)
        else:
            new_g = max(0, g - (new_r - 255))
            return (255, new_g, b)
    else:
        required = current_diff - target_diff
        new_r = r - required
        if new_r >= 0:
            return (new_r, g, b)
        else:
            new_g = min(255, g + abs(new_r))
            return (0, new_g, b)

def adaptive_encode_image(carrier_path, secret_data, output_path, max_mode=False):
    img = Image.open(carrier_path).convert('RGB')
    original_array = np.array(img)
    height, width, _ = original_array.shape
    block_size = 8

    if height % block_size != 0 or width % block_size != 0:
        raise ValueError("Image dimensions must be multiples of 8")

    if max_mode:
        blocks_count = (height // block_size) * (width // block_size)
        max_data_bits = blocks_count // 3
        max_data_bytes = max_data_bits // 8
        max_secret_bytes = max_data_bytes - 4
        if max_secret_bytes <= 0:
            raise ValueError("Image too small to hide any data in max mode")

        original_secret_len = len(secret_data)
        if original_secret_len == 0:
            raise ValueError("Secret data is empty, cannot repeat in max mode")

        repeat_times = (max_secret_bytes + original_secret_len - 1) // original_secret_len
        secret_data = (secret_data * repeat_times)[:max_secret_bytes]

    data_len = len(secret_data)
    data = data_len.to_bytes(4, 'big') + secret_data

    if not max_mode:
        required_bits = len(data) * 8 * 3
        available_blocks = (height // block_size) * (width // block_size)
        if required_bits > available_blocks:
            raise ValueError(f"Carrier too small. Needed: {required_bits} bits, Available: {available_blocks} blocks")

    bitstream = []
    for byte in data:
        for i in range(7, -1, -1):
            bit = (byte >> i) & 1
            bitstream.append(bit)
    encoded_bitstream = [bit for bit in bitstream for _ in range(3)]

    blocks = []
    for y in range(0, height, block_size):
        for x in range(0, width, block_size):
            block = original_array[y:y + block_size, x:x + block_size].copy()
            blocks.append(block)

    for i, bit in enumerate(encoded_bitstream):
        if i >= len(blocks):
            break
        block = blocks[i]
        variance = adaptive_compute_variance(block)
        x = adaptive_compute_threshold(variance)
        block[0, 0] = adaptive_adjust_pixel(block[0, 0], bit, x)
        blocks[i] = block

    reconstructed = np.zeros_like(original_array)
    block_idx = 0
    for y in range(0, height, block_size):
        for x in range(0, width, block_size):
            h = min(block_size, height - y)
            w = min(block_size, width - x)
            reconstructed[y:y + h, x:x + w] = blocks[block_idx][:h, :w]
            block_idx += 1

    Image.fromarray(reconstructed).save(output_path)
    stego_img = Image.open(output_path)
    psnr = adaptive_calculate_psnr(np.array(img), np.array(stego_img))
    print(f"PSNR: {psnr:.2f} dB")
    return psnr

def adaptive_decode_image(stego_path):
    img = Image.open(stego_path).convert('RGB')
    img_array = np.array(img)
    height, width, _ = img_array.shape
    block_size = 8

    blocks = []
    for y in range(0, height, block_size):
        for x in range(0, width, block_size):
            blocks.append(img_array[y:y + block_size, x:x + block_size])

    extracted_bits = []
    for block in blocks:
        variance = adaptive_compute_variance(block)
        x = adaptive_compute_threshold(variance)
        r, g, _ = block[0, 0]
        diff = int(r) - int(g)
        extracted_bits.append(1 if diff > x else 0)

    corrected_bits = []
    for i in range(0, len(extracted_bits), 3):
        trio = extracted_bits[i:i + 3]
        if len(trio) == 3:
            corrected_bits.append(1 if sum(trio) >= 2 else 0)

    data = bytearray()
    byte = 0
    for i, bit in enumerate(corrected_bits):
        if i % 8 == 0 and i != 0:
            data.append(byte)
            byte = 0
        byte = (byte << 1) | bit

    if corrected_bits:
        byte <<= (8 - (len(corrected_bits) % 8)) % 8
        data.append(byte)

    if len(data) < 4:
        raise ValueError("Invalid hidden data")

    data_len = int.from_bytes(data[:4], 'big')
    return data[4:4 + data_len]

def handle_adaptive_rgb(args):
    if args.command == "encode":
        with open(args.secret_file, 'rb') as f:
            secret_data = f.read()
        
        max_mode = args.max_mode
        adaptive_encode_image(
            args.carrier, 
            secret_data, 
            args.output,
            max_mode
        )
        print(f"Zakodowano dane w: {args.output}")

    elif args.command == "decode":
        secret_data = adaptive_decode_image(args.stego_image)
        
        if args.output_file:
            with open(args.output_file, 'wb') as f:
                f.write(secret_data)
            print(f"Zapisano dane do: {args.output_file}")
        else:
            print("Odkryte dane:", secret_data.decode('utf-8', errors='replace'))

# ==================================================================
# Funkcje z audio_steg.py
# ==================================================================
def audio_hide_message(input_audio, message, output_audio, group_size=8):
    with wave.open(input_audio, 'rb') as wav:
        params = wav.getparams()
        frames = wav.readframes(params.nframes)
        samples = list(struct.unpack(f'<{params.nframes * params.nchannels}h', frames))

    message_bytes = message.encode('utf-8')
    header = len(message_bytes).to_bytes(4, 'big')
    full_data = header + message_bytes

    binary_str = ''.join(f'{byte:08b}' for byte in full_data)
    total_bits_needed = len(binary_str)

    max_bits = (len(samples) // group_size)
    max_chars = (max_bits - 32) // 8

    if total_bits_needed > max_bits:
        raise ValueError(f"Wiadomość za długa. Maksymalna długość: {max_chars} znaków")

    bit_counter = 0
    for i in range(0, len(samples), group_size):
        if bit_counter >= total_bits_needed:
            break

        group = samples[i:i + group_size]
        target_bit = int(binary_str[bit_counter])
        current_parity = sum(sample & 1 for sample in group) % 2

        if current_parity != target_bit:
            group[0] = group[0] ^ 1

        samples[i:i + group_size] = group
        bit_counter += 1

    with wave.open(output_audio, 'wb') as out_wav:
        out_wav.setparams(params)
        out_wav.writeframes(struct.pack(f'<{len(samples)}h', *samples))

def audio_extract_message(stego_audio, group_size=8):
    with wave.open(stego_audio, 'rb') as wav:
        params = wav.getparams()
        frames = wav.readframes(params.nframes)
        samples = struct.unpack(f'<{params.nframes * params.nchannels}h', frames)

    bits = []
    for i in range(0, len(samples), group_size):
        group = samples[i:i + group_size]
        parity = sum(sample & 1 for sample in group) % 2
        bits.append(str(parity))

    if len(bits) < 32:
        raise ValueError("Brak ukrytej treści w pliku audio")

    header_bits = ''.join(bits[:32])
    message_length = int(header_bits, 2)

    max_possible = (len(bits) - 32) // 8
    if message_length <= 0 or message_length > max_possible:
        raise ValueError("Plik nie zawiera ukrytej wiadomości")

    message_bits = ''.join(bits[32:32 + message_length * 8])
    if len(message_bits) < message_length * 8:
        raise ValueError("Uszkodzona lub niekompletna wiadomość")

    message_bytes = bytes(
        int(message_bits[i:i + 8], 2)
        for i in range(0, len(message_bits), 8)
    )

    try:
        return message_bytes.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("Odczytane dane nie są poprawnym tekstem UTF-8")

def handle_audio_steg(args):
    if args.command == "encode":
        with open(args.message_file, 'r', encoding='utf-8') as f:
            message = f.read()
        
        audio_hide_message(
            args.input_audio,
            message,
            args.output_audio,
            args.group_size
        )
        print(f"Zakodowano wiadomość w: {args.output_audio}")

    elif args.command == "decode":
        secret = audio_extract_message(
            args.stego_audio,
            args.group_size
        )
        
        if args.output_file:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                f.write(secret)
            print(f"Zapisano wiadomość do: {args.output_file}")
        else:
            print("Ukryta wiadomość:", secret)

# ==================================================================
# Główny parser CLI
# ==================================================================
def main():
    parser = argparse.ArgumentParser(description='Steganografia - Narzędzie wielofunkcyjne')
    subparsers = parser.add_subparsers(dest='main_command', required=True)

    # IP Steganografia
    ip_parser = subparsers.add_parser('ip-steg', help='Steganografia w pakietach IP')
    ip_subparsers = ip_parser.add_subparsers(dest='mode', required=True)
    
    send_parser = ip_subparsers.add_parser('send', help='Wyślij ukrytą wiadomość')
    send_parser.add_argument('message', help='Wiadomość do wysłania')
    send_parser.add_argument('dest_ip', help='Docelowy adres IP')
    
    recv_parser = ip_subparsers.add_parser('receive', help='Odbierz wiadomość')
    recv_parser.add_argument('--timeout', type=float, default=10.0, help='Czas nasłuchiwania (domyślnie 10s)')
    ip_parser.set_defaults(func=handle_ip_steg)

    # Lingwistyczna steganografia
    ling_parser = subparsers.add_parser('linguistic', help='Steganografia lingwistyczna')
    ling_subparsers = ling_parser.add_subparsers(dest='command', required=True)
    
    ling_hide = ling_subparsers.add_parser('hide', help='Ukryj wiadomość w tekście')
    ling_hide.add_argument('source_text', help='Plik z tekstem źródłowym')
    ling_hide.add_argument('message_file', help='Plik z wiadomością do ukrycia')
    ling_hide.add_argument('output', help='Plik wyjściowy')
    ling_hide.add_argument('--lang', choices=['pl', 'en'], default='pl', help='Język (domyślnie: pl)')
    
    ling_extract = ling_subparsers.add_parser('extract', help='Wyodrębnij wiadomość z tekstu')
    ling_extract.add_argument('input_file', help='Plik z tekstem z ukrytą wiadomością')
    ling_extract.add_argument('--method', choices=['auto', 'sentences', 'words'], 
                             help='Metoda ekstrakcji (domyślnie: auto)')
    ling_parser.set_defaults(func=handle_linguistic)

    # Detekcja LSB
    lsb_detect_parser = subparsers.add_parser('lsb-detection', help='Detekcja steganografii LSB')
    lsb_detect_parser.add_argument('--image', help='Obraz do analizy')
    lsb_detect_parser.add_argument('--generate-test', action='store_true', help='Generuj obrazy testowe')
    lsb_detect_parser.set_defaults(func=handle_lsb_detection)

    # Metoda PM1
    pm1_parser = subparsers.add_parser('pm1', help='Steganografia metodą PM1')
    pm1_subparsers = pm1_parser.add_subparsers(dest='command', required=True)
    
    pm1_hide = pm1_subparsers.add_parser('hide', help='Ukryj wiadomość w obrazie')
    pm1_hide.add_argument('input_image', help='Obraz wejściowy')
    pm1_hide.add_argument('message_file', help='Plik z wiadomością do ukrycia')
    pm1_hide.add_argument('output_image', help='Obraz wyjściowy')
    pm1_hide.add_argument('--r', type=int, default=3, help='Liczba bitów parzystości (domyślnie 3)')
    pm1_hide.add_argument('--channel', type=int, default=0, choices=[0, 1, 2],
                         help='Kanał obrazu (0=R,1=G,2=B, domyślnie 0)')
    
    pm1_extract = pm1_subparsers.add_parser('extract', help='Wyodrębnij wiadomość z obrazu')
    pm1_extract.add_argument('stego_image', help='Obraz z ukrytą wiadomością')
    pm1_extract.add_argument('--r', type=int, default=3, help='Liczba bitów parzystości (domyślnie 3)')
    pm1_extract.add_argument('--channel', type=int, default=0, choices=[0, 1, 2],
                         help='Kanał obrazu (0=R,1=G,2=B, domyślnie 0)')
    pm1_parser.set_defaults(func=handle_pm1)

    # Prosty LSB
    simple_lsb_parser = subparsers.add_parser('simple-lsb', help='Prosta steganografia LSB')
    simple_lsb_subparsers = simple_lsb_parser.add_subparsers(dest='command', required=True)
    
    lsb_embed = simple_lsb_subparsers.add_parser('embed', help='Ukryj tekst w obrazie')
    lsb_embed.add_argument('input', help='Obraz wejściowy')
    lsb_embed.add_argument('output', help='Obraz wyjściowy')
    lsb_embed.add_argument('text', help='Tekst do ukrycia')
    
    lsb_embed_max = simple_lsb_subparsers.add_parser('embedMax', help='Ukryj maksymalną ilość powtórzeń wzorca')
    lsb_embed_max.add_argument('input', help='Obraz wejściowy')
    lsb_embed_max.add_argument('output', help='Obraz wyjściowy')
    lsb_embed_max.add_argument('pattern', help='Wzorzec do powtórzenia')
    
    lsb_various = simple_lsb_subparsers.add_parser('variousChars', help='Ukryj różne znaki')
    lsb_various.add_argument('input', help='Obraz wejściowy')
    lsb_various.add_argument('output', help='Obraz wyjściowy')
    
    lsb_extract = simple_lsb_subparsers.add_parser('extract', help='Wyodrębnij tekst z obrazu')
    lsb_extract.add_argument('input', help='Obraz z ukrytą wiadomością')
    simple_lsb_parser.set_defaults(func=handle_simple_lsb)

    # Adaptacyjna steganografia RGB
    adaptive_parser = subparsers.add_parser('adaptive-rgb', help='Adaptacyjna steganografia RGB')
    adaptive_subparsers = adaptive_parser.add_subparsers(dest='command', required=True)
    
    adaptive_encode = adaptive_subparsers.add_parser('encode', help='Ukryj dane w obrazie')
    adaptive_encode.add_argument('carrier', help='Obraz nośnikowy')
    adaptive_encode.add_argument('secret_file', help='Plik z danymi do ukrycia')
    adaptive_encode.add_argument('output', help='Obraz wyjściowy')
    adaptive_encode.add_argument('--max-mode', action='store_true', help='Maksymalne wypełnienie obrazu')
    
    adaptive_decode = adaptive_subparsers.add_parser('decode', help='Wyodrębnij dane z obrazu')
    adaptive_decode.add_argument('stego_image', help='Obraz z ukrytymi danymi')
    adaptive_decode.add_argument('--output-file', help='Plik do zapisu wyodrębnionych danych')
    adaptive_parser.set_defaults(func=handle_adaptive_rgb)

    # Steganografia audio
    audio_parser = subparsers.add_parser('audio-steg', help='Steganografia w plikach audio')
    audio_subparsers = audio_parser.add_subparsers(dest='command', required=True)
    
    audio_encode = audio_subparsers.add_parser('encode', help='Ukryj wiadomość w pliku audio')
    audio_encode.add_argument('input_audio', help='Plik audio wejściowy')
    audio_encode.add_argument('message_file', help='Plik z wiadomością do ukrycia')
    audio_encode.add_argument('output_audio', help='Plik audio wyjściowy')
    audio_encode.add_argument('--group-size', type=int, default=8, help='Rozmiar grupy próbek (domyślnie 8)')
    
    audio_decode = audio_subparsers.add_parser('decode', help='Wyodrębnij wiadomość z pliku audio')
    audio_decode.add_argument('stego_audio', help='Plik audio z ukrytą wiadomością')
    audio_decode.add_argument('--output-file', help='Plik do zapisu wyodrębnionej wiadomości')
    audio_decode.add_argument('--group-size', type=int, default=8, help='Rozmiar grupy próbek (domyślnie 8)')
    audio_parser.set_defaults(func=handle_audio_steg)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()