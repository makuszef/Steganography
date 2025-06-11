import sys
import argparse
import platform
import random
import wave
import struct
import struct
import re

import numpy as np
from PIL import Image
from scapy.all import IP, send, sniff

# ----------------------------------------------
# adaptiveRGB (example placeholder)
# ----------------------------------------------
def adaptiveRGB_hide(input_path, output_path, message):
    # Placeholder: implement adaptiveRGB method
    raise NotImplementedError("adaptiveRGB method not implemented")

def adaptiveRGB_extract(stego_path):
    raise NotImplementedError("adaptiveRGB method not implemented")

# ----------------------------------------------
# Simple LSB
# ----------------------------------------------
from Simple_LSB import hide_message as simple_lsb_hide, extract_message as simple_lsb_extract

# ----------------------------------------------
# LSBDetection
# ----------------------------------------------
from LSBDetection import detect_lsb

# ----------------------------------------------
# modified PM1 (Hamming syndromes)
# ----------------------------------------------
# Inlined from modifiedPM1.py

def build_hamming_H(r):
    n = 2**r - 1
    H = np.zeros((r, n), dtype=int)
    for i in range(1, n + 1):
        bits = [(i >> (r - 1 - j)) & 1 for j in range(r)]
        H[:, i - 1] = bits
    return H
n

def compute_syndrome(block_bits, H):
    return (H.dot(block_bits) % 2)


def pm1_hide(input_image, output_image, message, r=3, channel=0):
    img = Image.open(input_image)
    arr = np.array(img)
    msg_bytes = message.encode('utf-8')
    header = len(msg_bytes).to_bytes(2, 'big')
    data = header + msg_bytes
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    H = build_hamming_H(r)
    n = H.shape[1]
    chan = arr[..., channel] if arr.ndim==3 else arr
    flat = chan.flatten()
    num_blocks = flat.size//n
    if len(bits) > num_blocks*r:
        raise ValueError("Message too long")
    bit_idx=0
    for i in range(num_blocks):
        if bit_idx>=len(bits): break
        inds = np.arange(i*n,(i+1)*n)
        block=flat[inds]
        s=compute_syndrome(block&1,H)
        m=bits[bit_idx:bit_idx+r]; bit_idx+=r
        delta=s^m
        if np.any(delta):
            for j in range(n):
                if np.array_equal(H[:,j],delta):
                    idx=inds[j]
                    flat[idx]=flat[idx]-1 if flat[idx]==255 else flat[idx]+1
                    break
    stego=flat.reshape(chan.shape)
    if arr.ndim==3: arr[...,channel]=stego; stego=arr
    Image.fromarray(stego).save(output_image)


def pm1_extract(stego_image, r=3, channel=0):
    img=Image.open(stego_image); arr=np.array(img)
    chan=arr[...,channel] if arr.ndim==3 else arr
    flat=chan.flatten()
    H=build_hamming_H(r);n=H.shape[1]
    syndromes=[]
    for i in range(flat.size//n):
        block=flat[i*n:(i+1)*n]
        syndromes.extend(compute_syndrome(block&1,H).tolist())
    header=syndromes[:16]; msg_len=int(''.join(map(str,header)),2)
    bits=syndromes[16:16+msg_len*8]
    return bytes(np.packbits(bits)).decode('utf-8')

# ----------------------------------------------
# linguistic steganography
# ----------------------------------------------
def get_synonym(word, target_char, lang='en'):
    if target_char==' ': return word
    target_char=target_char.lower()
    mock_synonyms={
        'en':{'dog':['hound','pooch','puppy'], ...},
        'pl':{'pies':['kundel','szczeniak'], ...}
    }
    # simplified
    return word

def linguistic_hide(source, message, lang='pl'):
    # re-use linguistic_steg functions
    from linguistic_steg import hide_message
    return hide_message(source, message, lang)

def linguistic_extract(modified, method='auto'):
    from linguistic_steg import extract_message
    return extract_message(modified, method)

# ----------------------------------------------
# IP steganography
# ----------------------------------------------
def get_loopback_iface():
    sys_min=platform.system().lower()
    if sys_min=='linux': return 'lo'
    if sys_min=='darwin': return 'lo0'
    if sys_min=='windows': return 'Loopback Pseudo-Interface 1'
    raise RuntimeError(f'Unknown system: {sys_min}')


def ip_send(message, dest_ip):
    msg_bytes=message.encode('utf-8');total=len(msg_bytes)
    if total>1000: raise ValueError('Too long')
    pkts=[IP(dst=dest_ip, id=total, ttl=0)]
    for idx,b in enumerate(msg_bytes,1):
        rand_b=random.randrange(256);pid=(b<<8)|rand_b
        pkts.append(IP(dst=dest_ip, id=pid, ttl=idx))
    for p in pkts: send(p, verbose=False)
    return len(pkts)


def ip_receive(timeout=10, filter_expr='ip'):
    iface=get_loopback_iface(); pkts=sniff(iface=iface, timeout=timeout, filter=filter_expr)
    from_ip_pkts=[p for p in pkts if IP in p]
    length_pkt=next((p for p in from_ip_pkts if p[IP].ttl==0),None)
    total=length_pkt[IP].id if length_pkt else 0
    data=[(p[IP].ttl, (p[IP].id>>8)&0xFF) for p in from_ip_pkts if p[IP].ttl>0]
    data.sort(key=lambda x:x[0]);arr=bytes(b for _,b in data)[:total]
    return arr.decode('utf-8'), len(pkts)

# ----------------------------------------------
# audio steganography
# ----------------------------------------------
def audio_encode(input_audio, message, output_audio, group_size=8):
    with wave.open(input_audio,'rb') as wav:
        params=wav.getparams();frames=wav.readframes(params.nframes)
        samples=list(struct.unpack(f'<{params.nframes*params.nchannels}h',frames))
    msg_bytes=message.encode('utf-8');header=len(msg_bytes).to_bytes(4,'big')
    data=header+msg_bytes;binstr=''.join(f'{b:08b}' for b in data)
    bits_needed=len(binstr);max_bits=len(samples)//group_size
    if bits_needed>max_bits: raise ValueError('Too long')
    i=0
    for bit in binstr:
        group=samples[i:i+group_size];par=sum(s&1 for s in group)%2
        if par!=int(bit): group[0]^=1
        samples[i:i+group_size]=group; i+=group_size
    with wave.open(output_audio,'wb') as out_wav:
        out_wav.setparams(params);out_wav.writeframes(struct.pack(f'<{len(samples)}h',*samples))


def audio_decode(stego_audio, group_size=8):
    with wave.open(stego_audio,'rb') as wav:
        params=wav.getparams();frames=wav.readframes(params.nframes)
        samples=struct.unpack(f'<{params.nframes*params.nchannels}h',frames)
    bits=[str(sum(s&1 for s in samples[i:i+group_size])%2) 
          for i in range(0,len(samples),group_size)]
    header_bits=''.join(bits[:32]);msg_len=int(header_bits,2)
    data_bits=''.join(bits[32:32+msg_len*8])
    msg=bytes(int(data_bits[i:i+8],2) for i in range(0,len(data_bits),8))
    return msg.decode('utf-8')

# ----------------------------------------------
# CLI
# ----------------------------------------------
def main():
    parser=argparse.ArgumentParser(prog='stego_tool')
    subparsers=parser.add_subparsers(dest='command')

    # PM1
    pm1= subparsers.add_parser('pm1', help='PM1 steganography')
    pm1.add_argument('action', choices=['hide','extract'])
    pm1.add_argument('-i','--input', required=True)
    pm1.add_argument('-o','--output')
    pm1.add_argument('-m','--message')
    pm1.add_argument('-r',type=int,default=3)
    pm1.add_argument('-c','--channel',type=int,default=0)

    # Linguistic
    ling= subparsers.add_parser('linguistic', help='Linguistic steganography')
    ling.add_argument('action', choices=['hide','extract'])
    ling.add_argument('-s','--source',required=True)
    ling.add_argument('-m','--message')
    ling.add_argument('--method',choices=['auto','sentences','words'],default='auto')
    ling.add_argument('--lang',default='pl')

    # IP
    ip= subparsers.add_parser('ip', help='IP steganography')
    ip.add_argument('mode', choices=['send','receive'])
    ip.add_argument('-m','--message')
    ip.add_argument('-d','--dest')
    ip.add_argument('--timeout',type=float,default=10)

    # Audio
    audio= subparsers.add_parser('audio', help='Audio steganography')
    audio.add_argument('action',choices=['encode','decode'])
    audio.add_argument('-i','--input',required=True)
    audio.add_argument('-o','--output')
    audio.add_argument('-m','--message')

    # Simple LSB
    slsb= subparsers.add_parser('simple_lsb', help='Simple LSB steganography')
    slsb.add_argument('action',choices=['hide','extract'])
    slsb.add_argument('-i','--input',required=True)
    slsb.add_argument('-o','--output')
    slsb.add_argument('-m','--message')
    slsb.add_argument('-c','--channel',type=int,default=0)

    # LSB Detection
    detect= subparsers.add_parser('lsb_detect', help='Detect LSB steganography')
    detect.add_argument('-i','--input',required=True)
    detect.add_argument('-c','--channel',type=int,default=0)

    args=parser.parse_args()
    if args.command=='pm1':
        if args.action=='hide': pm1_hide(args.input,args.output,args.message,args.r,args.channel)
        else: print(pm1_extract(args.input,args.r,args.channel))
    elif args.command=='linguistic':
        if args.action=='hide': print(linguistic_hide(args.source,args.message,args.lang))
        else: print(linguistic_extract(args.source,args.method))
    elif args.command=='ip':
        if args.mode=='send':
            count=ip_send(args.message,args.dest); print(f"Sent {count} packets")
        else:
            msg,c=ip_receive(args.timeout); print(f"Received: {msg}")
    elif args.command=='audio':
        if args.action=='encode': audio_encode(args.input,args.message,args.output)
        else: print(audio_decode(args.input))
    elif args.command=='simple_lsb':
        if args.action=='hide': simple_lsb_hide(args.input,args.output,args.message,args.channel)
        else: print(simple_lsb_extract(args.input,args.channel))
    elif args.command=='lsb_detect':
        print(detect_lsb(args.input,args.channel))
    else:
        parser.print_help()

if __name__=='__main__':
    main()
