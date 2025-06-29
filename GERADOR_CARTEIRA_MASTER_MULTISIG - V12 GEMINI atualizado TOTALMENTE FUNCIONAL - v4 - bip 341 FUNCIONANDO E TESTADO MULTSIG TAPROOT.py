# -*- coding: utf-8 -*-

"""
GERADOR DE CARTEIRAS BITCOIN OFFLINE - v2.4 (Final)
===================================================

Este script gera diferentes tipos de carteiras Bitcoin para uso em um ambiente offline e seguro.
Ele é capaz de criar carteiras Electrum, Native Segwit (BIP84), Taproot (BIP86), 
Multisig Segwit (BIP48) e Multisig Taproot usando descritores Miniscript.

!! AVISO DE SEGURANÇA !!
-------------------------
Execute este script SOMENTE em um computador seguro, offline (air-gapped) e de sua confiança.
A exposição de chaves privadas ou mnemonics a um ambiente online pode resultar na perda
permanente de seus fundos.

DEPENDÊNCIAS:
-------------
1. Bibliotecas Python:
   pip install "bip_utils>=2.0.0" qrcode python-gnupg "bitcoin>=1.1.42"

2. Software Externo:
   - GnuPG (GPG): É necessário ter o GPG instalado e configurado no sistema para a
     criptografia dos dados sensíveis. As chaves públicas dos destinatários devem
     ser importadas para o seu chaveiro GPG.

"""

import os
import secrets
import hashlib
import gnupg
import qrcode
from pathlib import Path
from datetime import datetime
from itertools import combinations
from bip_utils import (
    Bip39MnemonicGenerator,
    Bip39SeedGenerator,
    Bip84, Bip84Coins,
    Bip86, Bip86Coins,
    Bip32Slip10Secp256k1,
    Bip44Changes,
)
from bitcoin import encode_privkey, privtopub, pubtoaddr
from typing import List, Dict, Any, Optional

# ==== CONFIGURAÇÕES GLOBAIS ====

# Diretório onde as carteiras geradas serão salvas.
OUTPUT_DIR = Path("Wallets_Geradas_Offline")
OUTPUT_DIR.mkdir(exist_ok=True)

# IDs das chaves públicas GPG que serão usadas para criptografar os arquivos de backup.
# IMPORTANTE: Substitua pelos IDs de suas próprias chaves GPG.
RECIPIENT_KEY_IDS = [
    "089DAE1840C1CE13", "005CD027E4F20FFD", "00F1B6A6792E943A", "343EDA551C9055D5",
    "710C2836B8A52C23", "0EC30FD5C87BC6BA", "F8C175287ECF94E3", "D70DC784FE8BEB3F",
]

# Padrões de derivação para cada tipo de carteira.
DERIVATION_BIP48 = "m/48'/0'/0'/2'"
DERIVATION_BIP84 = "m/84'/0'/0'"
DERIVATION_BIP86 = "m/86'/0'/0'"
DERIVATION_BIP87 = "m/87'/0'/0'" # Para o formato Miniscript

# Caracteres utilizados para o cálculo do checksum de descriptors.
DESCRIPTOR_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<>?!^_|~`abcdefghijklmnopqrstuvwxyz"
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# ==== FUNÇÕES UTILITÁRIAS ====

def descriptor_checksum(desc: str) -> str:
    """Calcula o checksum para um output descriptor de Bitcoin."""
    def poly_mod(c: int, v: int) -> int:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ v
        for i in range(5):
            if (c0 >> i) & 1:
                c ^= [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D,
                      0x3706B1677A, 0x644D626FF][i]
        return c
    c = 1
    cls = clscount = 0
    for ch in desc:
        pos = DESCRIPTOR_CHARSET.find(ch)
        if pos == -1: continue
        c = poly_mod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        clscount += 1
        if clscount == 3:
            c = poly_mod(c, cls)
            cls = clscount = 0
    if clscount:
        c = poly_mod(c, cls)
    for _ in range(8):
        c = poly_mod(c, 0)
    return "".join(CHECKSUM_CHARSET[(c >> (5 * (7 - i))) & 31] for i in range(8))

def compute_fingerprint(ctx) -> str:
    """Calcula o fingerprint de 4 bytes de uma chave mestre."""
    pub = ctx.PublicKey().RawCompressed().ToBytes()
    return hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()[:4].hex()

def generate_qr(data: str, filename: Path) -> None:
    """Gera e salva uma imagem de QR Code."""
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_Q)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)
    print(f"  - QR Code salvo em: {filename.name}")

def gpg_encrypt(text: str, filename: Path) -> None:
    """Criptografa um texto usando GPG para os destinatários configurados."""
    text_ascii = text.encode('ascii', 'ignore').decode('ascii')
    gpg = gnupg.GPG()
    enc = gpg.encrypt(text_ascii, RECIPIENT_KEY_IDS, always_trust=True, armor=True)
    if not enc.ok:
        raise RuntimeError(f"Erro de criptografia GPG: {enc.status}\n{enc.stderr}")
    filename.write_text(str(enc), encoding="utf-8")
    print(f"  - Backup criptografado salvo em: {filename.name}")

def export_bsms_sparrow(descriptor: str, name: str) -> None:
    """Exporta um arquivo .bsms para importação na Sparrow Wallet."""
    bsms_content = f"BSMS 1.0\n{descriptor}\n/0/*,/1/*\n"
    filepath = OUTPUT_DIR / f"{name}.bsms"
    filepath.write_text(bsms_content, encoding="utf-8")
    print(f"  - Arquivo de importação '{filepath.name}' gerado para Sparrow.")

# ==== FUNÇÕES DE GERAÇÃO DE CARTEIRAS ====

def generate_electrum_wallet(idx: int) -> None:
    """Gera uma carteira de chave privada única (formato WIF) para Electrum."""
    print(f"\nGerando carteira Electrum {idx}...")
    priv_hex = secrets.token_hex(32)
    wif = encode_privkey(priv_hex, "wif")
    pub = privtopub(wif)
    addr = pubtoaddr(pub)
    name = f"Electrum_{idx}"
    Path(OUTPUT_DIR / f"{name}_address.txt").write_text(addr, encoding="utf-8")
    generate_qr(addr, OUTPUT_DIR / f"{name}_address.png")
    content = f"""
==========================
CARTEIRA ELECTRUM {idx}
==========================
Data de Geracao: {datetime.today().strftime('%d/%m/%Y %H:%M:%S')}
Chave Privada (WIF): {wif}
Endereco (Legacy): {addr}
Observacoes:
Carteira Electrum com chave privada unica no formato WIF (Wallet Import Format).
Use a funcao "Importar Chaves Privadas" na Electrum.
==========================
"""
    gpg_encrypt(content, OUTPUT_DIR / f"{name}_wif.asc")
    print(f"✔️ Carteira Electrum {idx} gerada — Endereço: {addr}")

def generate_segwit_wallet(idx: int, words: int, passphrase: str = "") -> None:
    """Gera uma carteira HD Native Segwit (BIP84)."""
    print(f"\nGerando carteira Native Segwit {idx}...")
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(words)
    seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    ctx = Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
    acc = ctx.Purpose().Coin().Account(0)
    zpub = acc.PublicKey().ToExtended()
    fp = compute_fingerprint(ctx)
    addr = acc.Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
    desc_body = f"wpkh([{fp}/84h/0h/0h]{zpub}/0/*)"
    descriptor_full = f"{desc_body}#{descriptor_checksum(desc_body)}"
    qr_content_descriptor = f"{descriptor_full}\n/0/*,/1/*"
    name = f"NativeSegwit_{idx}"
    Path(OUTPUT_DIR / f"{name}_address.txt").write_text(addr, encoding="utf-8")
    Path(OUTPUT_DIR / f"{name}_descriptor.txt").write_text(descriptor_full, encoding="utf-8")
    generate_qr(addr, OUTPUT_DIR / f"{name}_address.png")
    generate_qr(qr_content_descriptor, OUTPUT_DIR / f"{name}_descriptor.png")
    export_bsms_sparrow(descriptor_full, name)
    content = f"""
==========================
CARTEIRA NATIVE SEGWIT (BIP84) {idx}
==========================
Data de Geracao: {datetime.today().strftime('%d/%m/%Y %H:%M:%S')}
Mnemonic ({words} palavras): {mnemonic}
Passphrase: {passphrase or 'Nao utilizada'}
Fingerprint: {fp}
Derivacao: {DERIVATION_BIP84}
Primeiro Endereco: {addr}
Descriptor: {descriptor_full}
Observacoes:
Carteira Hierarquica Determinista (HD) Native Segwit (P2WPKH).
==========================
"""
    gpg_encrypt(content, OUTPUT_DIR / f"{name}_mnemonic.asc")
    print(f"✔️ Carteira Native Segwit {idx} gerada — Endereço: {addr}")

def generate_taproot_wallet(idx: int, words: int, passphrase: str = "") -> None:
    """Gera uma carteira HD Taproot (BIP86)."""
    print(f"\nGerando carteira Taproot {idx}...")
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(words)
    seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    ctx = Bip86.FromSeed(seed, Bip86Coins.BITCOIN)
    acc = ctx.Purpose().Coin().Account(0)
    tpub = acc.PublicKey().ToExtended()
    fp = compute_fingerprint(ctx)
    addr = acc.Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
    desc_body = f"tr([{fp}/86h/0h/0h]{tpub}/0/*)"
    descriptor_full = f"{desc_body}#{descriptor_checksum(desc_body)}"
    qr_content_descriptor = f"{descriptor_full}\n/0/*,/1/*"
    name = f"Taproot_{idx}"
    Path(OUTPUT_DIR / f"{name}_address.txt").write_text(addr, encoding="utf-8")
    Path(OUTPUT_DIR / f"{name}_descriptor.txt").write_text(descriptor_full, encoding="utf-8")
    generate_qr(addr, OUTPUT_DIR / f"{name}_address.png")
    generate_qr(qr_content_descriptor, OUTPUT_DIR / f"{name}_descriptor.png")
    export_bsms_sparrow(descriptor_full, name)
    content = f"""
==========================
CARTEIRA TAPROOT (BIP86) {idx}
==========================
Data de Geracao: {datetime.today().strftime('%d/%m/%Y %H:%M:%S')}
Mnemonic ({words} palavras): {mnemonic}
Passphrase: {passphrase or 'Nao utilizada'}
Fingerprint: {fp}
Derivacao: {DERIVATION_BIP86}
Primeiro Endereco: {addr}
Descriptor: {descriptor_full}
Observacoes:
Carteira Hierarquica Determinista (HD) Taproot (P2TR).
==========================
"""
    gpg_encrypt(content, OUTPUT_DIR / f"{name}_mnemonic.asc")
    print(f"✔️ Carteira Taproot {idx} gerada — Endereço: {addr}")

def generate_multisig_wallet(name: str, m: int, n: int, words: int, passphrase: str = "") -> None:
    """Gera uma carteira Multisig Segwit (BIP48)."""
    print(f"\nGerando carteira Multisig Segwit {m}-de-{n} '{name}'...")
    cosigners: List[Dict[str, Any]] = []
    for i in range(n):
        print(f"  - Gerando cosigner {i + 1}/{n}...")
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(words)
        seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
        ctx = Bip32Slip10Secp256k1.FromSeed(seed)
        fp = compute_fingerprint(ctx)
        node = ctx.DerivePath(DERIVATION_BIP48)
        xpub = node.PublicKey().ToExtended()
        cosigners.append({"index": i + 1, "mnemonic": str(mnemonic), "xpub": xpub, "fingerprint": fp})
    cos_sorted = sorted(cosigners, key=lambda c: bytes.fromhex(c["fingerprint"]))
    desc_parts = [f"[{c['fingerprint']}/48h/0h/0h/2h]{c['xpub']}" for c in cos_sorted]
    body = f"wsh(sortedmulti({m},{','.join(desc_parts)}))"
    descriptor = f"{body}#{descriptor_checksum(body)}"
    qr_content_descriptor = f"{descriptor}\n/0/*,/1/*"
    Path(OUTPUT_DIR / f"{name}_descriptor.txt").write_text(descriptor, encoding="utf-8")
    generate_qr(qr_content_descriptor, OUTPUT_DIR / f"{name}_descriptor.png")
    export_bsms_sparrow(descriptor, name)
    for c in cosigners:
        generate_qr(c["xpub"], OUTPUT_DIR / f"{name}_cosigner{c['index']}_xpub.png")
        content = f"""
==========================
COSIGNER {c['index']} / {n} - CARTEIRA MULTISIG SEGWIT '{name.upper()}'
==========================
Data de Geracao: {datetime.today().strftime('%d/%m/%Y %H:%M:%S')}
Mnemonic ({words} palavras): {c['mnemonic']}
Passphrase: {passphrase or 'Nao utilizada'}
--------------------------
Fingerprint Mestre: {c['fingerprint']}
Derivacao da xpub: {DERIVATION_BIP48}
xpub: {c['xpub']}
--------------------------
Descriptor da Carteira ({m}-de-{n}): {descriptor}
Observacoes:
Este e o backup para UM dos {n} cosigners da carteira multisig {m}-de-{n} '{name}'.
Guarde cada backup de cosigner de forma separada e segura.
==========================
"""
        gpg_encrypt(content, OUTPUT_DIR / f"{name}_cosigner{c['index']}.asc")
    print(f"✔️ Carteira Multisig Segwit {m}-de-{n} '{name}' gerada com sucesso.")

def generate_taproot_simple_multisig_wallet(name: str, m: int, n: int, words: int, passphrase: str = "") -> None:
    """Gera uma carteira Multisig Taproot (P2TR) com uma chave interna simples."""
    print(f"\nGerando carteira Multisig Taproot Simples {m}-de-{n} '{name}'...")
    cosigners: List[Dict[str, Any]] = []
    origin_xpubs: List[str] = []
    for i in range(n):
        print(f"  - Gerando cosigner {i + 1}/{n}...")
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(words)
        seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
        ctx = Bip86.FromSeed(seed, Bip86Coins.BITCOIN)
        acc = ctx.Purpose().Coin().Account(0)
        fp = compute_fingerprint(ctx)
        tpub = acc.PublicKey().ToExtended()
        origin_xpub = f"[{fp}{DERIVATION_BIP86.replace('m', '')}]{tpub}"
        origin_xpubs.append(origin_xpub)
        cosigners.append({"index": i + 1, "mnemonic": str(mnemonic), "xpub": tpub, "fingerprint": fp, "origin_xpub": origin_xpub})
    origin_xpubs.sort()
    internal_key = origin_xpubs[0]
    script_keys = ",".join(origin_xpubs)
    script_path = f"sortedmulti_a({m},{script_keys})"
    desc_body = f"tr({internal_key}/0/*,{{{script_path}/1/*}})"
    descriptor = f"{desc_body}#{descriptor_checksum(desc_body)}"
    qr_content_descriptor = f"{descriptor}\n/0/*,/1/*"
    Path(OUTPUT_DIR / f"{name}_descriptor.txt").write_text(descriptor, encoding="utf-8")
    generate_qr(qr_content_descriptor, OUTPUT_DIR / f"{name}_descriptor.png")
    export_bsms_sparrow(descriptor, name)
    for c in cosigners:
        generate_qr(c["origin_xpub"], OUTPUT_DIR / f"{name}_cosigner{c['index']}_xpub.png")
        content = f"""
==========================
COSIGNER {c['index']} / {n} - CARTEIRA MULTISIG TAPROOT SIMPLES '{name.upper()}'
==========================
Data de Geracao: {datetime.today().strftime('%d/%m/%Y %H:%M:%S')}
Mnemonic ({words} palavras): {c['mnemonic']}
Passphrase: {passphrase or 'Nao utilizada'}
--------------------------
Fingerprint Mestre: {c['fingerprint']}
Derivacao da xpub: {DERIVATION_BIP86}
xpub com origem (para descriptor): {c['origin_xpub']}
--------------------------
Descriptor da Carteira ({m}-de-{n}): {descriptor}
==========================
"""
        gpg_encrypt(content, OUTPUT_DIR / f"{name}_cosigner{c['index']}.asc")
    print(f"✔️ Carteira Multisig Taproot Simples {m}-de-{n} '{name}' gerada com sucesso.")

def generate_taproot_advanced_miniscript_wallet(name: str, m: int, n: int, words: int, passphrase: str = "") -> None:
    """Gera uma carteira Multisig Taproot usando um descritor Miniscript (BIP 87)."""
    print(f"\nGerando carteira Multisig Taproot (Avançado - Miniscript) {m}-de-{n} '{name}'...")
    cosigners: List[Dict[str, Any]] = []
    for i in range(n):
        print(f"  - Gerando cosigner {i + 1}/{n}...")
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(words)
        seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
        ctx = Bip32Slip10Secp256k1.FromSeed(seed)
        fp = compute_fingerprint(ctx)
        node = ctx.DerivePath(DERIVATION_BIP87)
        xpub = node.PublicKey().ToExtended()
        origin_xpub = f"[{fp}{DERIVATION_BIP87.replace('m', '')}]{xpub}/**"
        cosigners.append({
            "index": i + 1, "mnemonic": str(mnemonic), "xpub": xpub,
            "fingerprint": fp, "origin_xpub": origin_xpub
        })
    cosigners.sort(key=lambda c: c['fingerprint'])
    all_origin_xpubs = [c['origin_xpub'] for c in cosigners]
    key_path_policy = f"musig({','.join(all_origin_xpubs)})"
    script_path_policies = []
    key_combinations = combinations(all_origin_xpubs, m)
    for combo in key_combinations:
        script_path_policies.append(f"pk(musig({','.join(combo)}))")
    def build_script_tree(policies: List[str]) -> str:
        if not policies: return ""
        if len(policies) == 1: return policies[0]
        mid = len(policies) // 2
        left = build_script_tree(policies[:mid])
        right = build_script_tree(policies[mid:])
        return f"{{{left},{right}}}"
    script_tree = build_script_tree(script_path_policies)
    desc_body = f"tr({key_path_policy},{script_tree})"
    descriptor = f"{desc_body}#{descriptor_checksum(desc_body)}"
    qr_content_descriptor = f"{descriptor}\n/0/*,/1/*"
    Path(OUTPUT_DIR / f"{name}_descriptor.txt").write_text(descriptor, encoding="utf-8")
    generate_qr(qr_content_descriptor, OUTPUT_DIR / f"{name}_descriptor.png")
    export_bsms_sparrow(descriptor, name)
    for c in cosigners:
        generate_qr(c["xpub"], OUTPUT_DIR / f"{name}_cosigner{c['index']}_xpub.png")
        content = f"""
==========================
COSIGNER {c['index']} / {n} - CARTEIRA MULTISIG TAPROOT (AVANÇADO - MINISCRIPT) '{name.upper()}'
==========================
Data de Geracao: {datetime.today().strftime('%d/%m/%Y %H:%M:%S')}
Mnemonic ({words} palavras): {c['mnemonic']}
Passphrase: {passphrase or 'Nao utilizada'}
--------------------------
Fingerprint Mestre: {c['fingerprint']}
Derivacao da xpub: {DERIVATION_BIP87}
xpub com origem (para descriptor): {c['origin_xpub']}
--------------------------
Descriptor da Carteira ({m}-de-{n}): {descriptor}
Observacoes:
Este e o backup para UM dos {n} cosigners da carteira multisig Taproot (Miniscript) {m}-de-{n} '{name}'.
O descriptor usa 'musig' para definir politicas de gasto cooperativas (n-de-n) e de recuperacao (m-de-n).
Guarde cada backup de cosigner de forma separada e segura.
==========================
"""
        gpg_encrypt(content, OUTPUT_DIR / f"{name}_cosigner{c['index']}.asc")
    print(f"✔️ Carteira Multisig Taproot (Avançado - Miniscript) {m}-de-{n} '{name}' gerada com sucesso.")


# ==== FUNÇÃO PRINCIPAL E INTERFACE ====

def get_validated_int(prompt: str, min_val: Optional[int] = None, max_val: Optional[int] = None) -> int:
    """Solicita um número inteiro ao usuário e o valida."""
    while True:
        try:
            val = int(input(prompt))
            if (min_val is not None and val < min_val) or (max_val is not None and val > max_val):
                print(f"Erro: O valor deve estar entre {min_val} e {max_val}.")
            else:
                return val
        except ValueError:
            print("Erro: Entrada invalida. Por favor, insira um numero inteiro.")

def main():
    """Exibe o menu principal e gerencia o fluxo do programa."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print("==========================================")
    print("=== GERADOR DE CARTEIRAS BTC OFFLINE ===")
    print("==========================================")
    print("!! AVISO: USE APENAS EM UM AMBIENTE OFFLINE E SEGURO !!\n")

    while True:
        print("\nEscolha o tipo de carteira a ser gerada:")
        print("1. Electrum (Chave Privada Única)")
        print("2. Native Segwit (BIP84)")
        print("3. Taproot (BIP86)")
        print("4. Multisig Segwit (BIP48)")
        print("5. Multisig Taproot (Simples)")
        print("6. Multisig Taproot (Avançado - Miniscript)")
        print("7. Sair")

        opt = input("Sua escolha (1-7): ").strip()

        if opt == "1":
            qnt = get_validated_int("Quantas carteiras Electrum deseja gerar? ", min_val=1)
            for i in range(1, qnt + 1):
                generate_electrum_wallet(i)
        elif opt in ("2", "3"):
            wallet_type = "Native Segwit" if opt == "2" else "Taproot"
            qnt = get_validated_int(f"Quantas carteiras {wallet_type} deseja gerar? ", min_val=1)
            while True:
                words = get_validated_int("Numero de palavras para o mnemonic (12/18/24)? ", min_val=12)
                if words in (12, 18, 24): break
                print("Erro: Numero de palavras deve ser 12, 18 ou 24.")
            passphrase = input("Digite a passphrase (opcional, pressione Enter para deixar em branco): ")
            for i in range(1, qnt + 1):
                if opt == "2":
                    generate_segwit_wallet(i, words, passphrase)
                else:
                    generate_taproot_wallet(i, words, passphrase)
        elif opt in ("4", "5", "6"):
            if opt == "4":
                name = input("Digite um nome para a carteira Multisig Segwit (ex: 'Holding_Familia'): ")
                n = get_validated_int("Total de cosigners (n): ", min_val=2)
                m = get_validated_int(f"Numero minimo de assinaturas (m, entre 1 e {n}): ", min_val=1, max_val=n)
            elif opt == "5":
                name = input("Digite um nome para a carteira Multisig Taproot Simples (ex: 'Cofre_Taproot'): ")
                n = get_validated_int("Total de cosigners (n): ", min_val=2)
                m = get_validated_int(f"Numero minimo de assinaturas (m, entre 1 e {n}): ", min_val=1, max_val=n)
            elif opt == "6":
                name = input("Digite um nome para a carteira Multisig Taproot Avançada (ex: 'Cofre_Avançado'): ")
                n = get_validated_int("Total de cosigners (n): ", min_val=2)
                m = get_validated_int(f"Numero minimo de assinaturas para recuperacao (m, entre 1 e {n}): ", min_val=1, max_val=n)
            
            while True:
                words = get_validated_int("Numero de palavras para o mnemonic (12/18/24)? ", min_val=12)
                if words in (12, 18, 24): break
                print("Erro: Numero de palavras deve ser 12, 18 ou 24.")
            passphrase = input("Digite a passphrase (opcional para TODOS os cosigners): ")
            
            if opt == "4":
                generate_multisig_wallet(name, m, n, words, passphrase)
            elif opt == "5":
                generate_taproot_simple_multisig_wallet(name, m, n, words, passphrase)
            elif opt == "6":
                generate_taproot_advanced_miniscript_wallet(name, m, n, words, passphrase)
        elif opt == "7":
            break
        else:
            print("Opção inválida. Por favor, escolha uma das opções acima.")

    print("\n=== PROGRAMA FINALIZADO ===")
    print(f"Verifique os arquivos gerados no diretorio: {OUTPUT_DIR.resolve()}")

if __name__ == "__main__":
    main()