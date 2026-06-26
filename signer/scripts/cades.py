#!/usr/bin/env python3
"""
CLI для CAdES/CMS-подписи ГОСТ.
"""
import sys
from cades_bes import sign_cades_bes
from gost_functions import detect_gost_bits


def main():
    if len(sys.argv) < 4:
        print("Использование: python cades.py <file> <cert> <key> [detached]")
        sys.exit(1)

    data_file = sys.argv[1]
    cert_file = sys.argv[2]
    key_file = sys.argv[3]
    detached = len(sys.argv) > 4 and sys.argv[4].lower() in ('detached', '1', 'true', 'yes')

    try:
        with open(data_file, 'rb') as f:
            data = f.read()

        gost_bits = detect_gost_bits(key_file)
        der = sign_cades_bes(data, cert_file, key_file, gost_bits=gost_bits, detached=detached)

        out_path = data_file + '.p7s'
        with open(out_path, 'wb') as f:
            f.write(der)

        kind = 'откреплённая' if detached else 'прикреплённая'
        print(f"CAdES-BES подпись ({kind}, ГОСТ-{gost_bits}): {out_path}")

    except Exception as e:
        print(f"\nОшибка: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
