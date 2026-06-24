#!/usr/bin/env python3
"""
CLI для подписи XML с GOST
"""

import sys
from lxml import etree
from gost_functions import gost_hash, gost_sign, load_certificate_b64, remove_whitespace_between_tags, sign_xml

def main():
    if len(sys.argv) < 5:
        print("Использование: python sign.py <xml> <cert> <key> <element_id>")
        sys.exit(1)

    xml_file = sys.argv[1]
    cert_file = sys.argv[2]
    key_file = sys.argv[3]
    element_id = sys.argv[4]

    try:
        with open(xml_file, 'rb') as f:
            xml_content = f.read()

        output_path = xml_file.replace('.xml', '_signed.xml')

        result_xml= sign_xml(xml_content, element_id, cert_file, key_file)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result_xml)

        print(f"Подписанный файл: {output_path}")

    except Exception as e:
        print(f"\n❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
