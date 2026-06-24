#!/usr/bin/env python3
import base64
import subprocess
import tempfile
import os
from lxml import etree

DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#'
C14N_EXC = 'http://www.w3.org/2001/10/xml-exc-c14n#'

# Параметры по размеру ключа ГОСТ Р 34.10-2012 (256 / 512 бит)
GOST_ALGS = {
    256: {
        'md': 'md_gost12_256',
        'signature_method': 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256',
        'digest_method': 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256',
    },
    512: {
        'md': 'md_gost12_512',
        'signature_method': 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512',
        'digest_method': 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512',
    },
}


def _alg(gost_bits):
    gost_bits = int(gost_bits)
    if gost_bits not in GOST_ALGS:
        raise ValueError(f"Неподдерживаемый размер ГОСТ: {gost_bits} (ожидается 256 или 512)")
    return GOST_ALGS[gost_bits]


def detect_gost_bits(key_path):
    """Определяет размер ключа ГОСТ (256/512) по приватному ключу. Fallback - 256."""
    try:
        out = subprocess.run(
            ['openssl', 'pkey', '-in', key_path, '-noout', '-text'],
            capture_output=True
        )
        text = (out.stdout + out.stderr).decode(errors='ignore')
        if '512' in text:
            return 512
    except Exception:
        pass
    return 256


def gost_hash(data, gost_bits=256):
    """ГОСТ Р 34.11-2012 хеш (256 или 512 бит)"""
    md = _alg(gost_bits)['md']
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ['openssl', 'dgst', f'-{md}', '-binary', tmp_path],
            capture_output=True
        )

        if result.returncode != 0:
            raise Exception(f"OpenSSL error: {result.stderr.decode()}")

        return base64.b64encode(result.stdout).decode()
    finally:
        os.unlink(tmp_path)


def gost_sign(data, key_path, gost_bits=256):
    """ГОСТ Р 34.10-2012 подпись (256 или 512 бит)"""
    md = _alg(gost_bits)['md']
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    try:
        result = subprocess.run([
            'openssl', 'dgst', f'-{md}',
            '-sign', key_path,
            '-binary',
            tmp_path
        ], capture_output=True)

        if result.returncode != 0:
            raise Exception(f"OpenSSL sign error: {result.stderr.decode()}")

        return base64.b64encode(result.stdout).decode()
    finally:
        os.unlink(tmp_path)


def load_certificate_b64(cert_path):
    """Загрузка сертификата"""
    with open(cert_path, 'rb') as f:
        cert_content = f.read()

    if b'BEGIN CERTIFICATE' in cert_content:
        lines = []
        in_cert = False
        for line in cert_content.decode().split('\n'):
            if 'BEGIN CERTIFICATE' in line:
                in_cert = True
                continue
            if 'END CERTIFICATE' in line:
                break
            if in_cert and line.strip():
                lines.append(line.strip())
        return ''.join(lines)
    else:
        return base64.b64encode(cert_content).decode()


def _strip_blank_text(element):
    """Убирает незначащие пробелы между тегами (in place)."""
    if element.text is not None and element.text.strip() == '':
        element.text = None
    if element.tail is not None and element.tail.strip() == '':
        element.tail = None
    for child in element:
        _strip_blank_text(child)


def remove_whitespace_between_tags(xml_string):
    """Убирает пробелы между тегами (обёртка над строкой, для обратной совместимости)."""
    root = etree.fromstring(xml_string.encode() if isinstance(xml_string, str) else xml_string)
    _strip_blank_text(root)
    return etree.tostring(root, encoding='unicode')


def _c14n(element):
    """Эксклюзивная канонизация (exc-c14n) без комментариев."""
    return etree.tostring(element, method='c14n', exclusive=True, with_comments=False)


def _build_signed_info(element_id, digest_value, alg, with_ns):
    """SignedInfo. with_ns=True добавляет xmlns:ds (нужно для standalone-канонизации)."""
    ds_ns = f' xmlns:ds="{DSIG_NS}"' if with_ns else ''
    return (
        f'<ds:SignedInfo{ds_ns}>'
        f'<ds:CanonicalizationMethod Algorithm="{C14N_EXC}"/>'
        f'<ds:SignatureMethod Algorithm="{alg["signature_method"]}"/>'
        f'<ds:Reference URI="#{element_id}">'
        f'<ds:Transforms><ds:Transform Algorithm="{C14N_EXC}"/></ds:Transforms>'
        f'<ds:DigestMethod Algorithm="{alg["digest_method"]}"/>'
        f'<ds:DigestValue>{digest_value}</ds:DigestValue>'
        f'</ds:Reference></ds:SignedInfo>'
    )


def sign_xml(xml_content, element_id, cert_path, key_path, gost_bits=256):
    """
    Enveloped XAdES-подпись ГОСТ произвольного XML.

    Подпись (<ds:Signature>) вставляется в исходный документ как предыдущий сосед
    подписываемого элемента (или первым потомком, если подписывается корень).
    Структура и корень документа сохраняются - никаких зашитых обёрток.

    :param element_id: значение атрибута Id подписываемого элемента
                       (ищется любой атрибут с локальным именем "Id": wsu:Id, ns1:Id, Id)
    :param gost_bits: 256 или 512 - размер ключа/хэша ГОСТ
    """
    alg = _alg(gost_bits)

    if isinstance(xml_content, str):
        xml_content = xml_content.encode('utf-8')
    if xml_content.startswith(b'<?xml'):
        xml_content = xml_content.split(b'>', 1)[1].lstrip()

    root = etree.fromstring(xml_content)

    # Подписываемый элемент по любому атрибуту с локальным именем "Id"
    targets = root.xpath(f'//*[@*[local-name()="Id"]="{element_id}"]')
    if not targets:
        raise ValueError(f"Элемент с Id '{element_id}' не найден")
    target = targets[0]

    # Убираем незначащие пробелы во всём документе: подписываемый элемент должен
    # побайтово соответствовать тому, что попало в хэш (иначе верификатор не сойдётся),
    # а заодно весь вывод получается минифицированным (без переносов/отступов)
    _strip_blank_text(root)

    # Дайджест подписываемого элемента
    digest_value = gost_hash(_c14n(target), gost_bits)

    # SignedInfo для подписи - канонизируем standalone (со своим xmlns:ds)
    signed_info_canonical = _c14n(
        etree.fromstring(_build_signed_info(element_id, digest_value, alg, with_ns=True).encode())
    )
    signature_value = gost_sign(signed_info_canonical, key_path, gost_bits)
    cert_b64 = load_certificate_b64(cert_path)

    # Итоговый <ds:Signature> (SignedInfo без xmlns:ds - наследуется от Signature)
    signature_xml = (
        f'<ds:Signature xmlns:ds="{DSIG_NS}">'
        f'{_build_signed_info(element_id, digest_value, alg, with_ns=False)}'
        f'<ds:SignatureValue>{signature_value}</ds:SignatureValue>'
        f'<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate>'
        f'</ds:X509Data></ds:KeyInfo>'
        f'</ds:Signature>'
    )
    signature_element = etree.fromstring(signature_xml.encode())

    # Вставляем подпись в документ (enveloped)
    parent = target.getparent()
    if parent is None:
        target.insert(0, signature_element)    # подписывается корень
    else:
        target.addprevious(signature_element)  # рядом с подписываемым элементом

    return etree.tostring(root, encoding='unicode')
