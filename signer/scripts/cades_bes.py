#!/usr/bin/env python3
"""
Строгий CAdES-BES (ГОСТ): CMS SignedData с ESS-атрибутом signingCertificateV2.

openssl cms (1.1.1) этот атрибут не добавляет, поэтому CMS собираем сами через
asn1crypto, а GOST-хэш/подпись считаем через openssl CLI (gost_functions).
"""
import base64
from datetime import datetime, timezone
from asn1crypto import cms, x509, algos, core
from gost_functions import gost_hash, gost_sign, _alg

# OID-ы алгоритмов ГОСТ по размеру (digest / public-key)
GOST_OIDS = {
    256: {'digest': '1.2.643.7.1.1.2.2', 'signature': '1.2.643.7.1.1.1.1'},
    512: {'digest': '1.2.643.7.1.1.2.3', 'signature': '1.2.643.7.1.1.1.2'},
}

OID_SIGNING_CERT_V2 = '1.2.840.113549.1.9.16.2.47'

class IssuerSerial(core.Sequence):
    _fields = [
        ('issuer', x509.GeneralNames),
        ('serial_number', core.Integer),
    ]

class ESSCertIDv2(core.Sequence):
    _fields = [
        ('hash_algorithm', algos.DigestAlgorithm),
        ('cert_hash', core.OctetString),
        ('issuer_serial', IssuerSerial, {'optional': True}),
    ]


class ESSCertIDv2s(core.SequenceOf):
    _child_spec = ESSCertIDv2


class SigningCertificateV2(core.Sequence):
    _fields = [
        ('certs', ESSCertIDv2s),
    ]


class SetOfSigningCertificateV2(core.SetOf):
    _child_spec = SigningCertificateV2


# Регистрируем signingCertificateV2 как тип CMS-атрибута
cms.CMSAttributeType._map[OID_SIGNING_CERT_V2] = 'signing_certificate_v2'
cms.CMSAttribute._oid_specs['signing_certificate_v2'] = SetOfSigningCertificateV2


def _raw_hash(data, gost_bits):
    return base64.b64decode(gost_hash(data, gost_bits))


def _raw_sign(data, key_path, gost_bits):
    return base64.b64decode(gost_sign(data, key_path, gost_bits))


def _load_cert_der(cert_path):
    raw = open(cert_path, 'rb').read()
    if b'BEGIN CERTIFICATE' in raw:
        b64 = ''.join(
            line.strip() for line in raw.decode().splitlines()
            if line.strip() and 'CERTIFICATE' not in line
        )
        return base64.b64decode(b64)
    return raw


def sign_cades_bes(data, cert_path, key_path, gost_bits=256, detached=False):
    """CMS SignedData (CAdES-BES) в DER. detached=True без вложенного контента."""
    gost_bits = int(gost_bits)
    _alg(gost_bits)  # валидация размера
    oids = GOST_OIDS[gost_bits]

    if isinstance(data, str):
        data = data.encode('utf-8')

    cert_der = _load_cert_der(cert_path)
    cert = x509.Certificate.load(cert_der)

    message_digest = _raw_hash(data, gost_bits)
    cert_hash = _raw_hash(cert_der, gost_bits)

    digest_algo = {'algorithm': oids['digest']}

    ess = SigningCertificateV2({
        'certs': [
            ESSCertIDv2({
                'hash_algorithm': digest_algo,
                'cert_hash': cert_hash,
                'issuer_serial': IssuerSerial({
                    'issuer': [x509.GeneralName({'directory_name': cert.issuer})],
                    'serial_number': cert.serial_number,
                }),
            })
        ]
    })

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({'type': 'content_type', 'values': ['data']}),
        cms.CMSAttribute({'type': 'signing_time',
                          'values': [cms.Time({'utc_time': datetime.now(timezone.utc)})]}),
        cms.CMSAttribute({'type': 'message_digest', 'values': [message_digest]}),
        cms.CMSAttribute({'type': 'signing_certificate_v2', 'values': [ess]}),
    ])

    # Подписываем DER-кодирование signedAttrs как SET OF (RFC 5652 §5.4)
    signature = _raw_sign(signed_attrs.dump(), key_path, gost_bits)

    signer_info = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': cert.issuer,
                'serial_number': cert.serial_number,
            })
        }),
        'digest_algorithm': digest_algo,
        'signed_attrs': signed_attrs,
        'signature_algorithm': {'algorithm': oids['signature']},
        'signature': signature,
    })

    encap = {'content_type': 'data'}
    if not detached:
        encap['content'] = data

    signed_data = cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [digest_algo],
        'encap_content_info': encap,
        'certificates': [cert],
        'signer_infos': [signer_info],
    })

    return cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data,
    }).dump()
