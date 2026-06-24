#!/usr/bin/env python3
"""
Flask API для подписи XML с GOST
"""

from flask import Flask, request, jsonify
import os
from gost_functions import sign_xml, detect_gost_bits

app = Flask(__name__)

# Пути по умолчанию
DEFAULT_CERT_PATH = '/app/certs/certificate.cer'
DEFAULT_KEY_PATH = '/app/certs/private.key'

# Ограничение размера тела запроса
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB


def resolve_gost_bits(value, key_path):
    """256/512 явно, либо 'auto'/пусто -> определить по ключу (fallback 256)."""
    if value in (None, '', 'auto'):
        return detect_gost_bits(key_path)
    return int(value)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'success': True,
        'status': 'ok'
    })


@app.route('/sign', methods=['POST'])
def sign():
    """
    Подпись XML из строки

    Request body (JSON):
    {
        "xml": "строка с XML",
        "id": "element-id",
        "certificate": "путь к сертификату (опционально)",
        "key": "путь к ключу (опционально)",
        "algorithm": "256 | 512 | auto (опционально, по умолчанию 256)"
    }

    Response (JSON):
    {
        "success": true/false,
        "result": "подписанный XML" или null,
        "error": "текст ошибки" или null
    }
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                'success': False,
                'error': 'Не передан JSON в теле запроса'
            }), 400

        xml_content = data.get('xml')
        element_id = data.get('id')

        if not xml_content:
            return jsonify({
                'success': False,
                'error': 'Не указан параметр "xml"'
            }), 400

        if not element_id:
            return jsonify({
                'success': False,
                'error': 'Не указан параметр "id"'
            }), 400

        cert_path = data.get('certificate', DEFAULT_CERT_PATH)
        key_path = data.get('key', DEFAULT_KEY_PATH)

        if not os.path.exists(cert_path):
            return jsonify({
                'success': False,
                'error': f'Сертификат не найден: {cert_path}'
            }), 400

        if not os.path.exists(key_path):
            return jsonify({
                'success': False,
                'error': f'Ключ не найден: {key_path}'
            }), 400

        # Размер ГОСТ: 256 (по умолчанию), 512 или 'auto' (определить по ключу)
        gost_bits = resolve_gost_bits(data.get('algorithm', 256), key_path)

        signed_xml = sign_xml(xml_content, element_id, cert_path, key_path, gost_bits)

        return jsonify({
            'success': True,
            'result': signed_xml,
            'error': None
        })

    except ValueError as e:
        return jsonify({
            'success': False,
            'result': None,
            'error': str(e)
        }), 400

    except Exception as e:
        return jsonify({
            'success': False,
            'result': None,
            'error': f'Ошибка при подписи: {str(e)}'
        }), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
