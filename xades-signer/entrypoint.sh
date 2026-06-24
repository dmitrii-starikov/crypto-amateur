#!/bin/bash

python3 /app/scripts/api.py &

function show_help() {
    echo "==========================================="
    echo "ГОСТ XML Подписант"
    echo "==========================================="
    echo ""
    echo "Использование:"
    echo "  sign <xml> <cert> <key> [element_id]"
    echo ""
    echo "Примеры:"
    echo "  sign input.xml cer.cer priv.key"
    echo "  sign input.xml cert.pem key.pem SIGNED_BY_EXPERT"
    echo ""
    echo "Другие команды:"
    echo "  check     - Проверить окружение"
    echo "  list      - Список файлов"
    echo "  bash      - Открыть shell"
    echo ""
}

if [ "$1" = "sign" ]; then
    if [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ]; then
        echo "Ошибка: не указаны все параметры"
        echo ""
        show_help
        exit 1
    fi

    XML_FILE="/app/xml/$2"
    CERT_FILE="/app/certs/$3"
    KEY_FILE="/app/certs/$4"
    ELEMENT_ID="${5:-SIGNED_BY_EXPERT}"

    echo "Подпись XML:"
    echo "  XML:      $XML_FILE"
    echo "  Cert:     $CERT_FILE"
    echo "  Key:      $KEY_FILE"
    echo "  ElementID: $ELEMENT_ID"
    echo ""

    python3 /app/scripts/sign.py "$XML_FILE" "$CERT_FILE" "$KEY_FILE" "$ELEMENT_ID"

elif [ "$1" = "check" ]; then
    echo "==========================================="
    echo "Проверка окружения"
    echo "==========================================="
    echo ""
    echo "Python версия:"
    python3 --version
    echo ""
    echo "OpenSSL версия:"
    openssl version
    echo ""
    echo "GOST engine:"
    openssl engine -t | grep gost || echo "GOST engine не найден!"
    echo ""
    echo "Python пакеты:"
    pip3 list | grep -E "lxml|flask"
    echo ""
    echo "Скрипты:"
    ls -lh /app/scripts/ 2>/dev/null || echo "(пусто)"
    echo ""
    echo "Сертификаты:"
    ls -lh /app/certs/ 2>/dev/null || echo "(пусто)"
    echo ""
    echo "XML файлы:"
    ls -lh /app/xml/ 2>/dev/null || echo "(пусто)"

elif [ "$1" = "list" ]; then
    echo "Скрипты (/app/scripts):"
    ls -lh /app/scripts/ 2>/dev/null || echo "(пусто)"
    echo ""
    echo "Сертификаты (/app/certs):"
    ls -lh /app/certs/ 2>/dev/null || echo "(пусто)"
    echo ""
    echo "XML файлы (/app/xml):"
    ls -lh /app/xml/ 2>/dev/null || echo "(пусто)"

elif [ "$1" = "bash" ]; then
    /bin/bash

else
    show_help
fi
