ifneq (,$(wildcard ./.env))
    include .env
    export
endif

DOCKER_COMPOSE ?= docker compose
SIGNER_PORT    ?= 888
OUT            ?= data/certs
NAME            = $(notdir $(basename $(DIR:/=)))
HOST_UID       := $(shell id -u)
HOST_GID       := $(shell id -g)

.DEFAULT_GOAL := help

help:  ## Показать список команд
	@awk 'BEGIN {FS = ":.*##"} \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 4); next } \
		/^[a-zA-Z0-9_-]+:.*##/ { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

##@ signer: подпись (XAdES / CAdES, ГОСТ)
sig-build:    ## Собрать образ (OpenSSL+GOST)
	$(DOCKER_COMPOSE) build signer
sig-up:       ## Поднять сервис подписи (API на :888)
	$(DOCKER_COMPOSE) up -d signer
sig-down:     ## Остановить и убрать контейнеры
	$(DOCKER_COMPOSE) down
sig-restart:  ## Перезапустить сервис
	$(MAKE) sig-down sig-up
sig-logs:     ## Логи подписывателя
	$(DOCKER_COMPOSE) logs -f signer
sig-check:    ## Проверить окружение (openssl, gost engine)
	$(DOCKER_COMPOSE) run --rm signer check
sig-health:   ## Пинг API /health
	curl -fsS http://localhost:$(SIGNER_PORT)/health && echo
sig-bash:     ## Shell внутри контейнера
	$(DOCKER_COMPOSE) run --rm signer bash
sig-start:    ## Собрать и поднять
	$(MAKE) sig-build sig-up

##@ cpcert: конвертер ключей КриптоПро в PEM
cpcert-build:  ## Собрать образ конвертера
	docker build -t crypto-amateur-cpcert ./cpcert
cpcert:  ## Извлечь в OUT/<имя>.cer + .key (OUT по умолчанию data/certs)
	@test -n "$(DIR)" || { echo "укажи DIR=путь_к_контейнеру (PASS=пароль, OUT=каталог)"; exit 1; }
	@test -n "$(NAME)" || { echo "не удалось определить имя из DIR=$(DIR)"; exit 1; }
	@mkdir -p "$(OUT)"
	@docker run --rm --entrypoint sh \
		-v "$(abspath $(DIR))":/container:ro \
		-v "$(abspath $(OUT))":/out \
		crypto-amateur-cpcert -c \
		'cpcert -o "/out/$(NAME)" /container "$(PASS)" && chown $(HOST_UID):$(HOST_GID) /out/$(NAME).key /out/$(NAME).cer 2>/dev/null; true'
	@echo "-> $(OUT)/$(NAME).cer + $(OUT)/$(NAME).key"
cpcert-pem:  ## Склеенный PEM в stdout: make cpcert-pem DIR=... PASS=... > out.pem
	@test -n "$(DIR)" || { echo "укажи DIR=путь_к_контейнеру (PASS=пароль)"; exit 1; }
	@docker run --rm -v "$(abspath $(DIR))":/container:ro crypto-amateur-cpcert /container "$(PASS)"

##@ certinfo: инспектор ГОСТ-сертификата
certinfo-build:  ## Собрать образ инспектора
	docker build -t crypto-amateur-certinfo ./certinfo
certinfo:  ## Разбор сертификата: make certinfo FILE=data/certs/valid.cer [JSON=1]
	@test -n "$(FILE)" || { echo "укажи FILE=путь_к_сертификату (JSON=1 для JSON)"; exit 1; }
	@docker run --rm -v "$(abspath $(FILE))":/cert.cer:ro crypto-amateur-certinfo \
		$(if $(JSON),-json) /cert.cer

.PHONY: help sig-build sig-up sig-down sig-logs sig-check sig-bash sig-health sig-start sig-restart cpcert-build cpcert cpcert-pem certinfo-build certinfo
