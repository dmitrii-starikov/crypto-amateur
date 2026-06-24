ifneq (,$(wildcard ./.env))
    include .env
    export
endif

DOCKER_COMPOSE ?= docker compose
XADES_PORT     ?= 888
OUT            ?= data/certs
NAME            = $(notdir $(basename $(DIR:/=)))
HOST_UID       := $(shell id -u)
HOST_GID       := $(shell id -g)

.DEFAULT_GOAL := help

help:  ## Показать список команд
	@awk 'BEGIN {FS = ":.*##"} \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 4); next } \
		/^[a-zA-Z0-9_-]+:.*##/ { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

##@ xades-signer: подпись XML
xs-build:    ## Собрать образ (OpenSSL+GOST)
	$(DOCKER_COMPOSE) build xades-signer
xs-up:       ## Поднять сервис подписи (API на :888)
	$(DOCKER_COMPOSE) up -d xades-signer
xs-down:     ## Остановить и убрать контейнеры
	$(DOCKER_COMPOSE) down
xs-restart:  ## Перезапустить сервис
	$(MAKE) xs-down xs-up
xs-logs:     ## Логи подписывателя
	$(DOCKER_COMPOSE) logs -f xades-signer
xs-check:    ## Проверить окружение (openssl, gost engine)
	$(DOCKER_COMPOSE) run --rm xades-signer check
xs-health:   ## Пинг API /health
	curl -fsS http://localhost:$(XADES_PORT)/health && echo
xs-bash:     ## Shell внутри контейнера
	$(DOCKER_COMPOSE) run --rm xades-signer bash
xs-start:    ## Собрать и поднять
	$(MAKE) xs-build xs-up

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

.PHONY: help xs-build xs-up xs-down xs-logs xs-check xs-bash xs-health xs-start xs-restart cpcert-build cpcert cpcert-pem
