# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

WASM-фильтр для Istio ingress gateway, реализующий OIDC-аутентификацию через Keycloak. Написан на Rust, компилируется в `.wasm` для target `wasm32-wasip1` и загружается через Istio `WasmPlugin` CRD.

## Build Commands

```bash
# Добавить target (один раз)
rustup target add wasm32-wasip1

# Собрать wasm-модуль
cargo build --release --target wasm32-wasip1
# Артефакт: target/wasm32-wasip1/release/istio_keycloak_wasm_plugin.wasm

# Собрать Docker-образ (копирует только .wasm через multi-stage build)
docker build -t ghcr.io/your-org/istio-keycloak-wasm-plugin:0.3.0 .
```

Тестов нет — логика фильтра тестируется в живой среде с Istio.

## Architecture

Весь код — `src/lib.rs`. Архитектура строится на `proxy-wasm` ABI:

- **`AuthRoot`** (RootContext) — синглтон на уровне воркера. Хранит `PluginConfig` и кэш JWKS. Обновляет JWKS каждые 120 секунд через HTTP-колбэк к Keycloak (`jwks_uri`), используя `dispatch_http_call` к `upstream_cluster`.
- **`AuthFilter`** (HttpContext) — создаётся для каждого входящего запроса. Реализует `on_http_request_headers`. Обрабатывает пути:
  - `/oauth2/callback` — обменивает code на токены (PKCE), шифрует сессию, ставит cookie
  - `/oauth2/start` — принудительный старт OIDC-флоу
  - `/oauth2/logout` — удаляет cookie, редиректит в Keycloak logout
  - Все остальные пути — проверяет cookie-сессию, при необходимости делает refresh, пробрасывает identity headers в backend

**Сессия** хранится в `HttpOnly` cookie `mesh_session`: структура `Session` сериализуется в JSON, шифруется AES-256-GCM-SIV (ключ через HKDF из `crypto_secret`), кодируется в base64.

**PKCE и CSRF** — pending state (verifier + redirect URL + timestamp) шифруется в cookie `mesh_csrf`.

## Deployment

Конфигурация в `k8s/wasmplugin.yaml`. Ключевые параметры `pluginConfig`:
- `upstream_cluster` — Envoy cluster для Keycloak (формат: `outbound|443||keycloak.example.com`). Должен совпадать с `ServiceEntry` из `k8s/serviceentry-keycloak.yaml`.
- `crypto_secret` — минимум 32 байта случайных данных для шифрования сессий.
- `public_prefixes` — пути, которые пропускаются без аутентификации.

**Важно про роутинг:** плагин работает на ingress gateway и перехватывает `/oauth2/callback` до backend. Если в VirtualService есть жёсткие path-match правила, убедиться, что `/oauth2/callback` не отбрасывается.
