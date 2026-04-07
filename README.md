# Istio Keycloak WASM Plugin

## Что это

WASM-фильтр для Istio ingress gateway, который:
- редиректит пользователя в Keycloak
- обрабатывает callback code -> token
- хранит сессию в HttpOnly cookie
- обновляет access token по refresh token
- грузит JWKS из Keycloak раз в 2 минуты
- проверяет JWT через JWKS
- прокидывает identity headers в backend

## Структура

- Cargo.toml
- src/lib.rs
- Dockerfile
- k8s/serviceentry-keycloak.yaml
- k8s/wasmplugin.yaml

## Требования

- установлен Istio ingress gateway
- есть внешний Keycloak
- confidential client в Keycloak
- redirect URI настроен на:
  https://app.example.com/oauth2/callback

## 1. Настроить Keycloak client

Создай client:
- Client type: OpenID Connect
- Access type / Client authentication: confidential
- Valid redirect URIs:
  https://app.example.com/oauth2/callback
- Web origins:
  https://app.example.com

Нужны:
- client_id
- client_secret
- realm endpoints

## 2. Собрать wasm-модуль

```bash
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1