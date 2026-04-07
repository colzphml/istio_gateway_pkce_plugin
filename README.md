# Istio Keycloak WASM Plugin

## Что это

WASM-фильтр для Istio ingress gateway, который:
- редиректит пользователя в Keycloak (PKCE, code challenge S256)
- обрабатывает callback code → token
- хранит сессию в HttpOnly cookie (AES-256-GCM-SIV)
- обновляет access token по refresh token
- грузит JWKS из Keycloak раз в 2 минуты и верифицирует JWT-подпись (RS256)
- прокидывает identity headers (`x-user`, `x-email`, `x-groups`) в backend

Фронт и бэкенд ничего не знают о Keycloak.

## Структура

```
src/lib.rs                          # Весь код плагина
Cargo.toml
Dockerfile                          # multi-stage: rust builder → scratch
helm/keycloak-wasm-auth/            # Helm chart для деплоя
  Chart.yaml
  values.yaml
  templates/
    secret.yaml
    wasmplugin.yaml
    serviceentry.yaml
.github/workflows/build-push.yaml   # CI: сборка и push OCI образа
docs/deploy.md                      # Инструкция по деплою
```

## Требования

- Istio 1.17+ (ingress gateway)
- Kubernetes 1.25+
- Helm 3.x
- Keycloak 21+ с настроенным realm

## Режимы Keycloak client

Плагин поддерживает оба варианта:

| Режим | Keycloak | `oidc.clientSecret` |
|-------|----------|---------------------|
| **Public client + PKCE** | Client authentication: OFF | не нужен (пустой) |
| **Confidential client + PKCE** | Client authentication: ON | обязателен |

Для production рекомендуется confidential client — дополнительный уровень защиты помимо PKCE.

## Быстрый старт

```bash
# Public client (без client_secret)
helm install keycloak-auth helm/keycloak-wasm-auth \
  --namespace istio-system \
  --set keycloak.host=keycloak.example.com \
  --set keycloak.realm=main \
  --set oidc.clientId=istio-gateway \
  --set oidc.redirectUri="https://app.example.com/oauth2/callback" \
  --set session.cryptoSecret="$(openssl rand -base64 32)" \
  --set cookie.domain=".example.com"

# Confidential client (с client_secret)
helm install keycloak-auth helm/keycloak-wasm-auth \
  --namespace istio-system \
  --set keycloak.host=keycloak.example.com \
  --set keycloak.realm=main \
  --set oidc.clientId=istio-gateway \
  --set oidc.clientSecret="<secret>" \
  --set oidc.redirectUri="https://app.example.com/oauth2/callback" \
  --set session.cryptoSecret="$(openssl rand -base64 32)" \
  --set cookie.domain=".example.com"
```

Подробная инструкция: [docs/deploy.md](docs/deploy.md)

## Сборка вручную

```bash
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
# Артефакт: target/wasm32-wasip1/release/istio_keycloak_wasm_plugin.wasm
```

## Публикация образа

```bash
git tag v0.3.0
git push origin v0.3.0
# GitHub Actions соберёт и запушит в ghcr.io автоматически
```
