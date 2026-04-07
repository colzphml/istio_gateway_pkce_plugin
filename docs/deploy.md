# Деплой Keycloak WASM Auth Plugin

## Предварительные требования

- Kubernetes 1.25+
- Istio 1.17+ (тестировалось на 1.29.1)
- Helm 3.x
- kubectl настроен на целевой кластер
- Keycloak 21+ с настроенным realm

## 1. Настройка Keycloak client

В Keycloak Admin Console создать клиент: **Clients → Create client**
- Client ID: `istio-gateway` (или свой)
- Client type: `OpenID Connect`

Общие настройки для обоих режимов:
- Standard flow: ✅ включить
- Direct access grants: ❌ выключить
- Valid redirect URIs: `https://app.example.com/oauth2/callback`
- Web origins: `https://app.example.com`
- Advanced → Proof Key for Code Exchange Code Challenge Method: `S256`

### Вариант A: Public client (PKCE без секрета)

- **Client authentication: OFF**
- `oidc.clientSecret` в Helm не нужен

### Вариант B: Confidential client (PKCE + секрет)

- **Client authentication: ON**
- Credentials → Client secret: скопировать значение
- Передать в Helm через `--set oidc.clientSecret="..."`

Если нужны группы в токене: Client Scopes → Add mapper → Group Membership → Token Claim Name: `groups`

## 2. Подготовка crypto_secret

Сгенерировать случайный секрет (минимум 32 байта):

```bash
openssl rand -base64 32
```

## 3. Установка через Helm

### Public client (без client_secret)

```bash
helm install keycloak-auth helm/keycloak-wasm-auth \
  --namespace istio-system \
  --set keycloak.host=keycloak.example.com \
  --set keycloak.realm=main \
  --set oidc.clientId=istio-gateway \
  --set oidc.redirectUri="https://app.example.com/oauth2/callback" \
  --set session.cryptoSecret="$(openssl rand -base64 32)" \
  --set cookie.domain=".example.com"
```

### Confidential client (с client_secret)

```bash
helm install keycloak-auth helm/keycloak-wasm-auth \
  --namespace istio-system \
  --set keycloak.host=keycloak.example.com \
  --set keycloak.realm=main \
  --set oidc.clientId=istio-gateway \
  --set oidc.clientSecret="<client_secret из Keycloak>" \
  --set oidc.redirectUri="https://app.example.com/oauth2/callback" \
  --set session.cryptoSecret="$(openssl rand -base64 32)" \
  --set cookie.domain=".example.com"
```

### Через values-override.yaml

```yaml
keycloak:
  host: keycloak.example.com
  realm: main

oidc:
  clientId: istio-gateway
  redirectUri: https://app.example.com/oauth2/callback
  # clientSecret: ""  # оставить пустым для public client

cookie:
  domain: .example.com
```

```bash
helm install keycloak-auth helm/keycloak-wasm-auth \
  --namespace istio-system \
  -f values-override.yaml \
  --set session.cryptoSecret="$(openssl rand -base64 32)"
  # добавить --set oidc.clientSecret="..." для confidential client
```

## 4. Использование существующего Secret

Если секрет уже создан вне Helm:

```bash
# Confidential client
kubectl create secret generic my-keycloak-secret \
  --namespace istio-system \
  --from-literal=client_secret="<secret>" \
  --from-literal=crypto_secret="<openssl rand -base64 32>"

# Public client — client_secret оставить пустым
kubectl create secret generic my-keycloak-secret \
  --namespace istio-system \
  --from-literal=client_secret="" \
  --from-literal=crypto_secret="<openssl rand -base64 32>"
```

```bash
helm install keycloak-auth helm/keycloak-wasm-auth \
  --namespace istio-system \
  --set existingSecret=my-keycloak-secret \
  --set keycloak.host=keycloak.example.com \
  --set keycloak.realm=main \
  --set oidc.clientId=istio-gateway \
  --set oidc.redirectUri=https://app.example.com/oauth2/callback \
  --set cookie.domain=.example.com
```

## 5. Проверка установки

```bash
# Проверить что WasmPlugin создан
kubectl get wasmplugin -n istio-system

# Посмотреть логи gateway для отладки
kubectl logs -n istio-system -l istio=ingressgateway -c istio-proxy --tail=50 | grep -i wasm

# Тест: запрос без сессии должен редиректить в Keycloak
curl -v https://app.example.com/ 2>&1 | grep -E "Location:|< HTTP"
# Ожидаем: HTTP/2 302, Location: https://keycloak.example.com/realms/.../auth?code_challenge=...
```

## 6. Эндпоинты плагина

| Путь | Описание |
|------|----------|
| `/oauth2/callback` | Обработчик callback от Keycloak (не проксировать на бэкенд) |
| `/oauth2/start?rd=/some/path` | Принудительный старт OIDC flow с редиректом |
| `/oauth2/logout` | Очистка сессии + редирект в Keycloak logout |

## 7. Заголовки для бэкенда

После успешной аутентификации бэкенд получает:

| Заголовок | Значение | Настройка |
|-----------|----------|-----------|
| `x-user` | `preferred_username` из токена | `headers.user` |
| `x-email` | email пользователя | `headers.email` |
| `x-groups` | группы через запятую | `headers.groups` |

Для проброса `Authorization: Bearer <access_token>` в бэкенд: `headers.passAuthorization: true`.

## 8. Переключение на приватный registry (Harbor)

```bash
# Создать ImagePullSecret
kubectl create secret docker-registry harbor-creds \
  --namespace istio-system \
  --docker-server=harbor.example.com \
  --docker-username=robot\$my-robot \
  --docker-password="..."

helm upgrade keycloak-auth helm/keycloak-wasm-auth \
  --namespace istio-system \
  --reuse-values \
  --set image.registry=harbor.example.com \
  --set image.repository=my-project/istio-keycloak-wasm-plugin \
  --set image.pullSecret=harbor-creds
```

## 9. Публикация новой версии

```bash
# Создать тег — GitHub Actions автоматически соберёт и запушит образ
git tag v0.3.1
git push origin v0.3.1

# Обновить чарт после публикации образа
helm upgrade keycloak-auth helm/keycloak-wasm-auth \
  --namespace istio-system \
  --reuse-values \
  --set image.tag=0.3.1
```
