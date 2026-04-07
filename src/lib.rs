use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::{Deserialize, Serialize};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;
use url::form_urlencoded;

type HmacSha256 = Hmac<Sha256>;

const SESSION_COOKIE: &str = "mesh_session";
const REDIRECT_COOKIE: &str = "mesh_rd";
const CSRF_COOKIE: &str = "mesh_csrf";
const CALLBACK_PATH: &str = "/oauth2/callback";
const START_PATH: &str = "/oauth2/start";
const LOGOUT_PATH: &str = "/oauth2/logout";
const JWKS_CACHE_TTL_SEC: u64 = 120;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| Box::new(AuthRoot::default()));
}}

#[derive(Debug, Clone, Deserialize, Default)]
struct PluginConfig {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    logout_endpoint: Option<String>,

    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scope: Option<String>,

    cookie_domain: Option<String>,
    cookie_path: Option<String>,
    cookie_secure: Option<bool>,
    cookie_samesite: Option<String>,

    crypto_secret: String,
    upstream_cluster: String,

    refresh_skew_seconds: Option<u64>,
    pass_authorization_header: Option<bool>,

    user_header: Option<String>,
    email_header: Option<String>,
    groups_header: Option<String>,

    public_prefixes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Session {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: Option<String>,
    expires_at_epoch_sec: u64,
    sub: Option<String>,
    email: Option<String>,
    preferred_username: Option<String>,
    groups: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingState {
    rd: String,
    ts: u64,
    code_verifier: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct JwtHeader {
    alg: Option<String>,
    kid: Option<String>,
    typ: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct JwtClaims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<serde_json::Value>,
    email: Option<String>,
    preferred_username: Option<String>,
    groups: Option<Vec<String>>,
    exp: Option<u64>,
    nbf: Option<u64>,
    iat: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct Jwk {
    kty: Option<String>,
    kid: Option<String>,
    use_: Option<String>,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
    x5c: Option<Vec<String>>,
}

#[derive(Default)]
struct AuthRoot {
    cfg: Option<PluginConfig>,
    jwks_cache_loaded_at: u64,
    jwks_refresh_in_flight: bool,
}

struct AuthHttp {
    cfg: PluginConfig,
    pending_redirect: Option<String>,
    pending_flow: Option<PendingFlow>,
}

#[derive(Debug, Clone)]
enum PendingFlow {
    ExchangeCode {
        rd: String,
        code: String,
        code_verifier: String,
    },
    Refresh {
        rd: String,
        session: Session,
    },
}

impl Context for AuthRoot {
    fn on_http_call_response(&mut self, _: u32, _: usize, body_size: usize, _: usize) {
        let status = self
            .get_http_call_response_header(":status")
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(500);

        let body = self
            .get_http_call_response_body(0, body_size)
            .unwrap_or_default();

        self.jwks_refresh_in_flight = false;

        if status / 100 != 2 {
            proxy_wasm::hostcalls::log(
                LogLevel::Warn,
                &format!("jwks refresh failed with status {status}"),
            )
            .ok();
            return;
        }

        match std::str::from_utf8(&body) {
            Ok(s) => {
                if self
                    .set_shared_data("jwks_cache", Some(s.as_bytes()), None)
                    .is_ok()
                {
                    self.jwks_cache_loaded_at = now_epoch_sec();
                    proxy_wasm::hostcalls::log(LogLevel::Info, "jwks cache updated").ok();
                } else {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Warn,
                        "jwks shared_data write failed",
                    )
                    .ok();
                }
            }
            Err(e) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Warn,
                    &format!("jwks body invalid utf8: {e}"),
                )
                .ok();
            }
        }
    }
}

impl RootContext for AuthRoot {
    fn on_configure(&mut self, _: usize) -> bool {
        let Some(raw) = self.get_plugin_configuration() else {
            proxy_wasm::hostcalls::log(LogLevel::Error, "missing plugin config").ok();
            return false;
        };

        match serde_json::from_slice::<PluginConfig>(&raw) {
            Ok(mut cfg) => {
                if cfg.scope.is_none() {
                    cfg.scope = Some("openid profile email offline_access".to_string());
                }
                if cfg.cookie_path.is_none() {
                    cfg.cookie_path = Some("/".to_string());
                }
                if cfg.cookie_secure.is_none() {
                    cfg.cookie_secure = Some(true);
                }
                if cfg.cookie_samesite.is_none() {
                    cfg.cookie_samesite = Some("Lax".to_string());
                }
                if cfg.refresh_skew_seconds.is_none() {
                    cfg.refresh_skew_seconds = Some(60);
                }
                if cfg.public_prefixes.is_none() {
                    cfg.public_prefixes = Some(vec![
                        "/health".to_string(),
                        "/metrics".to_string(),
                        "/favicon.ico".to_string(),
                        "/assets/".to_string(),
                        "/public/".to_string(),
                    ]);
                }

                // Override sensitive fields from env vars if set via vmConfig.env
                if let Ok(v) = std::env::var("OIDC_CLIENT_SECRET") {
                    if !v.is_empty() {
                        cfg.client_secret = v;
                    }
                }
                if let Ok(v) = std::env::var("SESSION_CRYPTO_SECRET") {
                    if !v.is_empty() {
                        cfg.crypto_secret = v;
                    }
                }

                if cfg.client_secret.is_empty() {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Error,
                        "client_secret not set (pluginConfig or OIDC_CLIENT_SECRET env var)",
                    )
                    .ok();
                    return false;
                }
                if cfg.crypto_secret.is_empty() {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Error,
                        "crypto_secret not set (pluginConfig or SESSION_CRYPTO_SECRET env var)",
                    )
                    .ok();
                    return false;
                }

                self.cfg = Some(cfg);
                true
            }
            Err(e) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("bad plugin config: {e}"),
                )
                .ok();
                false
            }
        }
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        self.cfg.clone().map(|cfg| {
            Box::new(AuthHttp {
                cfg,
                pending_redirect: None,
                pending_flow: None,
            }) as Box<dyn HttpContext>
        })
    }

    fn on_tick(&mut self) {
        let Some(cfg) = self.cfg.clone() else {
            return;
        };

        let now = now_epoch_sec();
        let need_refresh = self.jwks_cache_loaded_at == 0
            || now.saturating_sub(self.jwks_cache_loaded_at) >= JWKS_CACHE_TTL_SEC;

        if !need_refresh || self.jwks_refresh_in_flight {
            return;
        }

        self.jwks_refresh_in_flight = true;

        let jwks_path = extract_path_and_query(&cfg.jwks_uri);
        let jwks_authority = extract_authority(&cfg.jwks_uri);
        let headers = vec![
            (":method", "GET"),
            (":path", jwks_path.as_str()),
            (":authority", jwks_authority.as_str()),
        ];

        match self.dispatch_http_call(
            &cfg.upstream_cluster,
            headers,
            None,
            vec![],
            Duration::from_secs(5),
        ) {
            Ok(_) => {}
            Err(e) => {
                self.jwks_refresh_in_flight = false;
                proxy_wasm::hostcalls::log(
                    LogLevel::Warn,
                    &format!("jwks dispatch failed: {e:?}"),
                )
                .ok();
            }
        }
    }

    fn on_vm_start(&mut self, _: usize) -> bool {
        self.set_tick_period(Duration::from_secs(120));
        true
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

impl Context for AuthHttp {
    fn on_http_call_response(&mut self, _: u32, _: usize, body_size: usize, _: usize) {
        let status = self
            .get_http_call_response_header(":status")
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(500);

        let body = self.get_http_call_response_body(0, body_size).unwrap_or_default();

        if status / 100 != 2 {
            self.send_http_response(
                401,
                vec![("content-type", "text/plain; charset=utf-8")],
                Some(format!("token endpoint returned {status}").as_bytes()),
            );
            return;
        }

        let token: TokenResponse = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                self.send_http_response(
                    500,
                    vec![("content-type", "text/plain; charset=utf-8")],
                    Some(format!("bad token response: {e}").as_bytes()),
                );
                return;
            }
        };

        let jwks = match self.get_jwks_cached() {
            Some(v) => v,
            None => {
                self.send_http_response(
                    503,
                    vec![("content-type", "text/plain; charset=utf-8")],
                    Some(b"jwks cache not ready"),
                );
                return;
            }
        };

        let token_for_identity = token
            .id_token
            .as_deref()
            .unwrap_or(token.access_token.as_str());

        let claims = match verify_jwt_minimal(
            token_for_identity,
            &jwks,
            &self.cfg.issuer,
            &self.cfg.client_id,
        ) {
            Ok(c) => c,
            Err(e) => {
                self.send_http_response(
                    401,
                    vec![("content-type", "text/plain; charset=utf-8")],
                    Some(format!("jwt verify failed: {e}").as_bytes()),
                );
                return;
            }
        };

        let session = Session {
            access_token: token.access_token.clone(),
            refresh_token: token.refresh_token.clone(),
            id_token: token.id_token.clone(),
            token_type: token.token_type.clone(),
            expires_at_epoch_sec: claims.exp.unwrap_or(now_epoch_sec() + token.expires_in.unwrap_or(300)),
            sub: claims.sub.clone(),
            email: claims.email.clone(),
            preferred_username: claims.preferred_username.clone(),
            groups: claims.groups.clone(),
        };

        let set_cookie_value = match encrypt_session_cookie(&session, &self.cfg.crypto_secret) {
            Ok(v) => v,
            Err(e) => {
                self.send_http_response(
                    500,
                    vec![("content-type", "text/plain; charset=utf-8")],
                    Some(format!("session cookie error: {e}").as_bytes()),
                );
                return;
            }
        };

        let set_cookie = build_cookie(
            SESSION_COOKIE,
            &set_cookie_value,
            &self.cfg,
            Some(session_ttl(&session)),
        );

        let location = self.pending_redirect.clone().unwrap_or_else(|| "/".into());

        self.send_http_response(
            302,
            vec![
                ("location", &location),
                ("set-cookie", &set_cookie),
                ("set-cookie", &clear_cookie(CSRF_COOKIE, &self.cfg)),
                ("set-cookie", &clear_cookie(REDIRECT_COOKIE, &self.cfg)),
                ("cache-control", "no-store"),
            ],
            None,
        );
    }
}

impl HttpContext for AuthHttp {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        let path = self
            .get_http_request_header(":path")
            .unwrap_or_else(|| "/".into());

        if path.starts_with(START_PATH) {
            let rd = get_query_param(&path, "rd").unwrap_or_else(|| "/".into());
            return self.redirect_to_login(&rd);
        }

        if path.starts_with(LOGOUT_PATH) {
            return self.handle_logout();
        }

        if path.starts_with(CALLBACK_PATH) {
            return self.handle_callback(&path);
        }

        if self.is_public_path(&path) {
            return Action::Continue;
        }

        let jwks = match self.get_jwks_cached() {
            Some(v) => v,
            None => {
                self.send_http_response(
                    503,
                    vec![("content-type", "text/plain; charset=utf-8")],
                    Some(b"jwks cache not ready"),
                );
                return Action::Pause;
            }
        };

        match self.read_cookie(SESSION_COOKIE) {
            Some(raw) => {
                let Ok(session) = decrypt_session_cookie(&raw, &self.cfg.crypto_secret) else {
                    return self.redirect_to_login(&path);
                };

                let token_to_verify = session
                    .id_token
                    .as_deref()
                    .unwrap_or(session.access_token.as_str());

                match verify_jwt_minimal(
                    token_to_verify,
                    &jwks,
                    &self.cfg.issuer,
                    &self.cfg.client_id,
                ) {
                    Ok(claims) => {
                        let now = now_epoch_sec();

                        if claims.exp.unwrap_or(0) <= now + self.cfg.refresh_skew_seconds.unwrap_or(60) {
                            if session.refresh_token.is_some() {
                                self.pending_redirect = Some(path.clone());
                                self.pending_flow = Some(PendingFlow::Refresh {
                                    rd: path.clone(),
                                    session,
                                });
                                self.refresh_token();
                                return Action::Pause;
                            } else {
                                return self.redirect_to_login(&path);
                            }
                        }

                        self.inject_identity_headers_from_claims(&session, &claims);
                        Action::Continue
                    }
                    Err(_) => self.redirect_to_login(&path),
                }
            }
            None => self.redirect_to_login(&path),
        }
    }

}

impl AuthHttp {
    fn is_public_path(&self, path: &str) -> bool {
        self.cfg
            .public_prefixes
            .as_ref()
            .map(|items| items.iter().any(|p| path.starts_with(p)))
            .unwrap_or(false)
    }

    fn get_jwks_cached(&self) -> Option<Jwks> {
        let (bytes_opt, _cas) = self.get_shared_data("jwks_cache");
        let bytes = bytes_opt?;
        serde_json::from_slice::<Jwks>(&bytes).ok()
    }

    fn redirect_to_login(&mut self, rd: &str) -> Action {
        let ts = now_epoch_sec();

        let state = PendingState {
            rd: rd.to_string(),
            ts,
            code_verifier: derive_code_verifier(&self.cfg.crypto_secret, rd, ts),
        };

        let state_raw = serde_json::to_vec(&state).unwrap();
        let state_token = sign_blob(&state_raw, &self.cfg.crypto_secret).unwrap();
        let csrf_value = derive_csrf(&self.cfg.crypto_secret, rd, ts);

        let redirect_cookie = build_cookie(
            REDIRECT_COOKIE,
            &urlencoding::encode(rd),
            &self.cfg,
            Some(300),
        );
        let csrf_cookie = build_cookie(CSRF_COOKIE, &csrf_value, &self.cfg, Some(300));

        let code_challenge = pkce_s256(&state.code_verifier);
        let scope = self.cfg.scope.as_deref().unwrap_or("openid profile email offline_access");

        let mut q = form_urlencoded::Serializer::new(String::new());
        q.append_pair("client_id", &self.cfg.client_id);
        q.append_pair("redirect_uri", &self.cfg.redirect_uri);
        q.append_pair("response_type", "code");
        q.append_pair("scope", scope);
        q.append_pair("state", &state_token);
        q.append_pair("code_challenge", &code_challenge);
        q.append_pair("code_challenge_method", "S256");

        let location = format!("{}?{}", self.cfg.authorization_endpoint, q.finish());

        self.send_http_response(
            302,
            vec![
                ("location", &location),
                ("set-cookie", &redirect_cookie),
                ("set-cookie", &csrf_cookie),
                ("cache-control", "no-store"),
            ],
            None,
        );
        Action::Pause
    }

    fn handle_callback(&mut self, path: &str) -> Action {
        let Some(code) = get_query_param(path, "code") else {
            self.send_http_response(401, vec![], Some(b"missing code"));
            return Action::Pause;
        };

        let Some(state_token) = get_query_param(path, "state") else {
            self.send_http_response(401, vec![], Some(b"missing state"));
            return Action::Pause;
        };

        let rd_cookie = self.read_cookie(REDIRECT_COOKIE).unwrap_or_else(|| "/".into());
        let csrf_cookie = self.read_cookie(CSRF_COOKIE).unwrap_or_default();

        let state_bytes = match verify_signed_blob(&state_token, &self.cfg.crypto_secret) {
            Ok(v) => v,
            Err(_) => {
                self.send_http_response(401, vec![], Some(b"bad state"));
                return Action::Pause;
            }
        };

        let pending: PendingState = match serde_json::from_slice(&state_bytes) {
            Ok(v) => v,
            Err(_) => {
                self.send_http_response(401, vec![], Some(b"bad state payload"));
                return Action::Pause;
            }
        };

        if now_epoch_sec().saturating_sub(pending.ts) > 300 {
            self.send_http_response(401, vec![], Some(b"state expired"));
            return Action::Pause;
        }

        let expected_csrf = derive_csrf(&self.cfg.crypto_secret, &pending.rd, pending.ts);
        if expected_csrf != csrf_cookie {
            self.send_http_response(401, vec![], Some(b"csrf mismatch"));
            return Action::Pause;
        }

        self.pending_redirect = Some(
            urlencoding::decode(&rd_cookie)
                .map(|x| x.to_string())
                .unwrap_or_else(|_| "/".into()),
        );

        self.pending_flow = Some(PendingFlow::ExchangeCode {
            rd: pending.rd,
            code,
            code_verifier: pending.code_verifier,
        });

        self.exchange_code();
        Action::Pause
    }

    fn handle_logout(&mut self) -> Action {
        let clear_session = clear_cookie(SESSION_COOKIE, &self.cfg);
        let clear_redirect = clear_cookie(REDIRECT_COOKIE, &self.cfg);
        let clear_csrf = clear_cookie(CSRF_COOKIE, &self.cfg);

        let location = self
            .cfg
            .logout_endpoint
            .clone()
            .unwrap_or_else(|| "/".into());

        self.send_http_response(
            302,
            vec![
                ("location", &location),
                ("set-cookie", &clear_session),
                ("set-cookie", &clear_redirect),
                ("set-cookie", &clear_csrf),
            ],
            None,
        );
        Action::Pause
    }

    fn exchange_code(&mut self) {
        let Some(PendingFlow::ExchangeCode {
            code,
            code_verifier,
            ..
        }) = self.pending_flow.clone() else {
            self.send_http_response(500, vec![], Some(b"missing exchange context"));
            return;
        };

        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", &code)
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("client_secret", &self.cfg.client_secret)
            .append_pair("redirect_uri", &self.cfg.redirect_uri)
            .append_pair("code_verifier", &code_verifier)
            .finish();

        self.dispatch_token_request(&body);
    }

    fn refresh_token(&mut self) {
        let Some(PendingFlow::Refresh { session, .. }) = self.pending_flow.clone() else {
            self.send_http_response(500, vec![], Some(b"missing refresh context"));
            return;
        };

        let Some(refresh_token) = session.refresh_token else {
            self.send_http_response(401, vec![], Some(b"missing refresh token"));
            return;
        };

        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", &refresh_token)
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("client_secret", &self.cfg.client_secret)
            .finish();

        self.dispatch_token_request(&body);
    }

    fn dispatch_token_request(&mut self, body: &str) {
        let token_path = extract_path_and_query(&self.cfg.token_endpoint);
        let token_authority = extract_authority(&self.cfg.token_endpoint);
        let headers = vec![
            (":method", "POST"),
            (":path", token_path.as_str()),
            (":authority", token_authority.as_str()),
            ("content-type", "application/x-www-form-urlencoded"),
        ];

        if self
            .dispatch_http_call(
                &self.cfg.upstream_cluster,
                headers,
                Some(body.as_bytes()),
                vec![],
                Duration::from_secs(10),
            )
            .is_err()
        {
            self.send_http_response(500, vec![], Some(b"dispatch_http_call failed"));
        }
    }

    fn inject_identity_headers_from_claims(&self, session: &Session, claims: &JwtClaims) {
        let user_header = self.cfg.user_header.as_deref().unwrap_or("x-user");
        let email_header = self.cfg.email_header.as_deref().unwrap_or("x-email");
        let groups_header = self.cfg.groups_header.as_deref().unwrap_or("x-groups");

        if let Some(v) = claims
            .preferred_username
            .as_deref()
            .or(claims.sub.as_deref())
            .or(session.preferred_username.as_deref())
            .or(session.sub.as_deref())
        {
            self.set_http_request_header(user_header, Some(v));
        }

        if let Some(v) = claims.email.as_deref().or(session.email.as_deref()) {
            self.set_http_request_header(email_header, Some(v));
        }

        if let Some(v) = claims.groups.as_ref().or(session.groups.as_ref()) {
            self.set_http_request_header(groups_header, Some(&v.join(",")));
        }

        if self.cfg.pass_authorization_header.unwrap_or(false) {
            self.set_http_request_header(
                "authorization",
                Some(&format!("Bearer {}", session.access_token)),
            );
        }
    }

    fn read_cookie(&self, name: &str) -> Option<String> {
        let raw = self.get_http_request_header("cookie")?;
        parse_cookie(&raw, name)
    }
}

fn parse_cookie(header: &str, name: &str) -> Option<String> {
    for part in header.split(';') {
        let part = part.trim();
        let prefix = format!("{name}=");
        if let Some(v) = part.strip_prefix(&prefix) {
            return Some(v.to_string());
        }
    }
    None
}

fn build_cookie(name: &str, value: &str, cfg: &PluginConfig, max_age: Option<u64>) -> String {
    let mut attrs = vec![
        format!("{name}={value}"),
        format!("Path={}", cfg.cookie_path.as_deref().unwrap_or("/")),
        "HttpOnly".to_string(),
        format!(
            "SameSite={}",
            cfg.cookie_samesite.as_deref().unwrap_or("Lax")
        ),
    ];

    if let Some(age) = max_age {
        attrs.push(format!("Max-Age={age}"));
    }
    if cfg.cookie_secure.unwrap_or(true) {
        attrs.push("Secure".to_string());
    }
    if let Some(domain) = &cfg.cookie_domain {
        attrs.push(format!("Domain={domain}"));
    }

    attrs.join("; ")
}

fn clear_cookie(name: &str, cfg: &PluginConfig) -> String {
    let mut attrs = vec![
        format!("{name}=deleted"),
        "Expires=Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
        format!("Path={}", cfg.cookie_path.as_deref().unwrap_or("/")),
        "HttpOnly".to_string(),
        format!(
            "SameSite={}",
            cfg.cookie_samesite.as_deref().unwrap_or("Lax")
        ),
    ];

    if cfg.cookie_secure.unwrap_or(true) {
        attrs.push("Secure".to_string());
    }
    if let Some(domain) = &cfg.cookie_domain {
        attrs.push(format!("Domain={domain}"));
    }

    attrs.join("; ")
}

fn session_ttl(session: &Session) -> u64 {
    session
        .expires_at_epoch_sec
        .saturating_sub(now_epoch_sec())
        .max(60)
}

fn derive_material(secret: &str, info: &str, len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, secret.as_bytes());
    let mut out = vec![0u8; len];
    hk.expand(info.as_bytes(), &mut out).unwrap();
    out
}

fn derive_csrf(secret: &str, rd: &str, ts: u64) -> String {
    let input = format!("csrf|{rd}|{ts}");
    hex::encode(derive_material(secret, &input, 16))
}

fn derive_code_verifier(secret: &str, rd: &str, ts: u64) -> String {
    let input = format!("pkce|{rd}|{ts}");
    let raw = derive_material(secret, &input, 32);
    URL_SAFE_NO_PAD.encode(raw)
}

fn pkce_s256(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

fn sign_blob(payload: &[u8], secret: &str) -> Result<String, String> {
    let body = URL_SAFE_NO_PAD.encode(payload);
    let mut mac: HmacSha256 = Mac::new_from_slice(secret.as_bytes()).map_err(|e: hmac::digest::InvalidLength| e.to_string())?;
    mac.update(body.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{body}.{sig}"))
}

fn verify_signed_blob(value: &str, secret: &str) -> Result<Vec<u8>, String> {
    let (body, sig) = value.rsplit_once('.').ok_or("bad format")?;
    let mut mac: HmacSha256 = Mac::new_from_slice(secret.as_bytes()).map_err(|e: hmac::digest::InvalidLength| e.to_string())?;
    mac.update(body.as_bytes());
    let expected = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    if expected != sig {
        return Err("bad sig".into());
    }
    URL_SAFE_NO_PAD.decode(body).map_err(|e| e.to_string())
}

fn encrypt_session_cookie(session: &Session, secret: &str) -> Result<String, String> {
    let plaintext = serde_json::to_vec(session).map_err(|e| e.to_string())?;
    let key = derive_material(secret, "session-key", 32);

    let nonce_seed = format!(
        "nonce|{}|{}",
        session.expires_at_epoch_sec,
        session.sub.as_deref().unwrap_or("anonymous")
    );
    let nonce_raw = derive_material(secret, &nonce_seed, 12);

    let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|e| format!("{e:?}"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_raw), plaintext.as_ref())
        .map_err(|e| format!("{e:?}"))?;

    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(nonce_raw),
        URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

fn decrypt_session_cookie(raw: &str, secret: &str) -> Result<Session, String> {
    let (nonce_b64, ct_b64) = raw.rsplit_once('.').ok_or("bad cookie format")?;
    let nonce_raw = URL_SAFE_NO_PAD.decode(nonce_b64).map_err(|e| e.to_string())?;
    let ciphertext = URL_SAFE_NO_PAD.decode(ct_b64).map_err(|e| e.to_string())?;
    let key = derive_material(secret, "session-key", 32);
    let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|e| format!("{e:?}"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_raw), ciphertext.as_ref())
        .map_err(|e| format!("{e:?}"))?;
    serde_json::from_slice(&plaintext).map_err(|e| e.to_string())
}

fn decode_jwt_header(jwt: &str) -> Result<JwtHeader, String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("jwt must have 3 parts".into());
    }
    let bytes = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|e| e.to_string())?;
    serde_json::from_slice::<JwtHeader>(&bytes).map_err(|e| e.to_string())
}

fn decode_jwt_claims(jwt: &str) -> Result<JwtClaims, String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("jwt must have 3 parts".into());
    }
    let bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|e| e.to_string())?;
    serde_json::from_slice::<JwtClaims>(&bytes).map_err(|e| e.to_string())
}

fn verify_rsa_pkcs1_sha256(
    n_b64: &str,
    e_b64: &str,
    signing_input: &[u8],
    signature_b64: &str,
) -> Result<(), String> {
    let n_bytes = URL_SAFE_NO_PAD
        .decode(n_b64)
        .map_err(|e| format!("n decode: {e}"))?;
    let e_bytes = URL_SAFE_NO_PAD
        .decode(e_b64)
        .map_err(|e| format!("e decode: {e}"))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| format!("sig decode: {e}"))?;

    let em_len = n_bytes.len();

    if sig_bytes.len() != em_len {
        return Err(format!(
            "signature length {} != modulus length {}",
            sig_bytes.len(),
            em_len
        ));
    }

    let n = BigUint::from_bytes_be(&n_bytes);
    let e = BigUint::from_bytes_be(&e_bytes);
    let sig = BigUint::from_bytes_be(&sig_bytes);

    // RSA public key operation: m = sig^e mod n
    let m = sig.modpow(&e, &n);
    let m_bytes = m.to_bytes_be();

    // Left-pad to em_len
    let mut em = vec![0u8; em_len];
    let offset = em_len.saturating_sub(m_bytes.len());
    em[offset..].copy_from_slice(&m_bytes);

    // Verify PKCS#1 v1.5: 0x00 0x01 [0xff * N] 0x00 [DigestInfo] [hash]
    if em.len() < 2 || em[0] != 0x00 || em[1] != 0x01 {
        return Err("pkcs1: bad header".into());
    }

    // DigestInfo prefix for SHA-256 (RFC 3447)
    const SHA256_DIGEST_INFO: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
        0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    ];

    let hash = Sha256::digest(signing_input);
    let mut expected_tail = SHA256_DIGEST_INFO.to_vec();
    expected_tail.extend_from_slice(hash.as_slice());
    // expected_tail.len() == 19 + 32 == 51

    let suffix_len = expected_tail.len();
    if em_len < suffix_len + 3 {
        return Err("pkcs1: em too short".into());
    }
    let tail_start = em_len - suffix_len;

    if &em[tail_start..] != expected_tail.as_slice() {
        return Err("pkcs1: digest mismatch".into());
    }

    // Separator byte before tail
    if em[tail_start - 1] != 0x00 {
        return Err("pkcs1: missing separator".into());
    }

    // All padding bytes must be 0xff (minimum 8 per RFC 3447)
    let pad = &em[2..tail_start - 1];
    if pad.len() < 8 || pad.iter().any(|&b| b != 0xff) {
        return Err("pkcs1: bad padding".into());
    }

    Ok(())
}

fn verify_jwt_minimal(jwt: &str, jwks: &Jwks, issuer: &str, client_id: &str) -> Result<JwtClaims, String> {
    let header = decode_jwt_header(jwt)?;
    let claims = decode_jwt_claims(jwt)?;

    let alg = header.alg.as_deref().unwrap_or("");
    if alg != "RS256" {
        return Err(format!("unsupported algorithm: {alg}"));
    }

    let kid = header.kid.as_deref().ok_or("missing kid")?;
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid.as_deref() == Some(kid))
        .ok_or_else(|| format!("kid {kid} not found in jwks"))?;

    let n = jwk.n.as_deref().ok_or("jwk missing n")?;
    let e = jwk.e.as_deref().ok_or("jwk missing e")?;

    // signing input = "header_b64.payload_b64" (everything before the last dot)
    let last_dot = jwt.rfind('.').ok_or("jwt malformed")?;
    let signing_input = &jwt[..last_dot];
    let sig_b64 = &jwt[last_dot + 1..];

    verify_rsa_pkcs1_sha256(n, e, signing_input.as_bytes(), sig_b64)?;

    if claims.iss.as_deref() != Some(issuer) {
        return Err(format!("issuer mismatch: {:?}", claims.iss));
    }

    if !aud_matches(claims.aud.as_ref(), client_id) {
        return Err("aud mismatch".into());
    }

    let now = now_epoch_sec();
    if claims.exp.unwrap_or(0) <= now {
        return Err("token expired".into());
    }

    if let Some(nbf) = claims.nbf {
        if now < nbf {
            return Err("token not yet valid".into());
        }
    }

    Ok(claims)
}

fn aud_matches(aud: Option<&serde_json::Value>, client_id: &str) -> bool {
    match aud {
        Some(serde_json::Value::String(s)) => s == client_id,
        Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(client_id)),
        _ => false,
    }
}

fn get_query_param(path: &str, name: &str) -> Option<String> {
    let idx = path.find('?')?;
    let query = &path[idx + 1..];
    let params: HashMap<String, String> =
        form_urlencoded::parse(query.as_bytes()).into_owned().collect();
    params.get(name).cloned()
}

fn extract_authority(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| {
                if let Some(port) = u.port() {
                    format!("{h}:{port}")
                } else {
                    h.to_string()
                }
            })
        })
        .unwrap_or_default()
}

fn extract_path_and_query(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => {
            let mut out = u.path().to_string();
            if let Some(q) = u.query() {
                out.push('?');
                out.push_str(q);
            }
            out
        }
        Err(_) => "/".into(),
    }
}

fn now_epoch_sec() -> u64 {
    if let Ok(Some(v)) = proxy_wasm::hostcalls::get_property(vec!["request", "time"]) {
        if v.len() >= 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&v[..8]);
            return u64::from_le_bytes(bytes) / 1_000_000_000;
        }
    }
    0
}