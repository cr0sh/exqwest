use std::{
    cell::Cell, collections::HashMap, env::var, fmt::Debug, future::Future, num::ParseIntError,
    pin::Pin, sync::OnceLock,
};

use async_trait::async_trait;
use base64::Engine;
use hmac::{digest::Digest, Hmac, Mac};
use jwt::SignWithKey;
use reqwest::{header::AUTHORIZATION, Client, IntoUrl, Method, Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Sha256, Sha512};
use thiserror::Error;
use tracing::error;
use uuid::Uuid;

static CREDENTIALS: OnceLock<HashMap<&'static str, Credential>> = OnceLock::new();
static OKX_CREDENTIAL: OnceLock<OkxCredential> = OnceLock::new();

struct Credential {
    key: String,
    secret: String,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("key", &self.key)
            .field("secret", &"<censored>")
            .finish()
    }
}

struct OkxCredential {
    key: String,
    secret: String,
    passphrase: String,
}

impl Debug for OkxCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OkxCredential")
            .field("key", &self.key)
            .field("secret", &"<censored>")
            .field("passphrase", &"<censored>")
            .finish()
    }
}

pub fn initialize_credentials() {
    const EXCHANGES: [&str; 6] = ["BINANCE", "BITHUMB", "BYBIT", "GATEIO", "OKX", "UPBIT"];

    let mut creds = HashMap::new();

    for exchange in EXCHANGES {
        if exchange == "OKX" {
            let cred = (
                var(format!("{exchange}_API_KEY")),
                var(format!("{exchange}_API_SECRET")),
                var(format!("{exchange}_API_PASSPHRASE")),
            );
            if let (Ok(key), Ok(secret), Ok(passphrase)) = cred {
                OKX_CREDENTIAL
                    .set(OkxCredential {
                        key,
                        secret,
                        passphrase,
                    })
                    .expect("OKX credential already set");
            }
        } else {
            let cred = var(format!("{exchange}_API_KEY"))
                .and_then(|x| var(format!("{exchange}_API_SECRET")).map(|y| (x, y)));
            if let Ok(cred) = cred {
                creds.insert(
                    exchange,
                    Credential {
                        key: cred.0,
                        secret: cred.1,
                    },
                );
            }
        }
    }

    CREDENTIALS.set(creds).expect("credentials already set");
}

#[async_trait]
pub trait ClientExt {
    async fn get_public(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> reqwest::Result<serde_json::Value>;
    async fn post_public(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> reqwest::Result<serde_json::Value>;
    async fn put_public(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> reqwest::Result<serde_json::Value>;
    async fn delete_public(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> reqwest::Result<serde_json::Value>;
    async fn patch_public(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> reqwest::Result<serde_json::Value>;
    async fn get_private(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> Result<serde_json::Value, Error>;
    async fn post_private(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> Result<serde_json::Value, Error>;
    async fn put_private(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> Result<serde_json::Value, Error>;
    async fn delete_private(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> Result<serde_json::Value, Error>;
    async fn patch_private(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> Result<serde_json::Value, Error>;
}

macro_rules! request {
    (@public $this:expr, $method:ident, $url:ident, $query:ident, $payload:ident) => {
        $this
            .$method($url)
            .body($payload)
            .query(&$query)
            .send()
            .await?
            .json()
            .await
    };

    (@private $this:expr, $method:ident, $url:ident, $query:ident, $payload:ident) => {{
        let (client, req) = $this
            .$method($url)
            .query(&$query)
            .body($payload)
            .build_split();
        let mut req = req?;
        if let Err(e) = sign_request(&mut req) {
            let error = Box::new(e) as Box<dyn std::error::Error + Send + Sync + 'static>;
            error!(error, "cannot sign request");
            panic!("cannot sign request: {error}");
        }
        client.execute(req).await?.json().await.map_err(Into::into)
    }};
}

#[async_trait]
impl ClientExt for Client {
    async fn get_public(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> reqwest::Result<serde_json::Value> {
        request!(@public self, get, url, query, payload)
    }
    async fn post_public(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> reqwest::Result<serde_json::Value> {
        request!(@public self, post, url, query, payload)
    }
    async fn put_public(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> reqwest::Result<serde_json::Value> {
        request!(@public self, put, url, query, payload)
    }
    async fn delete_public(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> reqwest::Result<serde_json::Value> {
        request!(@public self, delete, url, query, payload)
    }
    async fn patch_public(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> reqwest::Result<serde_json::Value> {
        request!(@public self, patch, url, query, payload)
    }
    async fn get_private(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> Result<serde_json::Value, Error> {
        request!(@private self, get, url, query, payload)
    }
    async fn post_private(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> Result<serde_json::Value, Error> {
        request!(@private self, post, url, query, payload)
    }
    async fn put_private(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> Result<serde_json::Value, Error> {
        request!(@private self, put, url, query, payload)
    }
    async fn delete_private(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> Result<serde_json::Value, Error> {
        request!(@private self, delete, url, query, payload)
    }
    async fn patch_private(
        &self,
        url: impl IntoUrl + Send,
        query: impl Serialize + Send + Sync,
        payload: String,
    ) -> Result<serde_json::Value, Error> {
        request!(@private self, patch, url, query, payload)
    }
}

pub struct Clients {
    index: Cell<usize>,
    clients: Vec<Client>,
}

impl Clients {
    pub fn new(clients: impl Iterator<Item = Client>) -> Self {
        Self {
            index: Cell::new(0),
            clients: clients.collect(),
        }
    }

    pub fn get_client(&self) -> &Client {
        let client = &self.clients[self.index.get()];
        self.index.set((self.index.get() + 1) % self.clients.len());
        client
    }

    pub fn clients(&self) -> &[Client] {
        &self.clients
    }
}

impl ClientExt for Clients {
    fn get_public<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: String,
    ) -> Pin<Box<dyn Future<Output = reqwest::Result<serde_json::Value>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().get_public(url, query, payload)
    }

    fn post_public<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: String,
    ) -> Pin<Box<dyn Future<Output = reqwest::Result<serde_json::Value>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().post_public(url, query, payload)
    }

    fn put_public<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: String,
    ) -> Pin<Box<dyn Future<Output = reqwest::Result<serde_json::Value>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().put_public(url, query, payload)
    }

    fn delete_public<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: String,
    ) -> Pin<Box<dyn Future<Output = reqwest::Result<serde_json::Value>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().delete_public(url, query, payload)
    }

    fn patch_public<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: String,
    ) -> Pin<Box<dyn Future<Output = reqwest::Result<serde_json::Value>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().patch_public(url, query, payload)
    }

    fn get_private<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: String,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().get_private(url, query, payload)
    }

    fn post_private<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: String,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().post_private(url, query, payload)
    }

    fn put_private<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: String,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().put_private(url, query, payload)
    }

    fn delete_private<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: String,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().delete_private(url, query, payload)
    }

    fn patch_private<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: String,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().patch_private(url, query, payload)
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error("signing mechanism not implemented")]
    NotImplemented,
}

fn sign_request(req: &mut Request) -> Result<(), Error> {
    match req.url().host_str().expect("no host for request URL") {
        "api.binance.com" | "fapi.binance.com" => sign_binance(req),
        "api.bithumb.com" => sign_bithumb(req),
        "api.bybit.com" => sign_bybit(req),
        "api.gateio.ws" => sign_gateio(req),
        "aws.okx.com" | "www.okx.com" => sign_okx(req),
        "api.upbit.com" => sign_upbit(req),
        _ => Err(Error::NotImplemented),
    }
}

fn timestamp_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before the Unix epoch")
        .as_millis()
}

trait OptionBodyExt<'a> {
    fn into_str(self) -> &'a str;
}

impl<'a> OptionBodyExt<'a> for Option<&'a reqwest::Body> {
    fn into_str(self) -> &'a str {
        self.map(|x| {
            std::str::from_utf8(x.as_bytes().unwrap_or_default()).expect("non-utf-8 request body")
        })
        .unwrap_or_default()
    }
}

fn sign_bithumb(req: &mut Request) -> Result<(), Error> {
    let credential = CREDENTIALS
        .get()
        .expect("credentials not loaded")
        .get("BITHUMB")
        .expect("no credential for Bithumb");
    let nonce = timestamp_millis();
    let endpoint = req.url().path();
    let query_string = req.body().into_str().replace('/', "%2F");
    let encode_target = format!("{}\x00{}\x00{}", endpoint, query_string, nonce);

    let mut mac = Hmac::<Sha512>::new_from_slice(credential.secret.as_bytes())
        .expect("cannot initialize HMAC");
    mac.update(encode_target.as_bytes());
    let encrypted = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<String>();

    let base64 = base64::engine::general_purpose::STANDARD.encode(encrypted);

    req.headers_mut()
        .insert("Api-Key", credential.key.parse().unwrap());
    req.headers_mut()
        .insert("Api-Nonce", nonce.to_string().parse().unwrap());
    req.headers_mut()
        .insert("Api-Sign", base64.parse().unwrap());

    Ok(())
}

fn sign_bybit(req: &mut Request) -> Result<(), Error> {
    const RECV_WINDOW: u32 = 5000;

    let credential = CREDENTIALS
        .get()
        .expect("credentials not loaded")
        .get("BYBIT")
        .expect("no credential for Bybit");

    let url = req.url();
    let timestamp = timestamp_millis();

    let param_str = match req.method() {
        &Method::GET => {
            let query_string = url.query().unwrap_or("");
            format!("{timestamp}{}{RECV_WINDOW}{query_string}", credential.key)
        }
        &Method::POST => {
            format!(
                "{timestamp}{}{RECV_WINDOW}{}",
                credential.key,
                req.body().into_str()
            )
        }
        other => panic!("unsupported method {other}"),
    };

    let mut mac = Hmac::<Sha256>::new_from_slice(credential.secret.as_bytes())
        .expect("cannot initialize HMAC");
    mac.update(param_str.as_bytes());
    let encrypted = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<String>();

    req.headers_mut()
        .insert("X-BAPI-API-KEY", credential.key.parse().unwrap());
    req.headers_mut()
        .insert("X-BAPI-TIMESTAMP", timestamp.to_string().parse().unwrap());
    req.headers_mut()
        .insert("X-BAPI-SIGN", encrypted.parse().unwrap());
    req.headers_mut().insert(
        "X-BAPI-RECV-WINDOW",
        RECV_WINDOW.to_string().parse().unwrap(),
    );

    Ok(())
}

fn sign_binance(req: &mut Request) -> Result<(), Error> {
    const RECV_WINDOW: u32 = 3000;

    let credential = CREDENTIALS
        .get()
        .expect("credentials not loaded")
        .get("BINANCE")
        .expect("no credential for Binance");

    let timestamp = timestamp_millis();

    req.url_mut()
        .query_pairs_mut()
        .append_pair("recvWindow", &RECV_WINDOW.to_string())
        .append_pair("timestamp", &timestamp.to_string());

    let mut mac = Hmac::<Sha256>::new_from_slice(credential.secret.as_bytes())
        .expect("cannot intialize HMAC");
    mac.update(req.url().query().unwrap_or_default().as_bytes());
    let encrypted = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<String>();

    req.url_mut()
        .query_pairs_mut()
        .append_pair("signature", &encrypted);
    req.headers_mut()
        .insert("X-MBX-APIKEY", credential.key.parse().unwrap());

    Ok(())
}

fn sign_gateio(req: &mut Request) -> Result<(), Error> {
    let credential = CREDENTIALS
        .get()
        .expect("credentials not loaded")
        .get("GATEIO")
        .expect("no credential for Gate.io");

    let now = timestamp_millis() / 1000;

    let mut payload_hasher = Sha512::new();
    payload_hasher.update(req.body().into_str());
    let payload_hash = payload_hasher
        .finalize()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<String>();

    let hmac_payload = format!(
        "{}\n{}\n{}\n{}\n{}",
        req.method(),
        req.url().path(),
        req.url().query().unwrap_or_default(),
        payload_hash,
        now
    );
    let mut mac = Hmac::<Sha512>::new_from_slice(credential.secret.as_bytes())
        .expect("cannot initialize HMAC");
    mac.update(hmac_payload.as_bytes());
    let encrypted = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<String>();

    req.headers_mut()
        .insert("KEY", credential.key.parse().unwrap());
    req.headers_mut()
        .insert("Timestamp", now.to_string().parse().unwrap());
    req.headers_mut().insert("Sign", encrypted.parse().unwrap());

    Ok(())
}

fn sign_okx(req: &mut Request) -> Result<(), Error> {
    const RECV_WINDOW: u32 = 3000;

    let credential = OKX_CREDENTIAL.get().expect("no credential for OKX");

    let now = chrono::Utc::now();
    let timestamp = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let hmac_payload = timestamp.clone()
        + req.method().as_ref()
        + {
            &(req.url().path().to_string()
                + &(if let Some(q) = req.url().query() {
                    format!("?{q}")
                } else {
                    String::new()
                }))
        }
        + req.body().into_str();
    let mut mac = Hmac::<Sha256>::new_from_slice(credential.secret.as_bytes())
        .expect("cannot initialize HMAC");
    mac.update(hmac_payload.as_bytes());
    let encrypted = mac.finalize().into_bytes();
    let encoded = base64::engine::general_purpose::STANDARD.encode(encrypted);

    let exp_time = now.timestamp_millis() + RECV_WINDOW as i64;

    req.headers_mut()
        .insert("OK-ACCESS-KEY", credential.key.parse().unwrap());
    req.headers_mut()
        .insert("OK-ACCESS-SIGN", encoded.parse().unwrap());
    req.headers_mut()
        .insert("OK-ACCESS-TIMESTAMP", timestamp.parse().unwrap());
    req.headers_mut().insert(
        "OK-ACCESS-PASSPHRASE",
        credential.passphrase.parse().unwrap(),
    );
    req.headers_mut()
        .insert("expTime", exp_time.to_string().parse().unwrap());

    Ok(())
}

fn sign_upbit(req: &mut Request) -> Result<(), Error> {
    let credential = CREDENTIALS
        .get()
        .expect("credentials not loaded")
        .get("UPBIT")
        .expect("no credential for UPbit");

    let auth = if req.url().query().is_none() {
        #[derive(Serialize)]
        struct JwtPayload {
            access_key: String,
            nonce: String,
        }

        let jwt_payload = JwtPayload {
            access_key: credential.key.clone(),
            nonce: Uuid::new_v4().to_string(),
        };
        jwt_payload
            .sign_with_key(
                &Hmac::<Sha256>::new_from_slice(credential.secret.as_bytes())
                    .expect("cannot initialize HMAC"),
            )
            .expect("cannot sign payload")
    } else {
        #[derive(Serialize)]
        struct JwtPayload {
            access_key: String,
            nonce: String,
            query_hash: String,
            query_hash_alg: &'static str,
        }
        let mut hasher = Sha512::new();
        hasher.update(req.url().query().unwrap_or_default().as_bytes());
        let hash = hasher
            .finalize()
            .as_slice()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>();

        let jwt_payload = JwtPayload {
            access_key: credential.key.clone(),
            nonce: Uuid::new_v4().to_string(),
            query_hash: hash,
            query_hash_alg: "SHA512",
        };
        jwt_payload
            .sign_with_key(
                &Hmac::<Sha256>::new_from_slice(credential.secret.as_bytes())
                    .expect("cannot initialize HMAC"),
            )
            .expect("cannot sign payload")
    };

    req.headers_mut()
        .insert(AUTHORIZATION, format!("Bearer {auth}").parse().unwrap());

    Ok(())
}

#[macro_export]
macro_rules! serializable {
    (
    $key1:ident: $value1:expr
    $(,)?
    ) => {{
        #[derive(::serde::Serialize)]
        struct Serializable<T1> {
            $key1: T1,
        }

        Serializable { $key1: $value1 }
    }};
    (
    $key1:ident: $value1:expr
    ,$key2:ident: $value2:expr
    $(,)?
    ) => {{
        #[derive(::serde::Serialize)]
        struct Serializable<T1, T2> {
            $key1: T1,
            $key2: T2,
        }

        Serializable {
            $key1: $value1,
            $key2: $value2,
        }
    }};
    (
    $key1:ident: $value1:expr
    ,$key2:ident: $value2:expr
    ,$key3:ident: $value3:expr
    $(,)?
    ) => {{
        #[derive(::serde::Serialize)]
        struct Serializable<T1, T2, T3> {
            $key1: T1,
            $key2: T2,
            $key3: T3,
        }

        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
        }
    }};
    (
    $key1:ident: $value1:expr
    ,$key2:ident: $value2:expr
    ,$key3:ident: $value3:expr
    ,$key4:ident: $value4:expr
    $(,)?
    ) => {{
        #[derive(::serde::Serialize)]
        struct Serializable<T1, T2, T3, T4> {
            $key1: T1,
            $key2: T2,
            $key3: T3,
            $key4: T4,
        }

        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
        }
    }};
    (
    $key1:ident: $value1:expr
    ,$key2:ident: $value2:expr
    ,$key3:ident: $value3:expr
    ,$key4:ident: $value4:expr
    ,$key5:ident: $value5:expr
    $(,)?
    ) => {{
        #[derive(::serde::Serialize)]
        struct Serializable<T1, T2, T3, T4, T5> {
            $key1: T1,
            $key2: T2,
            $key3: T3,
            $key4: T4,
            $key5: T5,
        }

        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
        }
    }};
    (
    $key1:ident: $value1:expr
    ,$key2:ident: $value2:expr
    ,$key3:ident: $value3:expr
    ,$key4:ident: $value4:expr
    ,$key5:ident: $value5:expr
    ,$key6:ident: $value6:expr
    $(,)?
    ) => {{
        #[derive(::serde::Serialize)]
        struct Serializable<T1, T2, T3, T4, T5, T6> {
            $key1: T1,
            $key2: T2,
            $key3: T3,
            $key4: T4,
            $key5: T5,
            $key6: T6,
        }

        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
        }
    }};
    (
    $key1:ident: $value1:expr
    ,$key2:ident: $value2:expr
    ,$key3:ident: $value3:expr
    ,$key4:ident: $value4:expr
    ,$key5:ident: $value5:expr
    ,$key6:ident: $value6:expr
    ,$key7:ident: $value7:expr
    $(,)?
    ) => {{
        #[derive(::serde::Serialize)]
        struct Serializable<T1, T2, T3, T4, T5, T6, T7> {
            $key1: T1,
            $key2: T2,
            $key3: T3,
            $key4: T4,
            $key5: T5,
            $key6: T6,
            $key7: T7,
        }

        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
        }
    }};
    (
    $key1:ident: $value1:expr
    ,$key2:ident: $value2:expr
    ,$key3:ident: $value3:expr
    ,$key4:ident: $value4:expr
    ,$key5:ident: $value5:expr
    ,$key6:ident: $value6:expr
    ,$key7:ident: $value7:expr
    ,$key8:ident: $value8:expr
    $(,)?
    ) => {{
        #[derive(::serde::Serialize)]
        struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8> {
            $key1: T1,
            $key2: T2,
            $key3: T3,
            $key4: T4,
            $key5: T5,
            $key6: T6,
            $key7: T7,
            $key8: T8,
        }

        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
        }
    }};
    (
    $key1:ident: $value1:expr
    ,$key2:ident: $value2:expr
    ,$key3:ident: $value3:expr
    ,$key4:ident: $value4:expr
    ,$key5:ident: $value5:expr
    ,$key6:ident: $value6:expr
    ,$key7:ident: $value7:expr
    ,$key8:ident: $value8:expr
    ,$key9:ident: $value9:expr
    $(,)?
    ) => {{
        #[derive(::serde::Serialize)]
        struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9> {
            $key1: T1,
            $key2: T2,
            $key3: T3,
            $key4: T4,
            $key5: T5,
            $key6: T6,
            $key7: T7,
            $key8: T8,
            $key9: T9,
        }

        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
        }
    }};
    (
    $key1:ident: $value1:expr
    ,$key2:ident: $value2:expr
    ,$key3:ident: $value3:expr
    ,$key4:ident: $value4:expr
    ,$key5:ident: $value5:expr
    ,$key6:ident: $value6:expr
    ,$key7:ident: $value7:expr
    ,$key8:ident: $value8:expr
    ,$key9:ident: $value9:expr
    ,$key10:ident: $value10:expr
    $(,)?
    ) => {{
        #[derive(::serde::Serialize)]
        struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10> {
            $key1: T1,
            $key2: T2,
            $key3: T3,
            $key4: T4,
            $key5: T5,
            $key6: T6,
            $key7: T7,
            $key8: T8,
            $key9: T9,
            $key10: T10,
        }

        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
        }
    }};
    (
    $key1:ident: $value1:expr
    ,$key2:ident: $value2:expr
    ,$key3:ident: $value3:expr
    ,$key4:ident: $value4:expr
    ,$key5:ident: $value5:expr
    ,$key6:ident: $value6:expr
    ,$key7:ident: $value7:expr
    ,$key8:ident: $value8:expr
    ,$key9:ident: $value9:expr
    ,$key10:ident: $value10:expr
    ,$key11:ident: $value11:expr
    $(,)?
    ) => {{
        #[derive(::serde::Serialize)]
        struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11> {
            $key1: T1,
            $key2: T2,
            $key3: T3,
            $key4: T4,
            $key5: T5,
            $key6: T6,
            $key7: T7,
            $key8: T8,
            $key9: T9,
            $key10: T10,
            $key11: T11,
        }

        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
        }
    }};
    (
    $key1:ident: $value1:expr
    ,$key2:ident: $value2:expr
    ,$key3:ident: $value3:expr
    ,$key4:ident: $value4:expr
    ,$key5:ident: $value5:expr
    ,$key6:ident: $value6:expr
    ,$key7:ident: $value7:expr
    ,$key8:ident: $value8:expr
    ,$key9:ident: $value9:expr
    ,$key10:ident: $value10:expr
    ,$key11:ident: $value11:expr
    ,$key12:ident: $value12:expr
    $(,)?
    ) => {{
        #[derive(::serde::Serialize)]
        struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12> {
            $key1: T1,
            $key2: T2,
            $key3: T3,
            $key4: T4,
            $key5: T5,
            $key6: T6,
            $key7: T7,
            $key8: T8,
            $key9: T9,
            $key10: T10,
            $key11: T11,
            $key12: T12,
        }

        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
        }
    }};
}

pub trait ResponseExt {
    fn json_value(
        self,
    ) -> Box<dyn Future<Output = Result<Value, reqwest::Error>> + Send + Sync + 'static>;
}

impl ResponseExt for Response {
    fn json_value(
        self,
    ) -> Box<dyn Future<Output = Result<Value, reqwest::Error>> + Send + Sync + 'static> {
        Box::new(self.json())
    }
}

pub trait ValueExt {
    /// Extract a value with given query.
    ///
    /// # Examples
    ///
    /// ```
    /// # use serde_json::json;
    /// # use exqwest::ValueExt;
    /// let value = json!({ "name": "John Doe", "age": 43, "phones": ["+44 1234567", "+44 2345678"] });
    /// assert_eq!(value.query::<String>("name").unwrap(), "John Doe");
    /// assert_eq!(value.query::<u64>("age").unwrap(), 43);
    /// assert_eq!(value.query::<&str>("phones.0").unwrap(), "+44 1234567");
    /// ```
    fn query<'a, T>(&'a self, query: &str) -> Result<T, ValueQueryError>
    where
        T: Deserialize<'a>;
}

impl ValueExt for Value {
    fn query<'a, T>(&'a self, query: &str) -> Result<T, ValueQueryError>
    where
        T: Deserialize<'a>,
    {
        let mut query = query;
        let mut this = self;
        while !query.is_empty() {
            if let Some((q, rest)) = query.split_once('.') {
                if q.starts_with(|x: char| x.is_ascii_digit()) {
                    let index = q
                        .parse::<usize>()
                        .map_err(ValueQueryError::InvalidArrayIndex)?;
                    if let Some(x) = this.as_array() {
                        this = x.get(index).ok_or(ValueQueryError::ArrayOutOfBounds {
                            index,
                            len: x.len(),
                        })?;
                        query = rest;
                        continue;
                    } else {
                        return Err(ValueQueryError::ExpectedArray);
                    }
                }
                this = match this.get(q) {
                    Some(x) => x,
                    None => return Err(ValueQueryError::Index(q.to_string())),
                };
                query = rest;
            } else {
                if query.starts_with(|x: char| x.is_ascii_digit()) {
                    let index = query
                        .parse::<usize>()
                        .map_err(ValueQueryError::InvalidArrayIndex)?;
                    if let Some(x) = this.as_array() {
                        this = x.get(index).ok_or(ValueQueryError::ArrayOutOfBounds {
                            index,
                            len: x.len(),
                        })?;
                        break;
                    } else {
                        return Err(ValueQueryError::ExpectedArray);
                    }
                }
                this = match this.get(query) {
                    Some(x) => x,
                    None => return Err(ValueQueryError::Index(query.to_string())),
                };
                break;
            }
        }

        T::deserialize(this).map_err(|e| ValueQueryError::Deserialize {
            query: query.to_string(),
            source: e,
        })
    }
}

#[derive(Debug, Error)]
pub enum ValueQueryError {
    #[error("cannot deserialize field with query {query}")]
    Deserialize {
        query: String,
        source: serde_json::Error,
    },
    #[error("invalid array index")]
    InvalidArrayIndex(#[source] ParseIntError),
    #[error("expected an array")]
    ExpectedArray,
    #[error("array out of bounds: index is {index} but len is {len}")]
    ArrayOutOfBounds { index: usize, len: usize },
    #[error("field {0} not found")]
    Index(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serializable() {
        let x = serializable! {
            foo: "bar",
            baz: 42,
            field0: 0,
            field1: 1,
            field2: 2,
            field3: 3,
            field4: 4,
            field5: 5,
            field6: 6,
            field7: 7,
            field8: 8,
            field9: 9,
        };

        let s = serde_json::to_string(&x).unwrap();
        assert_eq!(
            s,
            r#"{"foo":"bar","baz":42,"field0":0,"field1":1,"field2":2,"field3":3,"field4":4,"field5":5,"field6":6,"field7":7,"field8":8,"field9":9}"#
        );
    }
}
