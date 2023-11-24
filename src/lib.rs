use std::{
    collections::{BTreeMap, HashMap},
    env::var,
    fmt::{Debug, Display, Write},
    future::Future,
    num::ParseIntError,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        OnceLock,
    },
};

use async_trait::async_trait;
use base64::{prelude::BASE64_STANDARD, Engine};
use dashmap::DashMap;
use ed25519_dalek::{SecretKey, Signature, Signer, SigningKey};
use hmac::{digest::Digest, Hmac, Mac};
use jwt::SignWithKey;
use reqwest::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE},
    Body, Client, IntoUrl, Method, Request, Response, StatusCode,
};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};
use thiserror::Error;
use tracing::{error, warn};
use uuid::Uuid;

mod macros;

pub use serde_json::Value;

#[doc(hidden)]
pub mod __private {
    pub use serde;
    pub use serde_json;
    pub use serde_urlencoded;
}

static CREDENTIALS: OnceLock<HashMap<&'static str, Credential>> = OnceLock::new();
static CREDENTIALS_WITH_SUFFIX: OnceLock<DashMap<String, HashMap<&'static str, Credential>>> =
    OnceLock::new();
static OKX_CREDENTIAL: OnceLock<OkxCredential> = OnceLock::new();
static OKX_CREDENTIAL_WITH_SUFFIX: OnceLock<DashMap<String, OkxCredential>> = OnceLock::new();

#[derive(Clone)]
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

#[derive(Clone)]
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

const EXCHANGES: [&str; 8] = [
    "BINANCE", "BITHUMB", "BYBIT", "GATEIO", "OKX", "UPBIT", "KRAKEN", "BACKPACK",
];

pub fn initialize_credentials() {
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

pub fn initialize_credentials_with_suffix(env_suffix: &str) {
    let mut creds = HashMap::new();

    for exchange in EXCHANGES {
        if exchange == "OKX" {
            let cred = (
                var(format!("{exchange}_API_KEY_{env_suffix}")),
                var(format!("{exchange}_API_SECRET_{env_suffix}")),
                var(format!("{exchange}_API_PASSPHRASE_{env_suffix}")),
            );
            if let (Ok(key), Ok(secret), Ok(passphrase)) = cred {
                let old = OKX_CREDENTIAL_WITH_SUFFIX.get_or_init(DashMap::new).insert(
                    env_suffix.to_string(),
                    OkxCredential {
                        key,
                        secret,
                        passphrase,
                    },
                );
                assert!(old.is_none(), "OKX credential already set");
            }
        } else {
            let cred = var(format!("{exchange}_API_KEY_{env_suffix}"))
                .and_then(|x| var(format!("{exchange}_API_SECRET_{env_suffix}")).map(|y| (x, y)));
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

    let old = CREDENTIALS_WITH_SUFFIX
        .get_or_init(DashMap::new)
        .insert(env_suffix.to_string(), creds);
    assert!(old.is_none(), "credentials already set");
}

#[async_trait]
pub trait ClientExt {
    async fn get_public(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error>;
    async fn post_public(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error>;
    async fn put_public(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error>;
    async fn delete_public(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error>;
    async fn patch_public(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error>;
    async fn get_private(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error>;
    async fn post_private(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error>;
    async fn put_private(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error>;
    async fn delete_private(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error>;
    async fn patch_private(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error>;
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum MaybeValue {
    Value(Value),
    Fail(String),
}

impl Display for MaybeValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MaybeValue::Value(x) => std::fmt::Display::fmt(&x, f),
            MaybeValue::Fail(s) => std::fmt::Display::fmt(&s, f),
        }
    }
}

macro_rules! request {
    (@public $this:expr, $method:ident, $url:ident, $query:ident, $payload:ident) => {{
        let url = $url;
        let method = stringify!($method);
        ::tracing::trace!(url = %url.clone().into_url().unwrap(), method, "sending an public request");
        let resp = $this
            .$method(url)
            .body($payload.as_ref().to_string())
            .query(&$query)
            .send()
            .await?;
        if !resp.status().is_success() {
            Err(Error::NonOkResponse {
                status: resp.status(),
                body: resp.text().await?,
            })
        } else {
            resp.json().await.map_err(Into::into)
        }
    }};

    (@private $this:expr, $method:ident, $url:ident, $query:ident, $payload:ident) => {{
        let url = $url;
        let method = stringify!($method);
        ::tracing::trace!(url = %url.clone().into_url().unwrap(), method, "sending an private request");
        let (client, req) = $this
            .$method(url)
            .query(&$query)
            .body($payload.as_ref().to_string())
            .build_split();
        let mut req = req?;
        if let Err(e) = sign_request(&mut req, None) {
            let error = Box::new(e) as Box<dyn std::error::Error + Send + Sync + 'static>;
            error!(error, "cannot sign request");
            panic!("cannot sign request: {error}");
        }
        if req.body().into_str().is_empty() {
            req.headers_mut()
                .insert(CONTENT_LENGTH, "0".parse().unwrap());
        }
        req.body().into_str();
        let resp = client.execute(req).await?;
        if !resp.status().is_success() {
            return Err(Error::NonOkResponse {
                status: resp.status(),
                body: resp.text().await?,
            });
        }
        let v = resp.json::<MaybeValue>().await.map_err(Error::from)?;
        match v {
            MaybeValue::Value(v) => Ok(v),
            MaybeValue::Fail(s) => Err(Error::InvalidJson(s)),
        }
    }};
}

#[async_trait]
impl ClientExt for Client {
    async fn get_public(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error> {
        request!(@public self, get, url, query, payload)
    }
    async fn post_public(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error> {
        request!(@public self, post, url, query, payload)
    }
    async fn put_public(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error> {
        request!(@public self, put, url, query, payload)
    }
    async fn delete_public(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error> {
        request!(@public self, delete, url, query, payload)
    }
    async fn patch_public(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error> {
        request!(@public self, patch, url, query, payload)
    }
    async fn get_private(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error> {
        request!(@private self, get, url, query, payload)
    }
    async fn post_private(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error> {
        request!(@private self, post, url, query, payload)
    }
    async fn put_private(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error> {
        request!(@private self, put, url, query, payload)
    }
    async fn delete_private(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error> {
        request!(@private self, delete, url, query, payload)
    }
    async fn patch_private(
        &self,
        url: impl IntoUrl + Clone + Send,
        query: impl Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync,
    ) -> Result<Value, Error> {
        request!(@private self, patch, url, query, payload)
    }
}

pub struct Clients {
    index: AtomicUsize,
    clients: Vec<Client>,
}

impl Clients {
    pub fn new(clients: impl IntoIterator<Item = Client>) -> Self {
        Self {
            index: AtomicUsize::new(0),
            clients: clients.into_iter().collect(),
        }
    }

    pub fn get_client(&self) -> &Client {
        &self.clients[self.index.fetch_add(1, Ordering::Relaxed) % self.clients.len()]
    }

    pub fn clients(&self) -> &[Client] {
        &self.clients
    }
}

impl ClientExt for Clients {
    fn get_public<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Clone + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync + 'async_trait,
    ) -> Pin<Box<dyn Future<Output = Result<Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().get_public(url, query, payload)
    }

    fn post_public<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Clone + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync + 'async_trait,
    ) -> Pin<Box<dyn Future<Output = Result<Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().post_public(url, query, payload)
    }

    fn put_public<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Clone + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync + 'async_trait,
    ) -> Pin<Box<dyn Future<Output = Result<Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().put_public(url, query, payload)
    }

    fn delete_public<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Clone + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync + 'async_trait,
    ) -> Pin<Box<dyn Future<Output = Result<Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().delete_public(url, query, payload)
    }

    fn patch_public<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Clone + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync + 'async_trait,
    ) -> Pin<Box<dyn Future<Output = Result<Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().patch_public(url, query, payload)
    }

    fn get_private<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Clone + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync + 'async_trait,
    ) -> Pin<Box<dyn Future<Output = Result<Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().get_private(url, query, payload)
    }

    fn post_private<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Clone + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync + 'async_trait,
    ) -> Pin<Box<dyn Future<Output = Result<Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().post_private(url, query, payload)
    }

    fn put_private<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Clone + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync + 'async_trait,
    ) -> Pin<Box<dyn Future<Output = Result<Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().put_private(url, query, payload)
    }

    fn delete_private<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Clone + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync + 'async_trait,
    ) -> Pin<Box<dyn Future<Output = Result<Value, Error>> + Send + 'async_trait>>
    where
        'this: 'async_trait,
        Self: 'async_trait,
    {
        self.get_client().delete_private(url, query, payload)
    }

    fn patch_private<'this, 'async_trait>(
        &'this self,
        url: impl 'async_trait + IntoUrl + Clone + Send,
        query: impl 'async_trait + Serialize + Send + Sync,
        payload: impl AsRef<str> + Send + Sync + 'async_trait,
    ) -> Pin<Box<dyn Future<Output = Result<Value, Error>> + Send + 'async_trait>>
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
    #[error("invalid JSON payload: {0}")]
    InvalidJson(String),
    #[error("signing mechanism not implemented")]
    NotImplemented,
    #[error("server returned non-OK response, status: {status}, body: {body}")]
    NonOkResponse { status: StatusCode, body: String },
    #[error(transparent)]
    ValueQuery(#[from] ValueQueryError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    SerializeUrlencoded(#[from] serde_urlencoded::ser::Error),
    #[error(transparent)]
    DeserializeUrlencoded(#[from] serde_urlencoded::de::Error),
}

pub fn sign_request(req: &mut Request, env_suffix: Option<String>) -> Result<(), Error> {
    match req.url().host_str().expect("no host for request URL") {
        "api.binance.com" | "fapi.binance.com" | "papi.binance.com" => {
            sign_binance(req, env_suffix)
        }
        "api.bithumb.com" => sign_bithumb(req, env_suffix),
        "api.bybit.com" => sign_bybit(req, env_suffix),
        "api.gateio.ws" => sign_gateio(req, env_suffix),
        "aws.okx.com" | "www.okx.com" => sign_okx(req, env_suffix),
        "api.upbit.com" => sign_upbit(req, env_suffix),
        "api.kraken.com" => sign_kraken(req, env_suffix),
        "api.backpack.exchange" => sign_backpack(req, env_suffix),
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

impl<'a> OptionBodyExt<'a> for Option<&'a Body> {
    fn into_str(self) -> &'a str {
        self.map(|x| {
            std::str::from_utf8(x.as_bytes().unwrap_or_default()).expect("non-utf-8 request body")
        })
        .unwrap_or_default()
    }
}

fn sign_bithumb(req: &mut Request, env_suffix: Option<String>) -> Result<(), Error> {
    let credential = if let Some(env_suffix) = env_suffix {
        CREDENTIALS_WITH_SUFFIX
            .get()
            .expect("credentials not loaded")
            .get(&env_suffix)
            .expect("suffix not loaded")
            .get("BITHUMB")
            .expect("no credential for Bithumb")
            .clone()
    } else {
        CREDENTIALS
            .get()
            .expect("credentials not loaded")
            .get("BITHUMB")
            .expect("no credential for Bithumb")
            .clone()
    };
    let nonce = timestamp_millis();
    let endpoint = req.url().path();
    let query_string = req.body().into_str().replace('/', "%2F");
    let encode_target = format!("{}\x00{}\x00{}", endpoint, query_string, nonce);

    let mut mac = Hmac::<Sha512>::new_from_slice(credential.secret.as_bytes())
        .expect("cannot initialize HMAC");
    mac.update(encode_target.as_bytes());
    let mut encrypted = String::with_capacity(32);
    for x in mac.finalize().into_bytes().iter() {
        write!(&mut encrypted, "{x:02x}").unwrap();
    }

    let base64 = base64::engine::general_purpose::STANDARD.encode(encrypted);

    req.headers_mut()
        .insert("Api-Key", credential.key.parse().unwrap());
    req.headers_mut()
        .insert("Api-Nonce", nonce.to_string().parse().unwrap());
    req.headers_mut()
        .insert("Api-Sign", base64.parse().unwrap());
    req.headers_mut().insert(
        CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    req.headers_mut()
        .insert(ACCEPT, "application/json".parse().unwrap());

    Ok(())
}

fn sign_bybit(req: &mut Request, env_suffix: Option<String>) -> Result<(), Error> {
    const RECV_WINDOW: u32 = 5000;

    let credential = if let Some(env_suffix) = env_suffix {
        CREDENTIALS_WITH_SUFFIX
            .get()
            .expect("credentials not loaded")
            .get(&env_suffix)
            .expect("suffix not loaded")
            .get("BYBIT")
            .expect("no credential for Bybit")
            .clone()
    } else {
        CREDENTIALS
            .get()
            .expect("credentials not loaded")
            .get("BYBIT")
            .expect("no credential for Bybit")
            .clone()
    };

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
    let mut encrypted = String::with_capacity(32);
    for x in mac.finalize().into_bytes().iter() {
        write!(&mut encrypted, "{x:02x}").unwrap();
    }

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

fn sign_binance(req: &mut Request, env_suffix: Option<String>) -> Result<(), Error> {
    const RECV_WINDOW: u32 = 3000;

    let credential = if let Some(env_suffix) = env_suffix {
        CREDENTIALS_WITH_SUFFIX
            .get()
            .expect("credentials not loaded")
            .get(&env_suffix)
            .expect("suffix not loaded")
            .get("BINANCE")
            .expect("no credential for Binance")
            .clone()
    } else {
        CREDENTIALS
            .get()
            .expect("credentials not loaded")
            .get("BINANCE")
            .expect("no credential for Binance")
            .clone()
    };

    let timestamp = timestamp_millis();

    req.url_mut()
        .query_pairs_mut()
        .append_pair("recvWindow", &RECV_WINDOW.to_string())
        .append_pair("timestamp", &timestamp.to_string());

    let mut mac = Hmac::<Sha256>::new_from_slice(credential.secret.as_bytes())
        .expect("cannot intialize HMAC");
    mac.update(req.url().query().unwrap_or_default().as_bytes());
    let mut encrypted = String::with_capacity(32);
    for x in mac.finalize().into_bytes().iter() {
        write!(&mut encrypted, "{x:02x}").unwrap();
    }

    req.url_mut()
        .query_pairs_mut()
        .append_pair("signature", &encrypted);
    req.headers_mut()
        .insert("X-MBX-APIKEY", credential.key.parse().unwrap());

    Ok(())
}

fn sign_gateio(req: &mut Request, env_suffix: Option<String>) -> Result<(), Error> {
    let credential = if let Some(env_suffix) = env_suffix {
        CREDENTIALS_WITH_SUFFIX
            .get()
            .expect("credentials not loaded")
            .get(&env_suffix)
            .expect("suffix not loaded")
            .get("GATEIO")
            .expect("no credential for Gate.io")
            .clone()
    } else {
        CREDENTIALS
            .get()
            .expect("credentials not loaded")
            .get("GATEIO")
            .expect("no credential for Gate.io")
            .clone()
    };

    let now = timestamp_millis() / 1000;

    let mut payload_hasher = Sha512::new();
    payload_hasher.update(req.body().into_str());
    let mut payload_hash = String::with_capacity(32);
    for x in payload_hasher.finalize().iter() {
        write!(&mut payload_hash, "{x:02x}").unwrap();
    }

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
    let mut encrypted = String::with_capacity(32);
    for x in mac.finalize().into_bytes().iter() {
        write!(&mut encrypted, "{x:02x}").unwrap();
    }

    req.headers_mut()
        .insert("KEY", credential.key.parse().unwrap());
    req.headers_mut()
        .insert("Timestamp", now.to_string().parse().unwrap());
    req.headers_mut().insert("Sign", encrypted.parse().unwrap());

    Ok(())
}

fn sign_okx(req: &mut Request, env_suffix: Option<String>) -> Result<(), Error> {
    const RECV_WINDOW: u32 = 3000;

    let credential = if let Some(env_suffix) = env_suffix {
        OKX_CREDENTIAL_WITH_SUFFIX
            .get()
            .expect("credentials not loaded")
            .get(&env_suffix)
            .expect("no credential for OKX")
            .value()
            .clone()
    } else {
        OKX_CREDENTIAL.get().expect("no credential for OKX").clone()
    };

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
    req.headers_mut()
        .insert(CONTENT_TYPE, "application/json".parse().unwrap());

    Ok(())
}

fn sign_upbit(req: &mut Request, env_suffix: Option<String>) -> Result<(), Error> {
    let credential = if let Some(env_suffix) = env_suffix {
        CREDENTIALS_WITH_SUFFIX
            .get()
            .expect("credentials not loaded")
            .get(&env_suffix)
            .expect("suffix not loaded")
            .get("UPBIT")
            .expect("no credential for UPbit")
            .clone()
    } else {
        CREDENTIALS
            .get()
            .expect("credentials not loaded")
            .get("UPBIT")
            .expect("no credential for UPbit")
            .clone()
    };

    let params = if req.method() == Method::GET {
        req.url()
            .query_pairs()
            .map(|(x, y)| (x.to_string(), serde_json::Value::String(y.to_string())))
            .collect::<BTreeMap<_, _>>()
    } else if let Some(body) = req.body() {
        serde_json::from_slice::<BTreeMap<String, serde_json::Value>>(
            body.as_bytes().expect("body is a stream"),
        )?
    } else {
        BTreeMap::new()
    };

    let auth = if params.is_empty() {
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
        hasher.update(
            serde_urlencoded::to_string(&params)
                .expect("cannot url-encode payload")
                .as_bytes(),
        );
        let mut hash = String::with_capacity(32);
        for x in hasher.finalize().iter() {
            write!(&mut hash, "{x:02x}").unwrap();
        }

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
        .insert(AUTHORIZATION, format!("Bearer {}", auth).parse().unwrap());
    req.headers_mut()
        .insert(CONTENT_TYPE, "application/json".parse().unwrap());

    Ok(())
}

fn sign_kraken(req: &mut Request, env_suffix: Option<String>) -> Result<(), Error> {
    if req.method() != Method::POST {
        warn!(method = %req.method(), "Kraken requests can only be signed with POST method, ignoring");
        return Ok(());
    }

    let credential = if let Some(env_suffix) = env_suffix {
        CREDENTIALS_WITH_SUFFIX
            .get()
            .expect("credentials not loaded")
            .get(&env_suffix)
            .expect("suffix not loaded")
            .get("KRAKEN")
            .expect("no credential for Kraken")
            .clone()
    } else {
        CREDENTIALS
            .get()
            .expect("credentials not loaded")
            .get("KRAKEN")
            .expect("no credential for Kraken")
            .clone()
    };
    let raw_secret = base64::prelude::BASE64_STANDARD
        .decode(&credential.secret)
        .expect("Kraken API secret is not a valid base64 string");

    let nonce = timestamp_millis();
    if let Some(body) = req.body_mut().as_mut() {
        if body
            .as_bytes()
            .expect("streamed body is not supported")
            .is_empty()
        {
            *body = Body::from(format!("nonce={nonce}"));
        } else {
            *body = Body::from(format!("{}&nonce={nonce}", Some(&*body).into_str()));
        }
    }

    let postdata = req.body().into_str();
    let payload = format!("{nonce}{postdata}");

    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let hash = hasher.finalize();

    let mut mac = Hmac::<Sha512>::new_from_slice(&raw_secret).expect("cannot initialize HMAC");
    mac.update(req.url().path().as_bytes());
    mac.update(hash.as_slice());
    let encrypted = mac.finalize().into_bytes();
    let sigdigest = base64::prelude::BASE64_STANDARD.encode(encrypted);

    req.headers_mut()
        .insert("API-Key", credential.key.parse().unwrap());
    req.headers_mut()
        .insert("API-Sign", sigdigest.parse().unwrap());
    req.headers_mut().insert(
        CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().unwrap(),
    );

    Ok(())
}

fn sign_backpack(req: &mut Request, env_suffix: Option<String>) -> Result<(), Error> {
    const WINDOW: u32 = 3000;

    let credential = if let Some(env_suffix) = env_suffix {
        CREDENTIALS_WITH_SUFFIX
            .get()
            .expect("credentials not loaded")
            .get(&env_suffix)
            .expect("suffix not loaded")
            .get("BACKPACK")
            .expect("no credential for Backpack")
            .clone()
    } else {
        CREDENTIALS
            .get()
            .expect("credentials not loaded")
            .get("BACKPACK")
            .expect("no credential for Backpack")
            .clone()
    };

    let sk = BASE64_STANDARD
        .decode(&credential.secret)
        .expect("cannot parse secret as Base64");
    let sk = SecretKey::try_from(sk).expect("invalid secret key");

    let timestamp = timestamp_millis();

    let instruction = match req.url().path() {
        "/api/v1/order" if req.method() == Method::GET => "orderQuery",
        "/api/v1/order" if req.method() == Method::POST => "orderExecute",
        "/api/v1/order" if req.method() == Method::DELETE => "orderCancel",
        "/api/v1/orders" if req.method() == Method::GET => "orderQueryAll",
        "/api/v1/orders" if req.method() == Method::DELETE => "orderCancelAll",
        "/api/v1/capital" if req.method() == Method::GET => "balanceQuery",
        other => unimplemented!("{other}"),
    };

    let params: BTreeMap<String, String> = match req.method() {
        &Method::POST | &Method::DELETE => serde_json::from_str(req.body().into_str())?,
        _ => req
            .url()
            .query_pairs()
            .map(|(x, y)| (x.into_owned(), y.into_owned()))
            .collect(),
    };

    let mut signee = format!("instruction={instruction}");
    for (k, v) in &params {
        signee.push_str(&format!("&{k}={v}"));
    }
    if req.method() == Method::GET {
        req.url_mut().set_query(Some(
            params
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&")
                .as_str(),
        ))
    }
    signee.push_str(&format!("&timestamp={timestamp}&window={WINDOW}"));

    let signature: Signature = SigningKey::from_bytes(&sk).sign(signee.as_bytes());
    let signature = BASE64_STANDARD.encode(signature.to_bytes());

    req.url_mut()
        .query_pairs_mut()
        .append_pair("timestamp", &timestamp.to_string())
        .append_pair("window", &WINDOW.to_string());

    req.headers_mut()
        .insert("X-Timestamp", timestamp.to_string().parse().unwrap());
    req.headers_mut()
        .insert("X-Window", WINDOW.to_string().parse().unwrap());
    req.headers_mut()
        .insert("X-API-Key", credential.key.parse().unwrap());
    req.headers_mut()
        .insert("X-Signature", signature.parse().unwrap());

    if matches!(req.method(), &Method::POST | &Method::DELETE) {
        req.headers_mut().insert(
            CONTENT_TYPE,
            "application/json; charset=utf-8".parse().unwrap(),
        );
    }

    Ok(())
}

/// # Examples
/// ```
/// # use exqwest::json;
/// let s = json! {
///     foo: "bar",
/// }.unwrap();
/// assert_eq!(&s, r#"{"foo":"bar"}"#);
/// ````
#[macro_export]
macro_rules! json {
    ($($key:ident: $value:expr)? $(,$keys:ident$(: $values:expr)?)* $(,)?) => {
        {
            use $crate::__private::serde_json;
            serde_json::to_string(&$crate::serializable! {
                $($key: $value)? $(,$keys$(: $values)?)*
            })
        }
    };
}

/// # Examples
/// ```
/// # use exqwest::urlencoded;
/// let s = urlencoded! {
///     foo: "bar",
/// }.unwrap();
/// assert_eq!(&s, "foo=bar");
/// ````
#[macro_export]
macro_rules! urlencoded {
    ($($key:ident: $value:expr)? $(,$keys:ident$(: $values:expr)?)* $(,)?) => {
        {
            use $crate::__private::serde_urlencoded;
            serde_urlencoded::to_string(&$crate::serializable! {
                $($key: $value)? $(,$keys$(: $values)?)*
            })
        }
    };
}

pub trait ResponseExt {
    fn json_value(
        self,
    ) -> Pin<Box<dyn Future<Output = Result<Value, reqwest::Error>> + Send + Sync + 'static>>;
}

impl ResponseExt for Response {
    fn json_value(
        self,
    ) -> Pin<Box<dyn Future<Output = Result<Value, reqwest::Error>> + Send + Sync + 'static>> {
        Box::pin(self.json())
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

    fn from_str(s: &str) -> Result<Self, serde_json::Error>
    where
        Self: Sized;
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
                    None => {
                        return Err(ValueQueryError::Index {
                            field: q.to_string(),
                            value: this.clone(),
                        })
                    }
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
                    None => {
                        return Err(ValueQueryError::Index {
                            field: query.to_string(),
                            value: this.clone(),
                        })
                    }
                };
                break;
            }
        }

        T::deserialize(this).map_err(|e| ValueQueryError::Deserialize {
            query: query.to_string(),
            source: e,
        })
    }

    fn from_str(s: &str) -> Result<Self, serde_json::Error>
    where
        Self: Sized,
    {
        serde_json::from_str(s)
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
    #[error("field {field} not found, value: {value}")]
    Index { field: String, value: Value },
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_serializable() {
        let x = crate::serializable! {
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
