#[macro_use]
extern crate http_guest;
extern crate base64;
extern crate byteorder;
extern crate failure;
extern crate hmac;
extern crate regex;
extern crate sha2;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use failure::Error;
use hmac::{Hmac, Mac};
use http_guest::header::HeaderValue;
use http_guest::{KVStore, Request, RequestExt, Response};
use regex::Regex;
use sha2::Sha256;

const IP_HEADER: &str = "fastly-client-ip";
const RATE_LIMIT: u32 = 10;
const API_BASE_URL: &str = "https://httpbin.org";
// head -c32 /dev/urandom | base64
const HMAC_SECRET: &[u8; 44] = b"ZPM//uZwrUN85ogHI0JAb8K1SFtNw270W6wdU4Op1Wk=";

#[derive(Debug)]
enum HandlerError {
    Internal(Error),
    Send(Error),
    RateLimit(String),
    Forbidden(String),
}

struct Handler<'a> {
    kvs: &'a mut KVStore,
}

type JWTPayload = Vec<u8>;

impl<'a> Handler<'a> {
    fn build_request(&self, req: &Request<Vec<u8>>, count: u32) -> Result<Request<Vec<u8>>, Error> {
        let mut builder = &mut Request::builder();
        for (k, v) in req.headers().iter() {
            if k.to_string().to_lowercase() == "user-agent" {
                // User-Agent must not be modified, otherwise `send` will fail with a `Hostcall` error.
                // This is the header that is expected: "User-Agent": "fastly-terrarium"
                continue;
            }
            builder = builder.header(k, v);
        }
        builder
            .method(req.method())
            .uri(format!(
                "{}{}",
                API_BASE_URL,
                req.uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("")
            ))
            .header("x-request-count", count.to_string())
            .body(req.body().clone())
            .map_err(Error::from)
    }

    fn get_count(&self, header: &HeaderValue) -> Result<u32, Error> {
        let key = header.to_str()?.to_string();
        let bytes = self.kvs.get(&key).unwrap_or_else(|| vec![0, 0, 0, 0]);
        let count = std::io::Cursor::new(bytes).read_u32::<BigEndian>()?;
        Ok(count)
    }

    fn store_count(&mut self, header: &HeaderValue, count: u32) -> Result<(), Error> {
        let mut bytes = vec![];
        bytes.write_u32::<BigEndian>(count)?;

        let key = header.to_str()?.to_string();
        self.kvs.insert(&key, &bytes);
        Ok(())
    }

    fn authenticate(&self, req: &Request<Vec<u8>>) -> Result<JWTPayload, HandlerError> {
        let mut mac =
            Hmac::<Sha256>::new_varkey(HMAC_SECRET).expect("failed to create MAC instance");

        let header = req
            .headers()
            .get("authorization")
            .ok_or_else(|| HandlerError::Forbidden("authorization header is missing".to_string()))?
            .to_str()
            .map_err(|_| {
                HandlerError::Internal(failure::format_err!(
                    "authorization header value is not a string"
                ))
            })?
            .to_string();

        let re = Regex::new(r"\s*Bearer\s+(?P<header>\w+)\.(?P<payload>\w+)\.(?P<signature>\w+)")
            .map_err(|_| {
            HandlerError::Internal(failure::format_err!("regex creation failed"))
        })?;
        let result = re.captures(&header).ok_or_else(|| HandlerError::Forbidden(format!(
            "bad authentication header format '{}', expected format 'Bearer <header>.<payload>.<signature>'",
            header
        )))?;

        mac.input(format!("{}.{}", &result["header"], &result["payload"]).as_bytes());

        let dec_sig =
            base64::decode_config(&result["signature"].as_bytes(), base64::URL_SAFE_NO_PAD)
                .map_err(|_| HandlerError::Forbidden("bad signature".to_string()))?;
        mac.verify(&dec_sig)
            .map_err(|_| HandlerError::Forbidden("failed to verify token signature".to_string()))?;
        Ok(result["payload"].as_bytes().to_vec())
    }

    fn handle(&mut self, req: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, HandlerError> {
        self.authenticate(req)?;

        let header = req
            .headers()
            .get(IP_HEADER)
            .ok_or_else(|| failure::format_err!("header {} was unset", IP_HEADER))
            .map_err(HandlerError::Internal)?;

        let count = self.get_count(header).map_err(HandlerError::Internal)?;
        if count > RATE_LIMIT {
            return Err(HandlerError::RateLimit(format!(
                "your IP '{}' is rate-limited\n",
                header.to_str().unwrap_or("").to_string()
            )));
        }

        let r = self
            .build_request(req, count)
            .map_err(HandlerError::Internal)?;
        let resp = r.send().map_err(Error::from).map_err(HandlerError::Send)?;

        self.store_count(header, count + 1)
            .map_err(HandlerError::Internal)?;

        Ok(resp)
    }
}

fn handler(kvs: &mut KVStore, req: &Request<Vec<u8>>) -> Response<Vec<u8>> {
    let mut h = Handler { kvs };
    match h.handle(req) {
        Ok(resp) => resp,
        Err(handler_err) => match handler_err {
            HandlerError::Internal(err) => Response::builder()
                .status(500)
                .header("Content-Type", "text/plain")
                .body(err.to_string().as_bytes().to_vec())
                .expect("failed to send error response"),
            HandlerError::Send(err) => Response::builder()
                .status(502)
                .header("Content-Type", "text/plain")
                .body(err.to_string().as_bytes().to_vec())
                .expect("failed to send error response"),
            HandlerError::RateLimit(msg) => Response::builder()
                .status(429)
                .header("Content-Type", "text/plain")
                .body(msg.as_bytes().to_vec())
                .expect("failed to send error response"),
            HandlerError::Forbidden(msg) => Response::builder()
                .status(400)
                .header("Content-Type", "text/plain")
                .body(msg.as_bytes().to_vec())
                .expect("failed to send error response"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_guest::KVStore;

    #[test]
    fn test_build_request() {
        let h = Handler {
            // Can't initialize KVStore but does not need it for the test, thus mock it.
            kvs: unsafe { &mut ::std::mem::transmute::<(), KVStore>(()) },
        };

        let body = b"this is our data".to_vec();
        let orig_req = Request::builder()
            .method("GET")
            .uri("https://api.spreadshirt.net/my/awesome/path")
            .header("user-agent", "something")
            .header("x-something", "spreadshirt")
            .body(body.clone())
            .expect("failed to build request");
        let res = h.build_request(&orig_req, 42);
        assert_eq!(res.is_ok(), true);
        let resp = res.unwrap();
        // check that user-agent is not copied
        assert_eq!(resp.headers().contains_key("user-agent"), false);
        assert_eq!(resp.headers().get("x-something").unwrap(), "spreadshirt");
        assert_eq!(resp.headers().get("x-request-count").unwrap(), "42");
        assert_eq!(resp.uri(), "https://httpbin.org/my/awesome/path");
        assert_eq!(resp.body().clone(), body);
        dbg!(resp.headers());
    }

    #[test]
    fn test_authenticate() {
        let h = Handler {
            // Can't initialize KVStore but does not need it for the test, thus mock it.
            kvs: unsafe { &mut ::std::mem::transmute::<(), KVStore>(()) },
        };

        // generated with jwt.io
        let token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.nJkjEH_2wFclNpjG4mem7xShvYDS9UB3zfHmQ93CNiQ";

        let orig_req = Request::builder()
            .method("GET")
            .uri("https://api.spreadshirt.net/my/awesome/path")
            .header("authorization", token)
            .body(vec![])
            .expect("failed to build request");
        let res = h.authenticate(&orig_req);
        assert_eq!(res.is_ok(), true);
        let dec_payload =
            base64::decode(&res.unwrap()).expect("failed to base64 decode JWT payload");

        let expected = r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#.as_bytes();
        assert_eq!(dec_payload, expected);
    }

    #[test]
    fn test_invalid_token() {
        let h = Handler {
            // Can't initialize KVStore but does not need it for the test, thus mock it.
            kvs: unsafe { &mut ::std::mem::transmute::<(), KVStore>(()) },
        };

        let token = "Bearer something.another-thing.whatever";

        let orig_req = Request::builder()
            .method("GET")
            .uri("https://api.spreadshirt.net/my/awesome/path")
            .header("authorization", token)
            .body(vec![])
            .expect("failed to build request");
        let res = h.authenticate(&orig_req);
        assert_eq!(res.is_err(), true);
    }

    #[test]
    fn test_missing_jwt() {
        let h = Handler {
            // Can't initialize KVStore but does not need it for the test, thus mock it.
            kvs: unsafe { &mut ::std::mem::transmute::<(), KVStore>(()) },
        };

        let orig_req = Request::builder()
            .method("GET")
            .uri("https://api.spreadshirt.net/my/awesome/path")
            .body(vec![])
            .expect("failed to build request");
        let res = h.authenticate(&orig_req);
        assert_eq!(res.is_err(), true);
    }
}

// Macro that sets handler as the entry point of the guest application:
guest_app_kvs!(handler);
