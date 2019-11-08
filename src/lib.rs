use chrono::{DateTime, Duration, Utc};
use deflate::{deflate_bytes_zlib_conf, Compression};
use log::*;
use ring::hmac;
use serde_json::{json, to_string};

pub struct TencentCloudApi {
    tcs_version: &'static str,
    app_id: u64,
    secret_id: String,
    secret_key: String,
}

impl TencentCloudApi {
    pub fn new(app_id: u64, secret_id: &str, secret_key: &str) -> Self {
        TencentCloudApi {
            tcs_version: "3.0",
            app_id,
            secret_id: secret_id.to_string(),
            secret_key: secret_key.to_string(),
        }
    }

    pub fn tcs_sign(&mut self, tcs_name: &str) {
        info!("TencentCloudApi[tcs_name: {}]", tcs_name);

        let service = "cvm";
        let host = "cvm.tencentcloudapi.com";
        let region = "ap-shanghai";
        let action = "DescribeInstances";
        let version = "2017-03-12";
        let algorithm = "TC3-HMAC-SHA256";

        // 获取记录调用时间...
        let mut local_time = chrono::Local::now();
        let mut local_ts = local_time.timestamp();
        let mut local_date = local_time.format("%Y-%m-%d").to_string();

        // 测试对比时间...
        //let local_ts = 1573009278;
        //let local_date = "2019-11-06".to_string();
        info!("[TIME]][local_ts: {:?}][local_date: {:?}]", local_ts, local_date);

        info!("[###][步骤 1：拼接规范请求串]===================================================================");

        // ************* 步骤 1：拼接规范请求串 *************
        let http_request_method = "POST";
        let canonical_uri = "/";
        let canonical_query_string = "";
        let canonical_headers = format!("{}{}{}{}", "content-type:application/json; charset=utf-8\n", "host:", host, "\n");
        let signed_headers = "content-type;host";

        // 参数签名...
        let payload = "{\"Limit\": 1, \"Filters\": [{\"Values\": [\"COAM-1\"], \"Name\": \"instance-name\"}]}";
        let payload = json!({
            "Limit": 1,
            "Filters": [
                {
                    "Values": ["COAM-1"],
                    "Name": "instance-name"
                }
            ]
        });
        info!("[payload: {}]", payload);
        let hashed_request_payload = sha256_hex(to_string(&payload).unwrap().as_str());
        info!("[hashed_request_payload: ]\n{}", hashed_request_payload);

        let canonical_request = format!("{}{}{}{}{}{}{}{}{}{}{}", http_request_method, "\n", canonical_uri, "\n", canonical_query_string, "\n", canonical_headers, "\n", signed_headers, "\n", hashed_request_payload);
        info!("[canonical_request: ]\n{}", canonical_request);

        // ************* 步骤 2：拼接待签名字符串 *************
        let credential_scope = format!("{}{}{}{}{}", local_date, "/", service, "/", "tc3_request");
        let hashed_canonical_request = sha256_hex(canonical_request.as_str());
        let string_to_sign = format!("{}{}{}{}{}{}{}", algorithm, "\n", local_ts, "\n", credential_scope, "\n", hashed_canonical_request);
        info!("[string_to_sign: ]\n{}", string_to_sign);

        // ************* 步骤 3：计算签名 *************
        let tc3_secret_key = format!("TC3{}", self.secret_key);
        info!("[tc3_secret_key: ]\n{:?}\n{:02X?}", tc3_secret_key, tc3_secret_key.as_bytes());

        let date_sign = hmac_256(tc3_secret_key.as_bytes().to_vec(), local_date.as_str());
        info!("[date_sign: ]\n{:02X?}", date_sign);

        let secret_service_sign = hmac_256(date_sign, service);
        info!("[secret_service_sign: ]\n{:02X?}", secret_service_sign);

        let tc3_secret_service_sign = hmac_256(secret_service_sign, "tc3_request");
        info!("[tc3_secret_service_sign: ]\n{:02X?}", tc3_secret_service_sign);

        let tc3_signature_vec = hmac_256(tc3_secret_service_sign, string_to_sign.as_str());
        let tc3_signature = bytes_to_string(&tc3_signature_vec);
        info!("[tc3_signature_vec: ]\n{:02x?}", tc3_signature_vec);
        info!("[tc3_signature: ]\n{:?}", tc3_signature);

        info!("[###][步骤 4：拼接Authorization]===================================================================");

        // ************* 步骤 4：拼接 Authorization *************
        let authorization = format!("{}{}{}{}{}{}{}{}{}{}{}{}", algorithm, " ", "Credential=", self.secret_id, "/", credential_scope, ", ", "SignedHeaders=", signed_headers, ", ", "Signature=", tc3_signature);
        info!("[authorization: ]\n{}", authorization);

        info!("[###][步骤 5：构造请求]===================================================================");

        let curl = format!("{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}", "curl -X POST https://", host, " -H \"Authorization: ", authorization, "\"", " -H \"Content-Type: application/json; charset=utf-8\"", " -H \"Host: ", host, "\"", " -H \"X-TC-Action: ", action, "\"", " -H \"X-TC-Timestamp: ", local_ts, "\"", " -H \"X-TC-Version: ", version, "\"", " -H \"X-TC-Region: ", region, "\"", " -d '", payload, "'");
        info!("[curl: ]\n{}", curl);
    }

    /// In case that the secret_key is leaked, we want to update the key at runtime.
    pub fn update_key(&mut self, secret_key: &str) {
        self.secret_key = secret_key.to_string();
    }

    /// generate user sign with timestamp. Note that the SDK only accept
    /// timestamps **in seconds**.
    ///
    /// # Examples
    ///
    /// ```
    /// use tls_sig_api::TencentCloudApi;
    /// use chrono::Duration;
    ///
    /// let mock_key = "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e";
    /// let signer = TencentCloudApi::new(0, mock_key,mock_key);
    ///
    /// let identifier = "10086";
    /// let expire = Duration::hours(2);
    /// let userbuf = "This' really a good crate!";
    ///
    /// let digest = signer.gen_sign(identifier, expire, Some(userbuf));
    /// println!("{}", digest);
    /// ```
    pub fn gen_sign(&self, identifier: &str, expire: Duration, userbuf: Option<&str>) -> String {
        // Always use current time for production sign.
        let curr_time = Utc::now();
        debug!(
            "current time: {}, timestamp in seconds: {}",
            curr_time,
            curr_time.timestamp()
        );

        self.gen_sign_with_time(identifier, curr_time, expire, userbuf)
    }

    fn gen_sign_with_time(
        &self,
        identifier: &str,
        dt: DateTime<Utc>,
        expire: Duration,
        userbuf: Option<&str>,
    ) -> String {
        let mut dict = json!({
            "TLS.ver": self.tcs_version,
            "TLS.identifier": identifier.to_string(),
            "TLS.app_id": self.app_id,
            "TLS.expire": expire.num_seconds(),
            "TLS.time": dt.timestamp()
        });

        let base64_buf = userbuf.map(|buf| base64::encode_config(buf.as_bytes(), base64::STANDARD));

        if let Some(buf) = base64_buf.clone() {
            dict["TLS.userbuf"] = json!(buf);
        }

        dict["TLS.sig"] = json!(self.hmac_sha256(identifier, dt, expire, base64_buf));
        debug!("raw sig json: {}", dict);

        let sig_compressed = deflate_bytes_zlib_conf(dict.to_string().as_bytes(), Compression::Best);
        debug!("compressed sig: {:?}", &sig_compressed);

        base64::encode_config(&sig_compressed, base64::STANDARD)
    }

    fn hmac_sha256(
        &self,
        identifier: &str,
        curr_time: DateTime<Utc>,
        expire: Duration,
        base64_buf: Option<String>,
    ) -> String {
        let mut raw_content_to_be_signed = format!("TLS.identifier:{}\nTLS.app_id:{}\nTLS.time:{}\nTLS.expire:{}\n", identifier, self.app_id, curr_time.timestamp(), expire.num_seconds()).to_string();

        if let Some(buf) = base64_buf {
            raw_content_to_be_signed.push_str(&format!("TLS.userbuf:{}\n", buf));
        }

        debug!("raw_content_to_be_signed: {}", raw_content_to_be_signed);

        let key = hmac::Key::new(hmac::HMAC_SHA256, self.secret_key.as_bytes());
        let digest = hmac::sign(&key, raw_content_to_be_signed.as_bytes());

        base64::encode_config(digest.as_ref(), base64::STANDARD)
    }
}

/// In case that the secret_key is leaked, we want to update the key at runtime.
pub fn sha256_hex(payload: &str) -> String {
    let payload_digest = ring::digest::digest(&ring::digest::SHA256, payload.as_bytes());
    bytes_to_string(payload_digest.as_ref())
}

pub fn hmac_256(secret_key: Vec<u8>, payload: &str) -> Vec<u8> {
    // 签名字符串...
    debug!("[签名Key十六进制字符串][secret_key.as_bytes(): {:02X?}]", secret_key);
    let secret_key = hmac::Key::new(hmac::HMAC_SHA256, &secret_key);
    let payload_digest = hmac::sign(&secret_key, payload.as_bytes());

    //let digest_bytes = &[0u8];
    //let payload_digest_bytes = payload_digest.as_ref();

    payload_digest.as_ref().to_vec()
}

// 字节转十六进制表示...
pub fn bytes_to_string(hex_bytes: &[u8]) -> String {
    let payload_digest_vec: Vec<String> = hex_bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
    let hashed_request_payload = payload_digest_vec.join("");
    hashed_request_payload
}

#[cfg(test)]
mod test {
    use log::*;
    use super::TencentCloudApi;
    use chrono::{Duration, TimeZone, Utc};

    const MOCK_APP_ID: u64 = 1400000000;
    const MOCK_SECRET_ID: &'static str = "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e";
    const MOCK_SECRET_KEY: &'static str = "balabala...";
    const MOCK_USERBUF: &'static str = "abc";

    fn log_init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_update_key() {
        let mut signer = TencentCloudApi::new(MOCK_APP_ID, "", "");
        assert_eq!(signer.secret_key, "".to_string());

        signer.update_key(MOCK_SECRET_KEY);
        assert_eq!(signer.secret_key, MOCK_SECRET_KEY.to_string());
    }

    #[test]
    fn test_hmac_sha256() {
        log_init();

        // the great moment of the 70th anniversary of the founding of new China!
        // timestamp_millis = 1569910200000
        let mock_curr_time = Utc.ymd(2019, 10, 1).and_hms(6, 10, 0);
        let signer = TencentCloudApi::new(MOCK_APP_ID, MOCK_SECRET_ID, MOCK_SECRET_KEY);
        let mock_base64_buf = Some(MOCK_USERBUF).map(|buf| base64::encode_config(buf.as_bytes(), base64::STANDARD));

        // mock sig generated from python version
        let mock_sig = "CpjuBdQs9ZwnuGAJR8onoOeI9fweX2vIMMY94iOJWJY=";
        let mock_sig_with_buf = "bC3u5cuslSg8Ds7KY58mhSkTrxunrFu50dkdkCYH4i8=";

        assert_eq!(
            &signer.hmac_sha256("0", mock_curr_time, Duration::days(180), None),
            mock_sig
        );
        assert_eq!(
            &signer.hmac_sha256("0", mock_curr_time, Duration::days(180), mock_base64_buf),
            mock_sig_with_buf
        );
    }

    // Ignore for lacking of expect output
    #[test]
    #[ignore]
    fn test_fix_time_sign_generation_no_buf() {
        log_init();

        // the great moment of the 70th anniversary of the founding of new China!
        // timestamp_millis = 1569910200000
        let mock_curr_time = Utc.ymd(2019, 10, 1).and_hms(6, 10, 0);
        let signer = TencentCloudApi::new(MOCK_APP_ID, MOCK_SECRET_ID, MOCK_SECRET_KEY);

        // mock sig generated from python version
        let mock_sig = "eJyrVgrxCdYrSy1SslIy0jNQ0gHzM1NS80oy0zLBwjDB4pTsxIKCzBQlK0MTAyiAyKRWFGQWpQLFTU1NjeCiJZm5YDEzS0tDAyOYaHFmOtBM54KsUqeUwGLLqPK8UndHryCL-Lx8-1RPy7Ty1AijMk9f30hLk0x-r3CvSFulWgAPYy*9";

        assert_eq!(
            &signer.gen_sign_with_time("0", mock_curr_time, Duration::days(180), None),
            mock_sig
        );
    }

    // Ignore for lacking of expect output
    #[test]
    #[ignore]
    fn test_fix_time_sign_generation_with_buf() {
        log_init();

        // the great moment of the 70th anniversary of the founding of new China!
        // timestamp_millis = 1569910200000
        let mock_curr_time = Utc.ymd(2019, 10, 1).and_hms(6, 10, 0);
        let signer = TencentCloudApi::new(MOCK_APP_ID, MOCK_SECRET_ID, MOCK_SECRET_KEY);

        // mock sig generated from python version
        let mock_sig_with_buf = "eJw9zEELwiAcBfDv4jmGs1lu0GkRUd0chMeWbv2zDdEZg*i7J5a92-s9eC-UnHj2VBZViGQYLWIHqcYJOoic0El9MQYkqvIC--Jd1GzAquCUUvLXCYZoq7LMMUnqnbKt78KvOB-u6Rr6AG299PTq3YP3bOvWR0HZcOO6sbMf7c5TLLXUtdgXwDbo-QEmHTZF";
        assert_eq!(
            &signer.gen_sign_with_time(
                "0",
                mock_curr_time,
                Duration::days(180),
                Some(MOCK_USERBUF),
            ),
            mock_sig_with_buf
        );
    }

    #[test]
    fn ring_sha256() {
        // 测试加密串...
        // [Function ring::digest::digest](https://briansmith.org/rustdoc/ring/digest/fn.digest.html)
        use ring::{digest, test};

        // 期望
        let expected_hex = "0118634ada81375203c9396eb9f04458c213d166e45b86f8adbc0d81e8a640ec";
        let expected: Vec<u8> = test::from_hex(expected_hex).unwrap();

        // 参数签名...
        let payload = "{\"Limit\": 1, \"Filters\": [{\"Values\": [\"COAM-1\"], \"Name\": \"instance-name\"}]}";
        let payload_digest = digest::digest(&digest::SHA256, payload.as_bytes());
        assert_eq!(&expected, &payload_digest.as_ref());

        // 字节转二进制
        use std::fmt::Write;

        // 方式一: write!()...
        let payload_digest_bytes: Vec<u8> = payload_digest.as_ref().iter().cloned().collect();
        let mut payload_digest_string = String::new();
        for &byte in payload_digest.as_ref() {
            write!(&mut payload_digest_string, "{:02x} ", byte).expect("Unable to write");
        }
        assert_eq!("01 18 63 4a da 81 37 52 03 c9 39 6e b9 f0 44 58 c2 13 d1 66 e4 5b 86 f8 ad bc 0d 81 e8 a6 40 ec ", payload_digest_string.as_str());

        // 方式二: format!()
        // [Rust: byte array to hex String](http://illegalargumentexception.blogspot.com/2015/05/rust-byte-array-to-hex-string.html)
        // 不同格式[{:02x}]
        let payload_digest_vec: Vec<String> = payload_digest.as_ref().iter().map(|byte| format!("{:02x}", byte)).collect();
        let payload_digest_string = payload_digest_vec.join(" ");
        assert_eq!("01 18 63 4a da 81 37 52 03 c9 39 6e b9 f0 44 58 c2 13 d1 66 e4 5b 86 f8 ad bc 0d 81 e8 a6 40 ec", payload_digest_string);

        // 不同格式[{:x}]
        let payload_digest_vec: Vec<String> = payload_digest.as_ref().iter().map(|byte| format!("{:x}", byte)).collect();
        let payload_digest_string = payload_digest_vec.join(" ");
        assert_eq!("1 18 63 4a da 81 37 52 3 c9 39 6e b9 f0 44 58 c2 13 d1 66 e4 5b 86 f8 ad bc d 81 e8 a6 40 ec", payload_digest_string);

        // 不同格式[{:02X}]
        let payload_digest_vec: Vec<String> = payload_digest.as_ref().iter().map(|byte| format!("{:02X}", byte)).collect();
        let payload_digest_string = payload_digest_vec.join(" ");
        assert_eq!("01 18 63 4A DA 81 37 52 03 C9 39 6E B9 F0 44 58 C2 13 D1 66 E4 5B 86 F8 AD BC 0D 81 E8 A6 40 EC", payload_digest_string);
    }
}
