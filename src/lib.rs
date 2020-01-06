use chrono::{DateTime, Duration, Utc};
use deflate::{deflate_bytes_zlib_conf, Compression};
use log::*;
use ring::hmac;
use serde_json::{json, Value, from_str, to_string, to_value};
use serde::Deserialize;
use std::collections::HashMap;

// reqwest
use reqwest::{Client, StatusCode};
use reqwest::header::{HeaderMap, HeaderValue};

use std::error::Error;
use std::io::{Read, Write};

// 打印请求日志数据...
fn load_response(response: &mut reqwest::Response) -> Result<String, Box<dyn Error>> {
    // 读取到字符串
    let mut content = String::new();
    response.read_to_string(&mut content)?;

    trace!("[TCS-API-RESPONSE-INFO]: \n{:?}", response);
    trace!("[TCS-API-RESPONSE-CONTENT]: \n{}", content);

    // 转化成 Value ...
    //let value: Value = from_str(&content)?;
    //let value: Value = {
    //    if !content.is_empty() {
    //        from_str(&content)?
    //    } else {
    //        to_value(true)?
    //    }
    //};
    //trace!("[TCS-API-RESPONSE-DATA]: \n{}", value);

    Ok(content)
}

// DNS 解析记录
#[derive(Deserialize, Debug, Clone)]
pub struct TcsData {
    pub tcs_region: String,
    pub host_name: String,
    pub instance_name: String,
    pub instance_id: String,
    pub tcs_image_id: String,
    pub password: String,
    pub key_ids: Vec<String>,
}

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

    // 实例列表
    pub fn tcs_describe_instances(&mut self, tcs_data: &TcsData) {
        info!("[######][实例列表][@][tcs_describe_instances()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_image_id = tcs_data.tcs_image_id.as_str();
        let host_name = tcs_data.host_name.as_str();
        let instance_name = tcs_data.instance_name.as_str();
        let instance_id = tcs_data.instance_id.as_str();
        let password = tcs_data.password.as_str();
        let key_ids = tcs_data.key_ids.clone();

        // 配置请求参数...
        let tcs_action = "DescribeInstances";

        // 请求参数
        //let payload = "{\"Limit\": 1, \"Filters\": [{\"Values\": [\"TCS-Instance-0\"], \"Name\": \"instance-name\"}]}";
        let payload = json!({
            "Limit": 1,
            "Filters": [
                {
                    "Values": [instance_name],
                    "Name": "instance-name"
                }
            ]
        });
        info!("[payload: {}]", payload);

        let api_payload = to_string(&payload).unwrap();
        //debug!("[api_payload: {}]", api_payload);

        // 发起请求...
        self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str());
    }

    // 启动实例
    pub fn tcs_start_instances(&mut self, tcs_data: &TcsData) {
        info!("[######][启动实例][@][tcs_start_instances()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_image_id = tcs_data.tcs_image_id.as_str();
        let host_name = tcs_data.host_name.as_str();
        let instance_name = tcs_data.instance_name.as_str();
        let instance_id = tcs_data.instance_id.as_str();
        let password = tcs_data.password.as_str();
        let key_ids = tcs_data.key_ids.clone();

        // 配置请求参数...
        let tcs_action = "StartInstances";

        // 请求参数
        let payload = json!({
            "InstanceIds": [instance_id]
        });
        info!("[payload: {}]", payload);

        let api_payload = to_string(&payload).unwrap();
        //debug!("[api_payload: {}]", api_payload);

        // 发起请求...
        self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str());
    }

    // 关闭实例
    pub fn tcs_stop_instances(&mut self, tcs_data: &TcsData) {
        info!("[######][关闭实例][@][tcs_stop_instances()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_image_id = tcs_data.tcs_image_id.as_str();
        let host_name = tcs_data.host_name.as_str();
        let instance_name = tcs_data.instance_name.as_str();
        let instance_id = tcs_data.instance_id.as_str();
        let password = tcs_data.password.as_str();
        let key_ids = tcs_data.key_ids.clone();

        // 配置请求参数...
        let tcs_action = "StopInstances";

        // 请求参数
        let payload = json!({
            "InstanceIds": [instance_id],
            // 正常关闭失败后是否进行强制关闭
            "ForceStop": false,
            // 实例关闭模式
            //"StopType": "SOFT",
            // 仅支持按量付费云主机...
            //"StoppedMode": "KEEP_CHARGING"
        });
        info!("[payload: {}]", payload);

        let api_payload = to_string(&payload).unwrap();
        //debug!("[api_payload: {}]", api_payload);

        // 发起请求...
        self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str());
    }

    // 重启实例
    pub fn tcs_reboot_instances(&mut self, tcs_data: &TcsData) {
        info!("[######][重启实例][@][tcs_reboot_instances()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_image_id = tcs_data.tcs_image_id.as_str();
        let host_name = tcs_data.host_name.as_str();
        let instance_name = tcs_data.instance_name.as_str();
        let instance_id = tcs_data.instance_id.as_str();
        let password = tcs_data.password.as_str();
        let key_ids = tcs_data.key_ids.clone();

        // 配置请求参数...
        let tcs_action = "RebootInstances";

        // 请求参数
        let payload = json!({
            "InstanceIds": [instance_id],
            // 是否在正常重启失败后选择强制重启实例
            "ForceReboot": false,
            // 实例关闭模式
            //"StopType": "SOFT",
        });
        info!("[payload: {}]", payload);

        let api_payload = to_string(&payload).unwrap();
        //debug!("[api_payload: {}]", api_payload);

        // 发起请求...
        self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str());
    }

    // 重装实例
    pub fn tcs_reset_instance(&mut self, tcs_data: &TcsData) {
        info!("[######][重装实例][@][tcs_reset_instance()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_image_id = tcs_data.tcs_image_id.as_str();
        let host_name = tcs_data.host_name.as_str();
        let instance_name = tcs_data.instance_name.as_str();
        let instance_id = tcs_data.instance_id.as_str();
        let password = tcs_data.password.as_str();
        let key_ids = tcs_data.key_ids.clone();

        // 配置请求参数...
        let tcs_action = "ResetInstance";

        // 请求参数
        let payload = json!({
            "HostName": host_name,
            "InstanceId": instance_id,
            "ImageId": tcs_image_id,
            "LoginSettings": {
                "Password": password,
                //"KeyIds": key_ids
            },
            "EnhancedService": {
                "SecurityService":{
                    "Enabled":false
                },
                "MonitorService":{
                    "Enabled":false
                }
            },
        });
        info!("[payload: {}]", payload);

        let api_payload = to_string(&payload).unwrap();
        //debug!("[api_payload: {}]", api_payload);

        // 发起请求...
        self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str());
    }

    // 查看镜像列表
    pub fn tcs_describe_images(&mut self, tcs_data: &TcsData) {
        info!("[######][查看镜像列表][@][tcs_describe_images()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_image_id = tcs_data.tcs_image_id.as_str();
        let host_name = tcs_data.host_name.as_str();
        let instance_name = tcs_data.instance_name.as_str();
        let instance_id = tcs_data.instance_id.as_str();
        let password = tcs_data.password.as_str();
        let key_ids = tcs_data.key_ids.clone();

        // 配置请求参数...
        let tcs_action = "DescribeImages";

        // 请求参数
        let payload = json!({
            "Limit": 100,
        });
        info!("[payload: {}]", payload);

        let api_payload = to_string(&payload).unwrap();
        //debug!("[api_payload: {}]", api_payload);

        // 发起请求...
        self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str());
    }

    // 发起请求
    pub fn tcs_request_api(&mut self, tcs_action: &str, tcs_region: &str, api_payload: &str) -> Result<String, Box<dyn Error>> {
        info!("[@@@@@@][发起请求][tcs_request_api()][tcs_action: {}][tcs_region: {}][api_payload: {}]", tcs_action, tcs_region, api_payload);

        // 初始化请求参数
        let tcs_host = "cvm.tencentcloudapi.com";
        let tcs_service = "cvm";
        let tcs_version = "2017-03-12";

        // 获取记录调用时间...
        let mut request_time = chrono::Local::now();
        let mut request_ts = request_time.timestamp();
        let mut request_date = request_time.format("%Y-%m-%d").to_string();
        // 请求参数格式...
        let request_ct = "application/json; charset=utf-8";
        let request_ct = "application/json";

        // 测试对比时间...
        //let request_ts = 1573009278;
        //let request_date = "2019-11-06".to_string();
        debug!("[TIME]][request_ts: {:?}][request_date: {:?}]", request_ts, request_date);

        // 计算签名...
        let authorization = self.request_tcs_signer(tcs_host, tcs_region, tcs_action, tcs_service, api_payload, request_ct, request_ts, request_date.as_str());

        let curl = format!("{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}", "curl -X POST https://", tcs_host, " -H \"Authorization: ", authorization, "\"", " -H \"Content-Type: ", request_ct, "\"", " -H \"Host: ", tcs_host, "\"", " -H \"X-TC-Action: ", tcs_action, "\"", " -H \"X-TC-Timestamp: ", request_ts, "\"", " -H \"X-TC-Version: ", tcs_version, "\"", " -H \"X-TC-Region: ", tcs_region, "\"", " -d '", api_payload, "'");
        info!("[curl: ]\n{}", curl);

        // 使用POST请求
        // 添加 [application/jose+json] 请求头
        let mut headers = HeaderMap::new();
        //headers.set(ContentType::json());
        headers.insert("Authorization", authorization.parse().unwrap());
        headers.insert("Content-Type", request_ct.parse().unwrap());
        headers.insert("Host", tcs_host.parse().unwrap());
        headers.insert("X-TC-Action", tcs_action.parse().unwrap());
        headers.insert("X-TC-Timestamp", format!("{}", request_ts).parse().unwrap());
        headers.insert("X-TC-Version", tcs_version.parse().unwrap());
        headers.insert("X-TC-Region", tcs_region.parse().unwrap());

        // Parse the string of data into serde_json::Value.
        let api_payload_value: Value = serde_json::from_str(api_payload)?;

        // 请求TCS服务 - 请求接口...
        let client = Client::new();
        let url = (String::from("https://") + tcs_host);
        //let url = "https://www.nocs.cn/service/requestToken";
        let mut response = client.post(url.as_str())
            //.json(&payload_json)
            //.json(&payload_value)
            .headers(headers)
            .body(api_payload.to_string())
            .send()?;

        // 处理 TCS 响应数据...
        let response_content = load_response(&mut response)?;

        Ok("tcs_request_api_successful".to_string())
    }

    // 设置签名
    // [接口鉴权 v3](https://cloud.tencent.com/document/api/213/30654)
    pub fn request_tcs_signer(&mut self, tcs_host: &str, tcs_region: &str, tcs_action: &str, tcs_service: &str, api_payload: &str, request_ct: &str, request_ts: i64, request_date: &str) -> String {
        debug!("[接口签名][request_tcs_signer()][tcs_host: {}][tcs_region: {}][tcs_action: {}][tcs_service: {}][api_payload: {}][request_ct: {}][request_ts: {}][request_date: {}]", tcs_host, tcs_region, tcs_action, tcs_service, api_payload, request_ct, request_ts, request_date);

        // 签名算法...
        let tcs_algorithm = "TC3-HMAC-SHA256";

        // ************* 步骤 1：拼接规范请求串 *************
        let request_method = "POST";
        let request_uri = "/";
        let request_qs = "";
        let request_headers = format!("{}{}{}{}{}{}", "content-type:", request_ct, "\n", "host:", tcs_host, "\n");
        let request_headers_signed_data = "content-type;host";

        // 参数签名...
        let api_payload_sha256 = sha256_hex(api_payload);
        //debug!("[api_payload_sha256: ]\n{}", api_payload_sha256);

        let request_canonical = format!("{}{}{}{}{}{}{}{}{}{}{}", request_method, "\n", request_uri, "\n", request_qs, "\n", request_headers, "\n", request_headers_signed_data, "\n", api_payload_sha256);
        //debug!("[request_canonical: ]\n{}", request_canonical);

        // ************* 步骤 2：拼接待签名字符串 *************
        let request_credential_scope = format!("{}{}{}{}{}", request_date, "/", tcs_service, "/", "tc3_request");
        let request_canonical_sha256 = sha256_hex(request_canonical.as_str());
        let request_canonical_data = format!("{}{}{}{}{}{}{}", tcs_algorithm, "\n", request_ts, "\n", request_credential_scope, "\n", request_canonical_sha256);
        //debug!("[request_canonical_data: ]\n{}", request_canonical_data);

        // ************* 步骤 3：计算签名 *************
        let tcs_secret_key = format!("TC3{}", self.secret_key);
        //debug!("[tcs_secret_key: ]\n{:?}\n{:02X?}", tcs_secret_key, tcs_secret_key.as_bytes());

        let request_tcs_secret_date_hmac = hmac_256(tcs_secret_key.as_bytes().to_vec(), request_date);
        //debug!("[request_tcs_secret_date_hmac: ]\n{:02X?}", request_tcs_secret_date_hmac);

        let request_tcs_secret_date_service_hmac = hmac_256(request_tcs_secret_date_hmac, tcs_service);
        //debug!("[request_tcs_secret_date_service_hmac: ]\n{:02X?}", request_tcs_secret_date_service_hmac);

        let request_tcs_secret_date_service_tc3_hmac = hmac_256(request_tcs_secret_date_service_hmac, "tc3_request");
        //debug!("[request_tcs_secret_date_service_tc3_hmac: ]\n{:02X?}", request_tcs_secret_date_service_tc3_hmac);

        let request_tcs_secret_date_service_tc3_canonical_hmac = hmac_256(request_tcs_secret_date_service_tc3_hmac, request_canonical_data.as_str());
        //debug!("[request_tcs_secret_date_service_tc3_canonical_hmac: ]\n{:02x?}", request_tcs_secret_date_service_tc3_canonical_hmac);

        let request_tc3_canonical_signature = bytes_to_string(&request_tcs_secret_date_service_tc3_canonical_hmac);
        //debug!("[request_tc3_canonical_signature: ]\n{:?}", request_tc3_canonical_signature);

        // ************* 步骤 4：拼接 Authorization *************
        let authorization = format!("{}{}{}{}{}{}{}{}{}{}{}{}", tcs_algorithm, " ", "Credential=", self.secret_id, "/", request_credential_scope, ", ", "SignedHeaders=", request_headers_signed_data, ", ", "Signature=", request_tc3_canonical_signature);
        debug!("[authorization: ]\n{}", authorization);

        authorization
    }
}

/// In case that the secret_key is leaked, we want to update the key at runtime.
pub fn sha256_hex(payload: &str) -> String {
    let payload_digest = ring::digest::digest(&ring::digest::SHA256, payload.as_bytes());
    bytes_to_string(payload_digest.as_ref())
}

pub fn hmac_256(secret_key: Vec<u8>, payload: &str) -> Vec<u8> {
    // 签名字符串...
    //debug!("[签名Key十六进制字符串][secret_key.as_bytes(): {:02X?}]", secret_key);

    // [0.16.9]
    //let secret_key = hmac::Key::new(hmac::HMAC_SHA256, &secret_key);
    // [0.13.5]
    let secret_key = hmac::SigningKey::new(&ring::digest::SHA256, &secret_key);

    let payload_digest = hmac::sign(&secret_key, payload.as_bytes());

    //let digest_bytes = &[0u8];
    //let payload_digest_bytes = payload_digest.as_ref();

    payload_digest.as_ref().to_vec()
}

// 字节转十六进制表示...
pub fn bytes_to_string(data_bytes: &[u8]) -> String {
    let data_vec: Vec<String> = data_bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
    data_vec.join("")
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
