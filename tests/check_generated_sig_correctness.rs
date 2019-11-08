use chrono::Duration;
use dotenv::{dotenv, var};
use log::*;
use rand::prelude::*;
use reqwest::Client;
use std::collections::HashMap;
use tcs_client::TencentCloudApi;

#[test]
fn check_generated_sig_correctness() {
    let _ = env_logger::builder().is_test(true).try_init();

    let env = dotenv().expect("Error occurs when processing .dotenv file!");
    trace!("Environments loaded from {:?}.", env);

    let app_id = var("TEST_APP_ID").map(|id_str| id_str.parse::<u64>().expect("Appid ParseError: Not a Int!")).expect("No test app_id configured!");
    let secret_id = var("TEST_APP_SECRET_ID").expect("No test app secret_id configured!");
    let secret_key = var("TEST_APP_SECRET_KEY").expect("No test app secret_key configured!");
    let admin = var("TEST_APP_ADMIN").expect("No test app administrator configured!");

    trace!(
        "Test Environments got: app_id: {}, secret_id: {}, secret_key: {}, admin: {}.",
        app_id,
        secret_id,
        secret_key,
        admin
    );
    let sig_api = TencentCloudApi::new(app_id, &secret_id, &secret_key);

    let admin_sig = sig_api.gen_sign(&admin, Duration::hours(10), None);
    trace!("generated admin_sig: {}", admin_sig);

    let r = random::<u32>();

    let url = format!("https://console.tim.qq.com/v4/im_open_login_svc/account_import?sdkapp_id={}&identifier={}&usersig={}&random={}&contenttype=json", app_id, admin, admin_sig, r).to_string();
    trace!("concated url: {}", url);

    let mut map = HashMap::new();
    map.insert("Identifier", "test");

    let client = Client::new();
    let res = client
        .post(&url)
        .json(&map)
        .send()
        .expect("Sending Request failed!")
        .text()
        .expect("Reading Content failed!");
    trace!("Get respone: {}", res);

    assert!(res.contains(r#""ActionStatus":"OK""#));
}