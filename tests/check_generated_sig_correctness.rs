use chrono::Duration;
use dotenv::{dotenv, var};
use log::*;
use rand::prelude::*;
use reqwest::Client;
use std::collections::HashMap;
use tcs_client::TencentCloudApi;