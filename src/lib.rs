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
    pub tcs_title: String,
    pub tcs_region: String,
    pub tcs_zone: String,
    pub host_name: String,
    pub instance_name: String,
    pub instance_id: String,
    pub tcs_image_id: String,
    pub password: String,
    pub key_ids: Vec<String>,
    pub tcs_info: TcsInfo,
}

// DNS 解析记录
#[derive(Deserialize, Debug, Clone)]
pub struct TcsInfo {
    pub instance_charge_type: String,
    pub instance_cpu: i32,
    pub instance_memory: i32,
    pub max_unit_price: f32,
}

// DNS 解析记录
#[derive(Deserialize, Debug, Clone)]
pub struct TcsResponse {
    #[serde(rename = "Response")]
    pub response: Value,
}

// DNS 解析记录
#[derive(Deserialize, Debug, Clone)]
pub struct TcsResponseError {
    #[serde(rename = "RequestId")]
    pub request_id: String,
    #[serde(rename = "Error")]
    pub error: TcsApiError,
}

// DNS 解析记录
#[derive(Deserialize, Debug, Clone)]
pub struct TcsApiError {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
}

// DNS 解析记录
#[derive(Deserialize, Debug, Clone)]
pub struct TcsResponseZoneInstanceConfig {
    #[serde(rename = "RequestId")]
    pub request_id: String,
    #[serde(rename = "InstanceTypeQuotaSet")]
    pub instance_type_quota_set: Vec<TcsInstanceTypeQuota>,
}

// DNS 解析记录
#[derive(Deserialize, Debug, Clone)]
pub struct TcsInstanceTypeQuota {
    #[serde(rename = "Zone")]
    pub zone: String,
    #[serde(rename = "InstanceType")]
    pub instance_type: String,
    #[serde(rename = "InstanceChargeType")]
    pub instance_charge_type: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Cpu")]
    pub cpu: i32,
    #[serde(rename = "Memory")]
    pub memory: i32,
    #[serde(rename = "InstanceFamily")]
    pub instance_family: String,
    #[serde(rename = "TypeName")]
    pub type_name: String,
    #[serde(rename = "Price")]
    pub price: TcsInstanceTypeQuotaPrice,
}

// DNS 解析记录
#[derive(Deserialize, Debug, Clone)]
pub struct TcsInstanceTypeQuotaPrice {
    #[serde(rename = "UnitPrice")]
    pub unit_price: f32,
    #[serde(rename = "UnitPriceDiscount")]
    pub unit_price_discount: f32,
    #[serde(rename = "Discount")]
    pub discount: u8,
    #[serde(rename = "ChargeUnit")]
    pub charge_unit: String,
}

// DNS 解析记录
#[derive(Deserialize, Debug, Clone)]
pub struct TcsResponseDescribeInstanceStatus {
    #[serde(rename = "RequestId")]
    pub request_id: String,
    #[serde(rename = "TotalCount")]
    pub total_count: u8,
    #[serde(rename = "InstanceStatusSet")]
    pub instance_status_set: Vec<TcsInstanceStatus>,
}

// DNS 解析记录
#[derive(Deserialize, Debug, Clone)]
pub struct TcsInstanceStatus {
    #[serde(rename = "InstanceId")]
    pub instance_id: String,
    #[serde(rename = "InstanceState")]
    pub instance_state: String,
}

// DNS 解析记录
#[derive(Deserialize, Debug, Clone)]
pub struct TcsResponseDescribeInstance {
    #[serde(rename = "RequestId")]
    pub request_id: String,
    #[serde(rename = "InstanceSet")]
    pub instance_set: Vec<TcsInstanceInfo>,
}

// DNS 解析记录
#[derive(Deserialize, Debug, Clone)]
pub struct TcsInstanceInfo {
    #[serde(rename = "InstanceId")]
    pub instance_id: String,
    #[serde(rename = "InstanceName")]
    pub instance_name: String,
    #[serde(rename = "InstanceType")]
    pub instance_type: String,
    #[serde(rename = "InstanceChargeType")]
    pub instance_charge_type: String,
    #[serde(rename = "InstanceState")]
    pub instance_state: String,
    #[serde(rename = "CPU")]
    pub cpu: i32,
    #[serde(rename = "Memory")]
    pub memory: i32,
    #[serde(rename = "ImageId")]
    pub image_id: Option<String>,
    #[serde(rename = "OsName")]
    pub os_name: String,
    #[serde(rename = "RestrictState")]
    pub restrict_state: String,
    #[serde(rename = "SystemDisk")]
    pub system_disk: DiskInfo,
    #[serde(rename = "DataDisks")]
    pub data_disks: Option<Vec<DiskInfo>>,
    #[serde(rename = "PrivateIpAddresses")]
    pub private_ip_addresses: Option<Vec<String>>,
    #[serde(rename = "PublicIpAddresses")]
    pub public_ip_addresses: Option<Vec<String>>,
}

// DNS 解析记录
#[derive(Deserialize, Debug, Clone)]
pub struct DiskInfo {
    #[serde(rename = "DiskType")]
    pub disk_type: String,
    #[serde(rename = "DiskId")]
    pub disk_id: Option<String>,
    #[serde(rename = "DiskSize")]
    pub disk_size: u16,
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
    pub fn tcs_describe_instance_list(&mut self, tcs_data: &TcsData) -> Result<TcsResponseDescribeInstance, Box<dyn Error>> {
        info!("[######][实例列表][@][tcs_describe_instance_list()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_title = tcs_data.tcs_title.as_str();
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_zone = tcs_data.tcs_zone.as_str();
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
            "Limit": 100
        });
        info!("[payload: {}]", payload);

        let api_payload = to_string(&payload).unwrap();
        //debug!("[api_payload: {}]", api_payload);

        // 发起请求...
        return match self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str()) {
            Result::Ok(tcs_response_data) => {
                debug!("[tcs_response_data: {}]", tcs_response_data);

                // 解析为机型对象...
                let tcs_response_data: TcsResponseDescribeInstance = serde_json::from_str(&tcs_response_data)?;
                // info!("[tcs_response_data: {:?}]", tcs_response_data);

                return Ok(tcs_response_data);
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                Result::Err("请求失败(..)!".into())
            }
        };
    }

    // 实例详情
    pub fn tcs_describe_instance_info(&mut self, tcs_data: &TcsData) -> Result<Option<TcsInstanceInfo>, Box<dyn Error>> {
        info!("[######][实例列表][@][tcs_describe_instance_info()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_title = tcs_data.tcs_title.as_str();
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_zone = tcs_data.tcs_zone.as_str();
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
            "Limit": 10,
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
        return match self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str()) {
            Result::Ok(tcs_response_data) => {
                debug!("[tcs_response_data: {}]", tcs_response_data);

                // 解析为机型对象...
                let tcs_response_data: TcsResponseDescribeInstance = serde_json::from_str(&tcs_response_data)?;
                // info!("[tcs_response_data: {:?}]", tcs_response_data);

                // 过滤实例...
                let mut instance_set = tcs_response_data.instance_set;

                // 如果没有满足的实例
                if instance_set.is_empty() {
                    return Ok(None);
                }

                return Ok(Some(instance_set.first().unwrap().clone()));
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                Result::Err("请求失败(..)!".into())
            }
        };
    }

    // 实例列表
    pub fn tcs_describe_instance_status(&mut self, tcs_data: &TcsData) -> Result<TcsResponseDescribeInstanceStatus, Box<dyn Error>> {
        info!("[######][实例列表][@][describe_instances_status()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_title = tcs_data.tcs_title.as_str();
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_zone = tcs_data.tcs_zone.as_str();
        let tcs_image_id = tcs_data.tcs_image_id.as_str();
        let host_name = tcs_data.host_name.as_str();
        let instance_name = tcs_data.instance_name.as_str();
        let instance_id = tcs_data.instance_id.as_str();
        let password = tcs_data.password.as_str();
        let key_ids = tcs_data.key_ids.clone();

        // 配置请求参数...
        let tcs_action = "DescribeInstancesStatus";

        // 请求参数
        //let payload = "{\"Limit\": 1, \"Filters\": [{\"Values\": [\"TCS-Instance-0\"], \"Name\": \"instance-name\"}]}";
        let payload = json!({
            "Limit": 100,
        });
        info!("[payload: {}]", payload);

        let api_payload = to_string(&payload).unwrap();
        //debug!("[api_payload: {}]", api_payload);

        // 发起请求...
        return match self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str()) {
            Result::Ok(tcs_response_data) => {
                debug!("[tcs_response_data: {}]", tcs_response_data);

                // 解析为机型对象...
                let tcs_response_data: TcsResponseDescribeInstanceStatus = serde_json::from_str(&tcs_response_data)?;
                info!("[tcs_response_data: {:?}]", tcs_response_data);

                // // 过滤机型...
                // let mut instance_status_set = tcs_response_data.instance_status_set;
                // if !instance_status_set.is_empty() {
                //     return Ok(instance_status_set.first().unwrap().clone());
                // }
                //Result::Err("请求成功,但无实例!".into())

                return Ok(tcs_response_data);
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                Result::Err("请求失败(..)!".into())
            }
        };
    }

    // 可用机型列表
    pub fn tcs_describe_zone_instance_config_infos(&mut self, tcs_data: &TcsData) -> Result<String, Box<dyn Error>> {
        info!("[######][可用机型列表][@][tcs_describe_zone_instance_config_infos()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_title = tcs_data.tcs_title.as_str();
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_zone = tcs_data.tcs_zone.as_str();
        let tcs_image_id = tcs_data.tcs_image_id.as_str();
        let host_name = tcs_data.host_name.as_str();
        let instance_name = tcs_data.instance_name.as_str();
        let instance_id = tcs_data.instance_id.as_str();
        let password = tcs_data.password.as_str();
        let key_ids = tcs_data.key_ids.clone();
        let tcs_info = tcs_data.tcs_info.clone();
        let tcs_instance_charge_type = tcs_info.instance_charge_type;
        let tcs_instance_cpu = tcs_info.instance_cpu;
        let tcs_instance_memory = tcs_info.instance_memory;
        let tcs_max_unit_price = tcs_info.max_unit_price;

        // 配置请求参数...
        let tcs_action = "DescribeZoneInstanceConfigInfos";

        // 请求参数
        let payload = json!({
            "Filters": [
                {
                    "Values": [tcs_zone],
                    "Name": "zone"
                },
//                {
//                    "Values": ["S2.LARGE8"],
//                    "Name": "instance-family"
//                },
                {
                    "Values": [tcs_instance_charge_type],
                    "Name": "instance-charge-type"
                }
            ]
        });
        info!("[payload: {}]", payload);

        let api_payload = to_string(&payload).unwrap();
        //debug!("[api_payload: {}]", api_payload);

        // 发起请求...
        return match self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str()) {
            Result::Ok(tcs_response_data) => {
                debug!("[tcs_response_data: {}]", tcs_response_data);

                // 解析为机型对象...
                //let tcs_response_data: TcsResponseZoneInstanceConfig = serde_json::from_str(&tcs_response_data)?; //info!("[tcs_response_data: {:?}]", tcs_response_data);

                Ok("请求成功!".to_string())
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                Result::Err("请求失败(..)!".into())
            }
        };
    }

    // 可用机型列表
    pub fn tcs_get_zone_instance_info(&mut self, tcs_data: &TcsData) -> Result<TcsInstanceTypeQuota, Box<dyn Error>> {
        info!("[######][可用机型列表][@][tcs_describe_zone_instance_config_infos()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_title = tcs_data.tcs_title.as_str();
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_zone = tcs_data.tcs_zone.as_str();
        let tcs_image_id = tcs_data.tcs_image_id.as_str();
        let host_name = tcs_data.host_name.as_str();
        let instance_name = tcs_data.instance_name.as_str();
        let instance_id = tcs_data.instance_id.as_str();
        let password = tcs_data.password.as_str();
        let key_ids = tcs_data.key_ids.clone();
        let tcs_info = tcs_data.tcs_info.clone();
        let tcs_instance_charge_type = tcs_info.instance_charge_type;
        let tcs_instance_cpu = tcs_info.instance_cpu;
        let tcs_instance_memory = tcs_info.instance_memory;
        let tcs_max_unit_price = tcs_info.max_unit_price;

        // 配置请求参数...
        let tcs_action = "DescribeZoneInstanceConfigInfos";

        // 请求参数
        let payload = json!({
            "Filters": [
                {
                    "Values": [tcs_zone],
                    "Name": "zone"
                },
//                {
//                    "Values": ["S2.LARGE8"],
//                    "Name": "instance-family"
//                },
                {
                    "Values": [tcs_instance_charge_type],
                    "Name": "instance-charge-type"
                }
            ]
        });
        info!("[payload: {}]", payload);

        let api_payload = to_string(&payload).unwrap();
        //debug!("[api_payload: {}]", api_payload);

        // 发起请求...
        return match self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str()) {
            Result::Ok(tcs_response_data) => {
                // debug!("[tcs_response_data: {}]", tcs_response_data);

                // 解析为机型对象...
                let tcs_response_data: TcsResponseZoneInstanceConfig = serde_json::from_str(&tcs_response_data)?;

                info!("[tcs_response_data: {:?}]", tcs_response_data);

                // 过滤机型...
                let mut instance_type_quota_set: Vec<TcsInstanceTypeQuota> = tcs_response_data.instance_type_quota_set;
                info!("[筛选可以机型][tcs_instance_cpu: {:?}][tcs_instance_memory: {:?}][status: SELL][tcs_max_unit_price: {:?}]", tcs_instance_cpu, tcs_instance_memory, tcs_max_unit_price);
                if !instance_type_quota_set.is_empty() {
                    instance_type_quota_set.retain(|x| x.cpu >= tcs_instance_cpu && x.memory >= tcs_instance_memory && x.status == "SELL" && x.price.unit_price_discount <= tcs_max_unit_price);
                    if !instance_type_quota_set.is_empty() {
                        return Ok(instance_type_quota_set.first().unwrap().clone());
                    }
                }

                Result::Err("请求成功,但无适配机型!".into())
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                Result::Err("请求失败(..)!".into())
            }
        };
    }

    // 创建实例
    pub fn tcs_run_instances(&mut self, tcs_data: &TcsData) -> Result<String, Box<dyn Error>> {
        info!("[######][创建实例][@][tcs_run_instances()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_title = tcs_data.tcs_title.as_str();
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_zone = tcs_data.tcs_zone.as_str();
        let tcs_image_id = tcs_data.tcs_image_id.as_str();
        let host_name = tcs_data.host_name.as_str();
        let instance_name = tcs_data.instance_name.as_str();
        let instance_id = tcs_data.instance_id.as_str();
        let password = tcs_data.password.as_str();
        let key_ids = tcs_data.key_ids.clone();
        let tcs_info = tcs_data.tcs_info.clone();
        let tcs_instance_charge_type = tcs_info.instance_charge_type;
        let tcs_instance_cpu = tcs_info.instance_cpu;
        let tcs_instance_memory = tcs_info.instance_memory;
        let tcs_max_unit_price = tcs_info.max_unit_price;

        // 验证实例是否已创建...
        // 查询实例数据 - 可用实例列表...
        match self.tcs_describe_instance_info(&tcs_data) {
            Result::Ok(tcs_response_data) => {
                // info!("[tcs_response_data: {:?}]", tcs_response_data);
                if let Some(_) = tcs_response_data {
                    return Result::Err("创建失败(实例已存在)!".into());
                }
            }
            Result::Err(err) => {
                warn!("[tcs_request_data][err: {}]", err);
                return Result::Err("请求失败,请稍后尝试!".into());
            }
        };

        // 挑选机型 - 可用机型列表...
        let tcs_instance_info: TcsInstanceTypeQuota = match self.tcs_get_zone_instance_info(&tcs_data) {
            Result::Ok(tcs_response_data) => {
                info!("[tcs_response_data: {:?}]", tcs_response_data);
                tcs_response_data
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                return Result::Err("请求失败(暂无可用机型)!".into());
            }
        };

        // 机型信息
        let instance_type = tcs_instance_info.instance_type;
        let instance_charge_type = tcs_instance_info.instance_charge_type;

        // 配置请求参数...
        let tcs_action = "RunInstances";

        // 请求参数
        let payload = json!({
            "Placement": {
                "Zone": tcs_zone
            },
            "InstanceChargeType": tcs_instance_charge_type,
            "InstanceType": instance_type,
            "SystemDisk": {
                "DiskType": "CLOUD_PREMIUM",
                "DiskSize": 50
            },
            "DataDisks": [
                {
                    "DiskType": "CLOUD_PREMIUM",
                    "DiskSize": 10,
                }
            ],
            "InternetAccessible": {
                "InternetChargeType": "TRAFFIC_POSTPAID_BY_HOUR",
                "InternetMaxBandwidthOut": 10,
                "PublicIpAssigned": true,
            },
            "InstanceName": instance_name,
            "ImageId": tcs_image_id,
            "InstanceMarketOptions": {
                "SpotOptions": {
                    "MaxPrice": format!{"{}", tcs_max_unit_price},
                    "SpotInstanceType": "one-time"
                },
                "MarketType": "spot"
            },
            "LoginSettings": {
                "Password": password,
                //"KeyIds": key_ids
            },
            "EnhancedService": {
                "SecurityService": {
                    "Enabled": false
                },
                "MonitorService": {
                    "Enabled": false
                }
            },
            "InstanceCount": 1
        });
        info!("[payload: {}]", payload);

        let api_payload = to_string(&payload).unwrap();
        //debug!("[api_payload: {}]", api_payload);

        // 发起请求...
        return match self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str()) {
            Result::Ok(tcs_response_data) => {
                debug!("[tcs_response_data: {}]", tcs_response_data);
                Ok("请求成功!".to_string())
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                Result::Err("请求失败(..)!".into())
            }
        };
    }

    // 退还实例
    pub fn tcs_terminate_instances(&mut self, tcs_data: &TcsData) -> Result<String, Box<dyn Error>> {
        info!("[######][退还实例][@][tcs_terminate_instances()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_title = tcs_data.tcs_title.as_str();
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_zone = tcs_data.tcs_zone.as_str();
        let tcs_image_id = tcs_data.tcs_image_id.as_str();
        let host_name = tcs_data.host_name.as_str();
        let instance_name = tcs_data.instance_name.as_str();
        let instance_id = tcs_data.instance_id.as_str();
        let password = tcs_data.password.as_str();
        let key_ids = tcs_data.key_ids.clone();

        // 查询实例数据 - 可用实例列表...
        let tcs_instance_info: TcsInstanceInfo = match self.tcs_describe_instance_info(&tcs_data) {
            Result::Ok(tcs_response_data) => {
                // info!("[tcs_response_data: {:?}]", tcs_response_data);
                if let Some(tcs_instance_info) = tcs_response_data {
                    tcs_instance_info
                } else {
                    return Result::Err("退还失败:实例不存在!".into());
                }
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                return Result::Err("请求失败(..)!".into());
            }
        };

        // 实例信息
        let instance_id = tcs_instance_info.instance_id;
        let instance_name = tcs_instance_info.instance_name;
        let instance_charge_type = tcs_instance_info.instance_charge_type;

        // 配置请求参数...
        let tcs_action = "TerminateInstances";

        // 禁止退还包年包月示例
        let ins_list = vec!["ins-288qdetp", "ins-94c9ohbj", "ins-33r57jmx"];
        if ins_list.contains(&instance_id.as_str()) {
            error!("{}", "禁止退还包年包月实例!");
            return Result::Err("请求不合法(..)!".into());
        }

        // 严禁删除包年包月实例
        let ins_list = vec!["PREPAID"];
        if ins_list.contains(&instance_charge_type.as_str()) {
            error!("{}", "禁止销毁包年包月实例!");
            return Result::Err("请求不合法(..)!".into());
        }

        // 请求参数
        let payload = json!({
            "InstanceIds": [instance_id]
        });
        info!("[payload: {}]", payload);

        let api_payload = to_string(&payload).unwrap();
        //debug!("[api_payload: {}]", api_payload);

        // 发起请求...
        return match self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str()) {
            Result::Ok(tcs_response_data) => {
                debug!("[tcs_response_data: {}]", tcs_response_data);

                // 解析为机型对象...
                //let tcs_response_data: TcsResponseZoneInstanceConfig = serde_json::from_str(&tcs_response_data)?;
                // info!("[tcs_response_data: {:?}]", tcs_response_data);

                Ok("请求成功!".to_string())
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                Result::Err("请求失败(..)!".into())
            }
        };
    }

    // 启动实例
    pub fn tcs_start_instances(&mut self, tcs_data: &TcsData) -> Result<String, Box<dyn Error>> {
        info!("[######][启动实例][@][tcs_start_instances()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_title = tcs_data.tcs_title.as_str();
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_zone = tcs_data.tcs_zone.as_str();
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
        return match self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str()) {
            Result::Ok(tcs_response_data) => {
                debug!("[tcs_response_data: {}]", tcs_response_data);
                Ok("请求成功!".to_string())
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                Result::Err("请求失败(..)!".into())
            }
        };
    }

    // 关闭实例
    pub fn tcs_stop_instances(&mut self, tcs_data: &TcsData) -> Result<String, Box<dyn Error>> {
        info!("[######][关闭实例][@][tcs_stop_instances()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_title = tcs_data.tcs_title.as_str();
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_zone = tcs_data.tcs_zone.as_str();
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
        return match self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str()) {
            Result::Ok(tcs_response_data) => {
                debug!("[tcs_response_data: {}]", tcs_response_data);
                Ok("请求成功!".to_string())
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                Result::Err("请求失败(..)!".into())
            }
        };
    }

    // 重启实例
    pub fn tcs_reboot_instances(&mut self, tcs_data: &TcsData) -> Result<String, Box<dyn Error>> {
        info!("[######][重启实例][@][tcs_reboot_instances()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_title = tcs_data.tcs_title.as_str();
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_zone = tcs_data.tcs_zone.as_str();
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
        return match self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str()) {
            Result::Ok(tcs_response_data) => {
                debug!("[tcs_response_data: {}]", tcs_response_data);
                Ok("请求成功!".to_string())
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                Result::Err("请求失败(..)!".into())
            }
        };
    }

    // 重装实例
    pub fn tcs_reset_instance(&mut self, tcs_data: &TcsData) -> Result<String, Box<dyn Error>> {
        info!("[######][重装实例][@][tcs_reset_instance()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_title = tcs_data.tcs_title.as_str();
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_zone = tcs_data.tcs_zone.as_str();
        let tcs_image_id = tcs_data.tcs_image_id.as_str();
        let host_name = tcs_data.host_name.as_str();
        let instance_name = tcs_data.instance_name.as_str();
        let instance_id = tcs_data.instance_id.as_str();
        let password = tcs_data.password.as_str();
        let key_ids = tcs_data.key_ids.clone();

        // 查询实例数据 - 可用实例列表...
        let tcs_instance_info: TcsInstanceInfo = match self.tcs_describe_instance_info(&tcs_data) {
            Result::Ok(tcs_response_data) => {
                // info!("[tcs_response_data: {:?}]", tcs_response_data);
                if let Some(tcs_instance_info) = tcs_response_data {
                    tcs_instance_info
                } else {
                    return Result::Err("重置失败:实例不存在!".into());
                }
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                return Result::Err("请求失败(..)!".into());
            }
        };

        // 实例信息
        let instance_id = tcs_instance_info.instance_id;
        let instance_name = tcs_instance_info.instance_name;
        let instance_charge_type = tcs_instance_info.instance_charge_type;

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
        return match self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str()) {
            Result::Ok(tcs_response_data) => {
                debug!("[tcs_response_data: {}]", tcs_response_data);
                Ok("请求成功!".to_string())
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                Result::Err("请求失败(..)!".into())
            }
        };
    }

    // 查看镜像列表
    pub fn tcs_describe_images(&mut self, tcs_data: &TcsData) -> Result<String, Box<dyn Error>> {
        info!("[######][查看镜像列表][@][tcs_describe_images()][tcs_data: {:?}]", tcs_data);

        // 获取 TCS 配置数据...
        let tcs_title = tcs_data.tcs_title.as_str();
        let tcs_region = tcs_data.tcs_region.as_str();
        let tcs_zone = tcs_data.tcs_zone.as_str();
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
        return match self.tcs_request_api(tcs_action, tcs_region, api_payload.as_str()) {
            Result::Ok(tcs_response_data) => {
                debug!("[tcs_response_data: {}]", tcs_response_data);
                Ok("请求成功!".to_string())
            }
            Result::Err(err) => {
                error!("[tcs_request_err: {:?}]", err);
                Result::Err("请求失败(..)!".into())
            }
        };
    }

    // 发起请求
    pub fn tcs_request_api(&mut self, tcs_action: &str, tcs_region: &str, api_payload: &str) -> Result<String, TcsApiError> {
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
        let api_payload_value: Value = serde_json::from_str(api_payload).unwrap();

        // 请求TCS服务 - 请求接口...
        let client = Client::new();
        let url = (String::from("https://") + tcs_host);
        //let url = "https://www.nocs.cn/service/requestToken";
        let mut response = client.post(url.as_str())
            //.json(&payload_json)
            //.json(&payload_value)
            .headers(headers)
            .body(api_payload.to_string())
            .send().unwrap();

        // 处理 TCS 响应数据...
        let response_content = load_response(&mut response).unwrap();
        info!("[#]{}", "tcs_request_api_successful");

        // 判断是否可解析错误...
        // [Support : new to rust and trying to handle serde_json::from_str errors #370](https://github.com/serde-rs/json/issues/370)
        // [Serde json typed deserialize error handling – return or wrap the error](https://users.rust-lang.org/t/serde-json-typed-deserialize-error-handling-return-or-wrap-the-error/28235)
        // let _: TcsResponseError = match serde_json::from_str(&response_content) {

        // 首先解析响应数据
        let tcs_response: TcsResponse = match serde_json::from_str(&response_content) {
            Result::Ok(tcs_response) => {
                info!("tcs response parsing successful!");
                tcs_response
            }
            Result::Err(tcs_error) => {
                debug!("tcs response parsing unsuccessful![tcs_error: {:?}]", tcs_error);
                // 自定义错误
                let tcs_api_error = TcsApiError {
                    message: "tcs response parsing unsuccessful!".to_string(),
                    code: "REQUEST_ID_NONE".to_string(),
                };
                return Result::Err(tcs_api_error);
                // return Result::Err("接口请求响应数据解析错误!".into());
            }
        };

        // 解析数据
        let tcs_response_value = tcs_response.response;
        // trace!("[@][tcs_response_value: {}]", tcs_response_value);
        let tcs_response_info = to_string(&tcs_response_value).unwrap();

        // 尝试解析响应错误
        let tcs_response_error: TcsResponseError = match serde_json::from_str(&tcs_response_info) {
            Result::Ok(tcs_response_error) => {
                info!("tcs response parsing error successful!");
                let tcs_response_error: TcsResponseError = tcs_response_error;
                return Result::Err(tcs_response_error.error);
            }
            Result::Err(tcs_response_data) => {
                debug!("tcs response parsing error unsuccessful![tcs_response_data: {:?}]", tcs_response_data);
                // 自定义错误
                let tcs_response_error = TcsResponseError {
                    request_id: "REQUEST_ID_NONE".to_string(),
                    error: TcsApiError {
                        message: "tcs response parsing unsuccessful!".to_string(),
                        code: "REQUEST_ID_NONE".to_string(),
                    },
                };
                tcs_response_error
            }
        };
        // trace!("[@][tcs_response_error: {:?}]", tcs_response_error);

        Ok(tcs_response_info)
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
