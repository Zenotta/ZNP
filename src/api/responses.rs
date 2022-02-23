use naom::primitives::asset::Asset;
use serde::Serialize;

/*------- JSON HANDLING --------*/

/// A JSON formatted reply.
#[derive(Debug, Clone)]
pub struct JsonReply(Vec<u8>);

impl warp::reply::Reply for JsonReply {
    #[inline]
    fn into_response(self) -> warp::reply::Response {
        use warp::http::header::{HeaderValue, CONTENT_TYPE};
        let mut res = warp::reply::Response::new(self.0.into());
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        res
    }
}

/// Embed block into Block enum
pub fn json_embed_block(value: Vec<u8>) -> JsonReply {
    json_embed(&[b"{\"Block\":", &value, b"}"])
}

/// Embed transaction into Transaction enum
pub fn json_embed_transaction(value: Vec<u8>) -> JsonReply {
    json_embed(&[b"{\"Transaction\":", &value, b"}"])
}

/// Embed serialized JSON into wrapping JSON
pub fn json_serialize_embed<T: Serialize>(value: T) -> JsonReply {
    JsonReply(serde_json::to_vec(&value).unwrap())
}

/// Embed JSON into wrapping JSON
pub fn json_embed(value: &[&[u8]]) -> JsonReply {
    JsonReply(value.iter().copied().flatten().copied().collect())
}

/*------- API RESPONSE HANDLING --------*/

/// Call response structure, with handling for errors and ok responses.
#[derive(Debug, Clone)]
pub struct CallResponse<'a> {
    pub route: &'a str,
    pub call_id: &'a str,
}

impl CallResponse<'_> {
    pub fn into_err(self, err: &dyn std::fmt::Display) -> Result<JsonReply, JsonReply> {
        Err(common_error_reply(self.call_id, err, self.route, None))
    }

    pub fn into_ok(self, info: JsonReply) -> Result<JsonReply, JsonReply> {
        Ok(common_success_reply(self.call_id, self.route, info))
    }
}

#[derive(Debug)]
pub struct CallResponseWithData<'a> {
    pub route: &'a str,
    pub call_id: &'a str,
    pub data: JsonReply,
}

impl CallResponseWithData<'_> {
    pub fn into_err(self, err: &dyn std::fmt::Display) -> Result<JsonReply, JsonReply> {
        Err(common_error_reply(
            self.call_id,
            err,
            self.route,
            Some(self.data),
        ))
    }

    pub fn into_ok(self) -> Result<JsonReply, JsonReply> {
        Ok(common_success_reply(self.call_id, self.route, self.data))
    }
}

#[derive(Debug, Serialize)]
pub enum APIResponseStatus {
    Success,
    Error,
    InProgress,
    Unknown,
}

impl std::fmt::Display for APIResponseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            APIResponseStatus::Success => write!(f, "Success"),
            APIResponseStatus::Error => write!(f, "Error"),
            APIResponseStatus::InProgress => write!(f, "InProgress"),
            APIResponseStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Default for APIResponseStatus {
    fn default() -> Self {
        APIResponseStatus::Unknown
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct APIAsset {
    asset: String,
    amount: u64,
    metadata: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct APICreateResponseContent {
    asset: String,
    amount: u64,
    to_address: String,
}

impl APICreateResponseContent {
    pub fn new(asset: String, amount: u64, to_address: String) -> Self {
        APICreateResponseContent {
            asset,
            amount,
            to_address,
        }
    }
}

/// Common reply structure for API calls
///
/// ### Arguments
///
/// * `id` - The ID of the API call. Provided by client
/// * `status` - The status of the API call.
/// * `reason` - The reason for the API call's failure, if any
/// * `route` - The route of the API call, as client confirmation
/// * `json_content` - Content of the API call, as JSON
pub fn common_reply(
    id: &str,
    status: APIResponseStatus,
    reason: Option<&str>,
    route: &str,
    json_content: JsonReply,
) -> JsonReply {
    let status = format!("{}", status);
    let reason = reason.unwrap_or("null");
    json_embed(&[
        b"{\"id\":\"",
        id.as_bytes(),
        b"\",\"status\":\"",
        status.as_bytes(),
        b"\",\"reason\":\"",
        reason.as_bytes(),
        b"\",\"route\":\"",
        route.as_bytes(),
        b"\",\"content\":",
        &json_content.0,
        b"}",
    ])
}

/// Handles common success replies
///
/// ### Arguments
///
/// * `id` - The ID of the API call. Provided by client
/// * `route` - The route of the API call, as client confirmation
/// * `json_content` - Content of the API call, as JSON
pub fn common_success_reply(id: &str, route: &str, json_content: JsonReply) -> JsonReply {
    common_reply(id, APIResponseStatus::Success, None, route, json_content)
}

/// Handles common error replies
///
/// ### Arguments
///
/// * `id` - The ID of the API call. Provided by client
/// * `error` - The reason for the API call's failure
/// * `route` - The route of the API call, as client confirmation
/// * `json_content` - Content of the API call, as JSON
pub fn common_error_reply<E: std::fmt::Display>(
    id: &str,
    error: E,
    route: &str,
    json_content: Option<JsonReply>,
) -> JsonReply {
    let json_content_to_use = optional_content_default(json_content);

    common_reply(
        id,
        APIResponseStatus::Error,
        Some(&format!("{}", error)),
        route,
        json_content_to_use,
    )
}

/// Converts a NAOM asset into a JSON reply structure
pub fn api_format_asset(asset: Asset) -> APIAsset {
    match asset {
        Asset::Token(token_amount) => APIAsset {
            asset: "token".to_string(),
            amount: token_amount.0,
            metadata: None,
        },
        Asset::Receipt(receipt_amount) => APIAsset {
            asset: "receipt".to_string(),
            amount: receipt_amount,
            metadata: None,
        },
        Asset::Data(data) => APIAsset {
            asset: "data".to_string(),
            amount: data.amount,
            metadata: Some(data.data),
        },
    }
}

/// Handles optional response content. Defaults to null if None provided
fn optional_content_default(content: Option<JsonReply>) -> JsonReply {
    match content {
        Some(c) => c,
        None => json_serialize_embed("null"),
    }
}
