use crate::api::errors::ApiErrorType;
use naom::primitives::asset::Asset;
use serde::Serialize;
use warp::hyper::StatusCode;

/*------- JSON HANDLING --------*/

/// A JSON formatted reply.
#[derive(Debug, Clone)]
pub struct JsonReply {
    data: Vec<u8>,
    status_code: StatusCode,
}

impl JsonReply {
    pub fn new(data: Vec<u8>) -> Self {
        JsonReply {
            data,
            status_code: StatusCode::OK,
        }
    }

    pub fn with_code(mut self, status_code: StatusCode) -> Self {
        self.status_code = status_code;
        self
    }
}

impl warp::reply::Reply for JsonReply {
    #[inline]
    fn into_response(self) -> warp::reply::Response {
        use warp::http::header::{HeaderValue, CONTENT_TYPE};
        let res = warp::reply::Response::new(self.data.into());
        let mut res = warp::reply::with_status(res, self.status_code).into_response();
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
    JsonReply::new(serde_json::to_vec(&value).unwrap())
}

/// Embed JSON into wrapping JSON
pub fn json_embed(value: &[&[u8]]) -> JsonReply {
    JsonReply::new(value.iter().copied().flatten().copied().collect())
}

/*------- API RESPONSE HANDLING --------*/

/// Call response structure, with handling for errors and ok responses.
#[derive(Debug, Clone)]
pub struct CallResponse<'a> {
    pub route: &'a str,
    pub call_id: &'a str,
}

impl<'a> CallResponse<'a> {
    pub fn new(route: &'a str, call_id: &'a str) -> Self {
        CallResponse { route, call_id }
    }

    pub fn into_err_internal(self, api_error_type: ApiErrorType) -> Result<JsonReply, JsonReply> {
        self.into_err(StatusCode::INTERNAL_SERVER_ERROR, api_error_type)
    }

    pub fn into_err_bad_req(self, api_error_type: ApiErrorType) -> Result<JsonReply, JsonReply> {
        self.into_err(StatusCode::BAD_REQUEST, api_error_type)
    }

    pub fn into_err_with_data(
        self,
        status: StatusCode,
        api_error_type: ApiErrorType,
        data: JsonReply,
    ) -> Result<JsonReply, JsonReply> {
        Err(common_error_reply(
            status,
            api_error_type,
            self.call_id,
            self.route,
            data,
        ))
    }

    pub fn into_err(
        self,
        status: StatusCode,
        api_error_type: ApiErrorType,
    ) -> Result<JsonReply, JsonReply> {
        self.into_err_with_data(status, api_error_type, json_serialize_embed("null"))
    }

    pub fn into_ok(self, reason: &str, data: JsonReply) -> Result<JsonReply, JsonReply> {
        Ok(common_success_reply(self.call_id, self.route, reason, data))
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
    asset: Asset,
    extra_info: Option<Vec<u8>>,
}

impl APIAsset {
    pub fn new(asset: Asset, extra_info: Option<Vec<u8>>) -> Self {
        APIAsset { asset, extra_info }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct APICreateResponseContent {
    asset: APIAsset,
    to_address: String,
    tx_hash: String,
}

impl APICreateResponseContent {
    pub fn new(asset: APIAsset, to_address: String, tx_hash: String) -> Self {
        APICreateResponseContent {
            asset,
            to_address,
            tx_hash,
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
    reason: &str,
    route: &str,
    content: JsonReply,
) -> JsonReply {
    let status = format!("{status}");
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
        &content.data,
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
pub fn common_success_reply(
    id: &str,
    route: &str,
    reason: &str,
    json_content: JsonReply,
) -> JsonReply {
    common_reply(id, APIResponseStatus::Success, reason, route, json_content)
        .with_code(StatusCode::OK)
}

/// Handles common error replies
///
/// ### Arguments
///
/// * `id` - The ID of the API call. Provided by client
/// * `error` - The reason for the API call's failure
/// * `route` - The route of the API call, as client confirmation
/// * `json_content` - Content of the API call, as JSON
pub fn common_error_reply(
    status: StatusCode,
    error_type: ApiErrorType,
    call_id: &str,
    route: &str,
    data: JsonReply,
) -> JsonReply {
    common_reply(
        call_id,
        APIResponseStatus::Error,
        &format!("{error_type}"),
        route,
        data,
    )
    .with_code(status)
}

/// Handles optional response content. Defaults to null if None provided
fn optional_content_default(content: Option<JsonReply>) -> JsonReply {
    match content {
        Some(c) => c,
        None => json_serialize_embed("null"),
    }
}
