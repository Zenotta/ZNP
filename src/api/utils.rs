use super::{
    errors::{ApiError, ApiErrorType},
    handlers::DbgPaths,
    responses::{common_error_reply, json_serialize_embed, CallResponse, JsonReply},
};
use crate::utils::{validate_pow_for_diff, ApiKeys, RoutesPoWInfo, StringError};
use futures::Future;
use std::convert::Infallible;
use tracing::log::error;
use warp::{
    hyper::{HeaderMap, StatusCode},
    path::FullPath,
    Filter, Rejection, Reply,
};

// Indicates that any API key may be used
pub const ANY_API_KEY: &str = "any_key";

// Clone component/struct to use in route
pub fn with_node_component<T: Clone + Send>(
    comp: T,
) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
    warp::any().map(move || comp.clone())
}

// Add route path to mutable reference DbgPaths
pub fn warp_path(
    dp: &mut DbgPaths,
    p: &'static str,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    dp.push(p);
    warp::path(p)
}

// Maps a StringError to JsonReply error for bad requests.
pub fn map_string_err(r: CallResponse, e: StringError, s: StatusCode) -> JsonReply {
    r.into_err(s, ApiErrorType::Generic(e.to_string()))
        .unwrap_err() // Should panic if result is not Err
}

// Map API response from Result<JsonReply, JsonReply> to Result<warp::Reply, warp::Rejection>
pub fn map_api_res(
    r: impl Future<Output = Result<JsonReply, JsonReply>>,
) -> impl Future<Output = Result<impl warp::Reply, warp::Rejection>> {
    use futures::future::TryFutureExt;
    r.map_ok_or_else(Ok, Ok)
}

// Authorizes a request based on API keys as well as PoW requirements for the route
// Successfull authorization will extract the x-request-id header value
pub fn auth_request(
    routes_pow: RoutesPoWInfo,
    api_keys: ApiKeys,
) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::path::full()
        .and(warp::header::headers_cloned())
        .and_then(move |path: FullPath, headers: HeaderMap| {
            let route_path = path.as_str()[1..].to_owned(); /* Slice to remove '/' prefix */
            let route_difficulty = routes_pow.lock().unwrap().get(&route_path).cloned();
            let keys = api_keys.lock().unwrap().clone();
            let need_api_key = !keys.contains(ANY_API_KEY);

            async move {
                // Extract headers
                let id = headers
                    .get("x-request-id")
                    .and_then(|n| n.to_str().ok())
                    .unwrap_or_default();

                let nonce = headers
                    .get("x-nonce")
                    .and_then(|n| n.to_str().ok())
                    .unwrap_or_default();

                let api_key = headers
                    .get("x-api-key")
                    .and_then(|n| n.to_str().ok())
                    .unwrap_or_default();

                // Error for authorization failure
                let err_unauthorized = Err(warp::reject::custom(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    ApiErrorType::Unauthorized,
                    id.to_owned(),
                    route_path,
                )));

                // All requests require a unique ID of 32 characters
                if id.chars().count() != 32 {
                    return err_unauthorized;
                }

                // API key is needed, but the corresponding API key is not provided/invalid
                if need_api_key && !keys.contains(api_key) {
                    return err_unauthorized;
                }

                let hash_content = format!("{}-{}", nonce, id);

                // This route requires PoW
                if let Some(difficulty) = route_difficulty {
                    if validate_pow_for_diff(difficulty, hash_content.as_bytes()).is_none() {
                        return err_unauthorized;
                    }
                }

                // No PoW required
                Ok(id.to_owned())
            }
        })
        .or_else(move |err| async move { Err(err) })
}

// Custom function to handle request errors that occur before the request can be logically processed
pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Rejection> {
    let mut error = ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        ApiErrorType::InternalError,
        "null".to_string(),
        "null".to_string(),
    );

    if err.is_not_found() {
        // Method not found
        error.code = StatusCode::NOT_FOUND;
        error.message = ApiErrorType::MethodNotFound;
    } else if err
        .find::<warp::filters::body::BodyDeserializeError>()
        .is_some()
    {
        // Failure to deserialize request body
        error.code = StatusCode::BAD_REQUEST;
        error.message = ApiErrorType::BadRequest;
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        // Method not allowed
        error.code = StatusCode::METHOD_NOT_ALLOWED;
        error.message = ApiErrorType::MethodNotAllowed;
    } else if let Some(err) = err.find::<ApiError>().cloned() {
        // Custom errors
        error = err;
    } else {
        // This should not happen! All errors should be handled
        error!("Unhandled API rejection: {:?}", err);
        error.code = StatusCode::INTERNAL_SERVER_ERROR;
        error.message = ApiErrorType::Generic(format!("Unhandled rejection: {:?}", err));
    }

    Ok(common_error_reply(
        error.code,
        error.message,
        &error.id,
        &error.route,
        json_serialize_embed("null"),
    ))
}
