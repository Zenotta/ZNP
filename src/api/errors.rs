use warp::hyper::StatusCode;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub code: StatusCode,
    pub message: ApiErrorType,
    pub id: String,
    pub route: String,
}
#[derive(Debug, Clone)]
pub enum ApiErrorType {
    Generic(String),
    InvalidPassphrase,
    InvalidRequestBody,
    CannotParseAddress,
    CannotAccessWallet,
    CannotAccessUserNode,
    CannotAccessComputeNode,
    CannotAccessPeerUserNode,
    CannotSaveAddressesToWallet,
    CannotFetchBalance,
    NoDataFoundForKey,
    InternalError,
    Unauthorized,
    MethodNotFound,
    MethodNotAllowed,
    BadRequest,
}

impl ApiError {
    pub fn new(code: StatusCode, message: ApiErrorType, id: String, route: String) -> Self {
        ApiError {
            code,
            message,
            id,
            route,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl warp::reject::Reject for ApiError {}

impl std::fmt::Display for ApiErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            ApiErrorType::Generic(message) => write!(f, "Generic error: {}", message),
            ApiErrorType::InvalidPassphrase => write!(f, "Invalid passphrase"),
            ApiErrorType::InvalidRequestBody => write!(f, "Invalid request body"),
            ApiErrorType::CannotParseAddress => write!(f, "Cannot parse address"),
            ApiErrorType::CannotAccessWallet => write!(f, "Cannot access wallet"),
            ApiErrorType::CannotAccessUserNode => write!(f, "Cannot access user node"),
            ApiErrorType::CannotAccessComputeNode => write!(f, "Cannot access compute node"),
            ApiErrorType::CannotAccessPeerUserNode => write!(f, "Cannot access peer user node"),
            ApiErrorType::CannotSaveAddressesToWallet => {
                write!(f, "Cannot save address to wallet")
            }
            ApiErrorType::CannotFetchBalance => write!(f, "Cannot fetch balance"),
            ApiErrorType::NoDataFoundForKey => write!(f, "No data found for key"),
            ApiErrorType::InternalError => write!(f, "Internal Error"),
            ApiErrorType::Unauthorized => write!(f, "Unauthorized"),
            ApiErrorType::MethodNotFound => write!(f, "Method not found"),
            ApiErrorType::MethodNotAllowed => write!(f, "Method not allowed"),
            ApiErrorType::BadRequest => write!(f, "Bad request"),
        }
    }
}
