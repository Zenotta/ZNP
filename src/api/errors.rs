/// Generic error
#[derive(Debug)]
pub struct ErrorGeneric {
    pub name: &'static str,
}
impl ErrorGeneric {
    pub fn new(name: &'static str) -> Self {
        ErrorGeneric { name }
    }
}
impl ::std::fmt::Display for ErrorGeneric {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Generic error: {:?}", self.name)
    }
}
impl ::std::error::Error for ErrorGeneric {}
impl warp::reject::Reject for ErrorGeneric {}

/// API error struct for invalid passphrase entered
#[derive(Debug)]
pub struct ErrorInvalidPassphrase;
impl warp::reject::Reject for ErrorInvalidPassphrase {}

impl std::fmt::Display for ErrorInvalidPassphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Invalid passphrase")
    }
}

/// API error struct for invalid HTTP body content
#[derive(Debug)]
pub struct ErrorInvalidJSONStructure;
impl warp::reject::Reject for ErrorInvalidJSONStructure {}

impl std::fmt::Display for ErrorInvalidJSONStructure {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Invalid JSON structure")
    }
}

/// API error struct for inability to parse an IP address from a string
#[derive(Debug)]
pub struct ErrorCannotParseAddress;
impl warp::reject::Reject for ErrorCannotParseAddress {}

impl std::fmt::Display for ErrorCannotParseAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Cannot parse provided address")
    }
}

/// API error struct for inability to access wallet
#[derive(Debug)]
pub struct ErrorCannotAccessWallet;
impl warp::reject::Reject for ErrorCannotAccessWallet {}

impl std::fmt::Display for ErrorCannotAccessWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Cannot access wallet")
    }
}

/// API error struct for inability to access user node
#[derive(Debug)]
pub struct ErrorCannotAccessUserNode;
impl warp::reject::Reject for ErrorCannotAccessUserNode {}

impl std::fmt::Display for ErrorCannotAccessUserNode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Cannot access user node")
    }
}

/// API error struct for inability to access compute node
#[derive(Debug)]
pub struct ErrorCannotAccessComputeNode;
impl warp::reject::Reject for ErrorCannotAccessComputeNode {}

impl std::fmt::Display for ErrorCannotAccessComputeNode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Cannot access compute node")
    }
}

/// API error struct for inability to access peer user node
#[derive(Debug)]
pub struct ErrorCannotAccessPeerUserNode;
impl warp::reject::Reject for ErrorCannotAccessPeerUserNode {}

/// API error struct for inability to save addresses to wallet
#[derive(Debug)]
pub struct ErrorCannotSaveAddressesToWallet;
impl warp::reject::Reject for ErrorCannotSaveAddressesToWallet {}

#[derive(Debug)]
pub struct ErrorCannotFetchBalance;
impl warp::reject::Reject for ErrorCannotFetchBalance {}

impl std::fmt::Display for ErrorCannotFetchBalance {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Cannot fetch balances")
    }
}

/// API error struct for trying to access non-existent data
#[derive(Debug)]
pub struct ErrorNoDataFoundForKey;
impl warp::reject::Reject for ErrorNoDataFoundForKey {}

impl std::fmt::Display for ErrorNoDataFoundForKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Entry not found in blockchain")
    }
}

/// API error for struct ambiguous code 500 internal errors.
///
/// TODO: Decide how much information on the internal error should be displayed to the client
#[derive(Debug)]
pub struct InternalError;
impl warp::reject::Reject for InternalError {}

impl std::fmt::Display for InternalError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Internal error")
    }
}

/// API error for Unauthorized requests.
#[derive(Debug)]
pub struct Unauthorized;
impl warp::reject::Reject for Unauthorized {}
