/// API error struct for a lack of wallet funds
#[derive(Debug)]
pub struct ErrorLackOfFunds;
impl warp::reject::Reject for ErrorLackOfFunds {}

/// API error struct for inability to access wallet
#[derive(Debug)]
pub struct ErrorCannotAccessWallet;
impl warp::reject::Reject for ErrorCannotAccessWallet {}

/// API error struct for inability to access user node
#[derive(Debug)]
pub struct ErrorCannotUserNode;
impl warp::reject::Reject for ErrorCannotUserNode {}