//! App to run a Zenotta node.

use clap::{App, ArgMatches};

mod compute;
mod miner;
mod pre_launch;
mod storage;
mod user;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let matches = clap_app().get_matches();
    launch_node_with_args(matches).await;
}

async fn launch_node_with_args(matches: ArgMatches<'_>) {
    if let Some(sub_command) = matches.subcommand_name() {
        let sub_matches = matches.subcommand_matches(sub_command).unwrap();

        println!(" ---------- BUILD DETAILS ---------- ");
        println!("Build Timestamp:    {}", env!("VERGEN_BUILD_TIMESTAMP"));
        println!("Build Date:    {}", env!("VERGEN_BUILD_DATE"));

        println!(" ---------- GIT DETAILS ---------- ");
        println!("Git Branch:    {}", env!("VERGEN_GIT_BRANCH"));
        println!("Git Hash:    {}", env!("VERGEN_GIT_HASH"));
        println!(
            "Git commit message:    {}",
            env!("VERGEN_GIT_COMMIT_MESSAGE")
        );
        println!("Git commit date:    {}", env!("VERGEN_GIT_COMMIT_DATE"));

        println!(" ---------- RUSTC DETAILS ---------- ");
        println!("Rustc Channel:    {}", env!("VERGEN_RUSTC_CHANNEL"));
        println!("Rustc Version:    {}", env!("VERGEN_RUSTC_SEMVER"));

        match sub_command {
            "user" => user::run_node(sub_matches).await,
            "miner" => miner::run_node(sub_matches).await,
            "compute" => compute::run_node(sub_matches).await,
            "storage" => storage::run_node(sub_matches).await,
            "pre_launch" => pre_launch::run_node(sub_matches).await,
            invalid_type => panic!("Invalid node type: {:?}", invalid_type),
        }
    } else {
        println!("Node type needs to be specified.")
    }
}

fn clap_app<'a, 'b>() -> App<'a, 'b> {
    App::new("Zenotta Node")
        .about("Runs a Zenotta node.")
        .subcommand(user::clap_app())
        .subcommand(miner::clap_app())
        .subcommand(compute::clap_app())
        .subcommand(storage::clap_app())
        .subcommand(pre_launch::clap_app())
}
