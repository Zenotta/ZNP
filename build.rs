// /// Git information separated by slashes: `<sha> / <branch> / <describe>`
// pub fn git_info() -> &'static str {
//     concat!(
//     env!("VERGEN_GIT_SHA"),
//     " / ",
//     env!("VERGEN_GIT_BRANCH"),
//     " / ",
//     env!("VERGEN_GIT_DESCRIBE")
//     )
// }
//
// /// Annotated tag description, or fall back to abbreviated commit object.
// pub fn git_describe() -> &'static str {
//     env!("VERGEN_GIT_DESCRIBE")
// }
//
// /// Current git branch.
// pub fn git_branch() -> &'static str {
//     env!("VERGEN_GIT_BRANCH")
// }
//
// /// Shortened SHA-1 hash.
// pub fn git_sha() -> &'static str {
//     env!("VERGEN_GIT_SHA")
// }

use vergen::EmitBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    EmitBuilder::builder().all_build().all_git().emit()?;

    Ok(())
}
