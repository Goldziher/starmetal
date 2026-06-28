const VERSION: &str = "0.0.1";

fn main() {
    let mut args = std::env::args().skip(1);
    if matches!(args.next().as_deref(), Some("--version" | "-V")) {
        println!("sm {VERSION}");
        return;
    }

    println!(
        "StarMetal {VERSION}\n\n\
         This crates.io package reserves the public starmetal namespace while the production sm CLI \
         distribution is finalized.\n\
         Repository: https://github.com/Goldziher/starmetal"
    );
}
