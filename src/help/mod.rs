use crate::Result;

mod client;
mod server;

struct Operation {
    name: &'static str,
    usage: &'static str,
    description: &'static str,
    details: &'static str,
    example: &'static str,
}

fn banner() {
    println!(
        "Autobricks PKI Server {} (C) 2026 Autobricks, Co.",
        crate::VERSION
    );
}

pub fn print_if_requested(binary: &str, args: &[String]) -> Result<bool> {
    let (operations, examples) = match binary {
        "abpkid" => (server::OPERATIONS, server::EXAMPLES),
        "abpki-cli" => (client::OPERATIONS, client::EXAMPLES),
        _ => return Err("unknown executable help target".into()),
    };
    if args.len() == 1 && matches!(args[0].as_str(), "-V" | "--version") {
        println!("{binary} {}", crate::VERSION);
        return Ok(true);
    }
    if args.is_empty() || (args.len() == 1 && matches!(args[0].as_str(), "-h" | "--help")) {
        banner();
        println!("Usage:\n  {binary} <operation> [options]\n\nOperations:");
        for operation in operations {
            println!("  {}\n      {}\n", operation.usage, operation.description);
        }
        println!(
            "Global options:\n  -h, --help\n      Show this help and exit.\n\n  -V, --version\n      Show the program version.\n\nOperation help:\n  {binary} <operation> --help\n\nExamples:\n{examples}"
        );
        return Ok(true);
    }
    if args
        .iter()
        .skip(1)
        .any(|arg| matches!(arg.as_str(), "-h" | "--help"))
    {
        let operation = operations
            .iter()
            .find(|operation| args.first().is_some_and(|name| name == operation.name))
            .ok_or("unknown operation; run --help")?;
        banner();
        println!(
            "Usage:\n  {binary} {}\n\n{}\n\n{}\n\nExample:\n  {}",
            operation.usage, operation.description, operation.details, operation.example
        );
        return Ok(true);
    }
    Ok(false)
}
