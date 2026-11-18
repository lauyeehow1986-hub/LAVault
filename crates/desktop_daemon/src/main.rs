use clap::Parser;
use desktop_daemon::cli::{execute_cli_command, Cli};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    execute_cli_command(cli)
}
