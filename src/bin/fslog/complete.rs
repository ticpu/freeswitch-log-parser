use clap_complete::aot::Shell;

pub fn generate_completions(shell: Shell, cmd: &mut clap::Command) {
    clap_complete::generate(shell, cmd, "fslog", &mut std::io::stdout());
}
