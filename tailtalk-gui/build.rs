fn main() {
    slint_build::compile_with_config(
        "ui/app.slint",
        slint_build::CompilerConfiguration::new().with_style("native".into()),
    )
    .unwrap();

    // EtherTalk is on by default on macOS, where libpcap ships with the OS and
    // its BPF devices open without root once ChmodBPF is installed. Elsewhere it
    // stays opt-in, since pcap has to be installed separately (libpcap-dev, the
    // Npcap SDK) and a missing one breaks the build outright. Cargo features
    // cannot be made target-conditional, hence a cfg rather than a feature.
    println!("cargo::rustc-check-cfg=cfg(ethertalk)");
    let macos = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos");
    if macos || std::env::var_os("CARGO_FEATURE_ETHERTALK").is_some() {
        println!("cargo::rustc-cfg=ethertalk");
    }
}
