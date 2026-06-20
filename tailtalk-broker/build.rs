fn main() {
    prost_build::compile_protos(&["../proto/tailtalk.proto"], &["../proto"])
        .expect("prost_build failed");

    println!("cargo:rerun-if-changed=../proto/tailtalk.proto");
}
