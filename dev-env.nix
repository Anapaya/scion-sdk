# Reuseable dev shell environment config
{
  pkgs,
  rootDir,
  extraPackages ? [],
  extraRustcLibs ? [],
  ...
}: let
  # Fetch the rust version from rust-toolchain.toml
  rustVersion = (builtins.fromTOML (builtins.readFile "${rootDir}/rust-toolchain.toml")).toolchain.channel;
in rec {
  packages = with pkgs;
    [
      # Protobuf
      protobuf

      # Native Compiler Toolchains
      gcc
      rustup
      pkg-config
      clang
      llvmPackages.bintools
      m4
      cmake
      ninja

      # Libs
      zlib
      libbpf
      linuxHeaders
      openssl
    ]
    ++ extraPackages;

  ### Rustc

  RUSTC_VERSION = rustVersion;

  # Precompiled libraries for rustc
  RUSTC_SEARCH_LIBS = with pkgs; [] ++ extraRustcLibs;
  # Add precompiled libraries to rustc's search path
  RUSTFLAGS = builtins.map (search_lib: ''-L ${search_lib}/lib'') RUSTC_SEARCH_LIBS;

  ### Add Rust to Path
  shellHook = ''
    export PATH=$PATH:''${CARGO_HOME:-~/.cargo}/bin
    export PATH=$PATH:''${RUSTUP_HOME:-~/.rustup}/toolchains/${rustVersion}-x86_64-unknown-linux-gnu/bin
  '';

  ### Rust Bind Gen
  # Include libraries using standard import paths (<>/include)
  BINDGEN_INCLUDE = with pkgs; [
    glibc.dev
    glib
  ];
  # Add glibc, clang, glib, and other headers to bindgen search path
  BINDGEN_EXTRA_CLANG_ARGS =
    (builtins.map (lib_base_path: ''-I "${lib_base_path}/include"'') BINDGEN_INCLUDE)
    ++ BINDGEN_CUSTOM_INCLUDE;

  # Development libraries with custom import paths
  BINDGEN_CUSTOM_INCLUDE = with pkgs; [
    ''-I "${llvmPackages_latest.libclang.lib}/lib/clang/${llvmPackages_latest.libclang.version}/include"''
    ''-I "${glib.dev}/include/glib-2.0"''
    ''-I "${glib.out}/lib/glib-2.0/include/"''
  ];

  # https://github.com/rust-lang/rust-bindgen#environment-variables
  LIBCLANG_PATH = pkgs.lib.makeLibraryPath [pkgs.llvmPackages_latest.libclang.lib];

  ### Shell settings
  # Disable some hardening options that are not compatible with BPF.
  hardeningDisable = [
    "zerocallusedregs"
    "stackclashprotection"
  ];
  NIX_CFLAGS_COMPILE = "-Wno-unused-command-line-argument -idirafter ${pkgs.glibc.dev}/include"; # Ignore some errors while building shell
  CFLAGS = "-idirafter ${pkgs.glibc.dev}/include";
  CXXFLAGS = "-idirafter ${pkgs.glibc.dev}/include";
}
