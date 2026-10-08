{
  description = "Ktor HttpClientEngine with a Rust library, bound through Gobley";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin"];
    forAllSystems = function:
      nixpkgs.lib.genAttrs systems (system:
        function (import nixpkgs {
          inherit system;
          config = {
            # The Android SDK is unfree and carries a licence to accept.
            allowUnfree = true;
            android_sdk.accept_license = true;
          };
        }));
  in {
    devShells = forAllSystems (pkgs: let
      # ndkVersions must match androidNdk in gradle/libs.versions.toml.
      # Gobley reads android.ndkVersion and looks for <sdk>/ndk/<version>.
      android = pkgs.androidenv.composeAndroidPackages {
        platformVersions = ["35"];
        buildToolsVersions = ["35.0.0"];
        includeNDK = true;
        ndkVersions = ["27.2.12479018"];
        # An emulator for the instrumented tests. The image has the ABI of
        # the host, so KVM or the Apple hypervisor runs it at full speed.
        includeEmulator = true;
        includeSystemImages = true;
        systemImageTypes = ["google_apis"];
        abiVersions =
          if pkgs.stdenv.hostPlatform.isx86_64
          then ["x86_64"]
          else ["arm64-v8a"];
      };

      # On Darwin, Xcode supplies the C toolchain and the Apple SDKs. The
      # Nix stdenv points SDKROOT at a macOS-only SDK and puts a clang
      # wrapper on PATH that cannot target iOS.
      mkShell =
        if pkgs.stdenv.hostPlatform.isDarwin
        then pkgs.mkShellNoCC
        else pkgs.mkShell;

      # Gradle downloads the Kotlin/Native toolchain and rustup downloads
      # rustc. Neither is a Nix build, so on Linux neither finds a library
      # on its own. libxcrypt-legacy carries libcrypt.so.1, which every
      # Kotlin/Native linuxX64 binary needs.
      #
      # Keep this list minimal. Every entry applies to every child
      # process, so one library that needs a newer glibc than /bin/sh
      # uses breaks the shell itself. Never add the Nix glibc.
      linuxLibraries = pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
          pkgs.zlib
          pkgs.stdenv.cc.cc.lib
          pkgs.libxcrypt-legacy
        ];

        # On NixOS, nix-ld starts those binaries with the system glibc.
        # The libraries above need the glibc of this flake, which can be
        # newer. Hand nix-ld the loader of this flake. A Linux host without
        # nix-ld ignores the variable.
        NIX_LD = pkgs.stdenv.cc.bintools.dynamicLinker;

        # boring-sys runs bindgen, and bindgen loads libclang. The Nix
        # libclang finds no C headers on its own. The variable names the host
        # triple, so the Android cross builds keep the NDK sysroot.
        LIBCLANG_PATH = pkgs.lib.makeLibraryPath [pkgs.llvmPackages.libclang.lib];
        "BINDGEN_EXTRA_CLANG_ARGS_${hostTriple}" = pkgs.lib.concatStringsSep " " [
          "-isystem ${pkgs.llvmPackages.libclang.lib}/lib/clang/${pkgs.lib.versions.major pkgs.llvmPackages.libclang.version}/include"
          "-isystem ${pkgs.glibc.dev}/include"
        ];
      };

      # The Rust spelling of the host, with underscores, as bindgen reads it.
      hostTriple =
        builtins.replaceStrings ["-"] ["_"] pkgs.stdenv.hostPlatform.rust.rustcTarget;

      # A cross target of the Rust library. zig is the C compiler, the
      # archiver, and the linker. bindgen reads the libc headers of zig.
      zigCross = {
        rustTriple,
        zigTarget,
        cmakeSystem,
        cmakeProcessor,
        cmakeExtra ? "",
        libcIncludes,
      }: let
        zigTool = tool: args:
          pkgs.writeShellScript "${rustTriple}-${tool}" ''
            exec env -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
              ${pkgs.cargo-zigbuild}/bin/cargo-zigbuild zig ${tool} -- ${args} "$@"
          '';
        cc = zigTool "cc" "-target ${zigTarget}";
        cxx = zigTool "c++" "-target ${zigTarget}";
        ar = zigTool "ar" "";
        ranlib = zigTool "ranlib" "";
        cmakeToolchain = pkgs.writeText "${rustTriple}.cmake" ''
          set(CMAKE_SYSTEM_NAME ${cmakeSystem})
          set(CMAKE_SYSTEM_PROCESSOR ${cmakeProcessor})
          set(CMAKE_C_COMPILER ${cc})
          set(CMAKE_CXX_COMPILER ${cxx})
          set(CMAKE_AR ${ar})
          set(CMAKE_RANLIB ${ranlib})
          set(CMAKE_C_LINKER_DEPFILE_SUPPORTED FALSE)
          set(CMAKE_CXX_LINKER_DEPFILE_SUPPORTED FALSE)
          set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
          ${cmakeExtra}
        '';
        target = builtins.replaceStrings ["-"] ["_"] rustTriple;
      in {
        "CC_${target}" = cc;
        "CXX_${target}" = cxx;
        "AR_${target}" = ar;
        "RANLIB_${target}" = ranlib;
        "CARGO_TARGET_${pkgs.lib.toUpper target}_LINKER" = cc;
        "CMAKE_TOOLCHAIN_FILE_${target}" = cmakeToolchain;
        # The Nix libclang of a Linux host finds no compiler headers on its
        # own. The libclang of Xcode does.
        "BINDGEN_EXTRA_CLANG_ARGS_${target}" = pkgs.lib.concatMapStringsSep " " (dir: "-isystem ${dir}") (
          pkgs.lib.optional pkgs.stdenv.hostPlatform.isLinux
          "${pkgs.llvmPackages.libclang.lib}/lib/clang/${pkgs.lib.versions.major pkgs.llvmPackages.libclang.version}/include"
          ++ map (dir: "${pkgs.zig}/lib/zig/libc/include/${dir}") libcIncludes
        );
      };

      # The JVM jar carries a Windows DLL, so a Linux host and a Mac cross
      # compile the Rust library to x86_64-pc-windows-gnu. zig ships a static
      # MinGW runtime, so the DLL needs no MinGW DLL at run time. The Nix
      # MinGW GCC links mcfgthread, which the DLL would then need. nasm
      # assembles the Windows code of BoringSSL.
      windowsCross = zigCross {
        rustTriple = "x86_64-pc-windows-gnu";
        zigTarget = "x86_64-windows-gnu";
        cmakeSystem = "Windows";
        cmakeProcessor = "AMD64";
        cmakeExtra = "set(CMAKE_ASM_NASM_COMPILER ${pkgs.nasm}/bin/nasm)";
        libcIncludes = ["any-windows-any"];
      };

      # A Mac also builds the Linux library. glibc 2.17 is the oldest that
      # Rust supports, so the library loads on every Linux that Rust runs on.
      linuxCross = zigCross {
        rustTriple = "x86_64-unknown-linux-gnu";
        zigTarget = "x86_64-linux-gnu.2.17";
        cmakeSystem = "Linux";
        cmakeProcessor = "x86_64";
        libcIncludes = ["x86-linux-gnu" "generic-glibc" "x86-linux-any" "any-linux-any"];
      };

      # rustc calls the dlltool of the target by this name, for the raw-dylib
      # imports of windows-sys.
      dlltool = pkgs.writeShellScriptBin "x86_64-w64-mingw32-dlltool" ''
        exec ${pkgs.zig}/bin/zig dlltool "$@"
      '';

      # The symbol step in build-logic rewrites the Linux and the Windows
      # archives with GNU binutils. On a Mac, ld and ar stay those of Xcode,
      # so these keep their target prefix. Only the tools of that step, so
      # that the MinGW dlltool cannot replace the one of zig.
      macBinutils = pkgs.runCommand "cross-binutils" {} ''
        mkdir -p $out/bin
        for tool in ld objcopy nm ar; do
          ln -s ${pkgs.pkgsCross.gnu64.buildPackages.binutils-unwrapped}/bin/x86_64-unknown-linux-gnu-$tool $out/bin/
        done
        for tool in objcopy nm ar; do
          ln -s ${pkgs.pkgsCross.mingwW64.buildPackages.binutils-unwrapped}/bin/x86_64-w64-mingw32-$tool $out/bin/
        done
      '';

      cross =
        if pkgs.stdenv.hostPlatform.isLinux
        then {
          # cargo-zigbuild finds zig on PATH.
          packages = [dlltool pkgs.zig];
          env = windowsCross;
        }
        else {
          packages = [dlltool pkgs.zig macBinutils];
          env = windowsCross // linuxCross;
        };
    in {
      default = mkShell ({
          packages = [
            # The nixpkgs OpenJDK crashes with SIGSEGV inside cinterop, in
            # the Kotlin/Native libclang bridge. Temurin runs it.
            pkgs.temurin-bin-21
            # rustup, not a fixed rustc, because the build cross compiles to
            # Android and Apple targets.
            pkgs.rustup
            pkgs.git
            pkgs.unzip
            pkgs.curl
            # scion-http3 pulls in BoringSSL, which boring-sys builds with
            # cmake for every Rust target.
            pkgs.cmake
            # emulator, avdmanager, and adb.
            android.androidsdk
          ]
          ++ cross.packages;

          ANDROID_HOME = "${android.androidsdk}/libexec/android-sdk";

          shellHook =
            pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
              # If an outer shell exports these, xcrun misses the Xcode SDKs.
              unset DEVELOPER_DIR SDKROOT
            ''
            + ''
              # An outer shell, such as the endhost/public one, can export
              # glibc include flags. Every cross C compiler reads them, and
              # the Android build of BoringSSL then fails.
              unset CFLAGS CXXFLAGS CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH BINDGEN_EXTRA_CLANG_ARGS

              # rustup keeps its shims here, and Gobley calls cargo by name.
              export PATH="$HOME/.cargo/bin:$PATH"
              export PATH="$ANDROID_HOME/platform-tools:$PATH"
              echo "ktor-scion dev shell. Run: ./gradlew build"
            '';
        }
        // linuxLibraries
        // cross.env);
    });
  };
}
