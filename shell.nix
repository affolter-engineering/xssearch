{ pkgs ? import <nixpkgs> {}
, release ? false
}:

let
  cargoFlags = pkgs.lib.optionalString release "--release";
  profile = if release then "release" else "debug";
in

pkgs.mkShell {
  name = "xssearch-dev";

  buildInputs = with pkgs; [
    gcc
    rustc
    cargo
    pkg-config
    cargo-watch   # optional: auto-rebuild on file changes
  ];

  shellHook = ''
    echo "xssearch dev shell - rustc $(rustc --version | cut -d' ' -f2), cargo $(cargo --version | cut -d' ' -f2)"
    echo ""
    echo "  build:          cargo build"
    echo "  build release:  cargo build --release"
    echo "  run:            cargo run -- [ARGS]"
    echo "  watch:          cargo watch -x 'build'"
    echo ""
  '';

  # nix-build entry: nix-shell --run 'build' or nix-shell --argstr release true --run 'build'
  BUILD = pkgs.writeShellScript "xssearch-build" ''
    set -e
    echo "[nix] Building xssearch (${profile}) ..."
    cargo build ${cargoFlags}
    echo "[nix] Binary: target/${profile}/xssearch"
  '';
}
