{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  buildInputs =
    with pkgs;
    [
      go
      golangci-lint
      gofumpt
      python3
      nodejs
      git
    ]
    ++ lib.optionals stdenv.isLinux [
      bubblewrap
      socat
    ];
}
