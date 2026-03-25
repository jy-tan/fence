{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  buildInputs =
    with pkgs;
    [
      go
      gopls
      gotestsum
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
