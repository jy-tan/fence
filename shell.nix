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
      python3
      nodejs
      git
    ]
    ++ lib.optionals stdenv.isLinux [
      bubblewrap
      socat
    ];
}
