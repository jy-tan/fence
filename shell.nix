{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  buildInputs =
    with pkgs;
    [
      go
      python3
      nodejs
      git
    ]
    ++ lib.optionals stdenv.isLinux [
      bubblewrap
      socat
    ];
}
