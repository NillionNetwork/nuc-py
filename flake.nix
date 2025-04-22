{
  description = "Fully isolated Python 3.12 development environment with uv and zsh";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = {
            allowUnfree = true;
          };
        };
        
        # Define the Python version to use
        pythonPackage = pkgs.python312;
        
        # Create a Python environment with basic packages
        pythonEnv = pythonPackage.withPackages (ps: with ps; [
          pip
          pytest
          pytest-cov
        ]);
        
        # Include uv from nixpkgs
        uv = pkgs.uv;
        
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pythonEnv
            uv
            pkgs.gcc
            pkgs.stdenv.cc.cc.lib  # Add standard C++ library
            pkgs.zsh
          ];

          
          shellHook = ''
            # Launch zsh with our custom config file
            export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib"
            export ZDOTDIR=$PWD
            exec zsh -i -c "uvinit ; exec zsh -i"
          '';
        };
      }
    );
}
