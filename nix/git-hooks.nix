{ lib, pkgs, ... }:
{
  src = ../.;
  default_stages = [
    "manual"
    "pre-push"
  ];
  hooks =
    let
      # XXX(@fricklerhandwerk): these need to be tacked onto the `pre-commit` configuration file,
      # which seems to ignore per-tool configuration
      excludes = [
        "\\.min.css$"
        "\\.html$"
        "npins"
        "migrations"
        "grafana-dashboard.json"
      ];
      # XXX(@fricklerhandwerk): due to implementation details of pre-commit.nix this is
      # required for running in CI when building the hooks as a derivation
      stages = [ "manual" ];
    in
    lib.mapAttrs (_: v: v // { inherit excludes stages; }) {
      # Nix setup
      nixfmt-rfc-style.enable = true;
      statix = {
        enable = true;
        # XXX(@fricklerhandwerk): statix for some reason needs its own ignores repeated...
        settings.ignore = excludes;
      };
      deadnix.enable = true;

      # Python setup
      ruff.enable = true;
      ruff-format = {
        enable = true;
        types = [
          "text"
          "python"
        ];

        entry = "${pkgs.lib.getExe pkgs.ruff} format";
      };

      pyright =
        let
          pyEnv = pkgs.python3.withPackages (_: pkgs.nix-security-tracker.propagatedBuildInputs);
          wrappedPyright = pkgs.runCommand "pyright" { nativeBuildInputs = [ pkgs.makeWrapper ]; } ''
            makeWrapper ${pkgs.pyright}/bin/pyright $out \
              --set PYTHONPATH ${pyEnv}/${pyEnv.sitePackages} \
              --prefix PATH : ${pyEnv}/bin \
              --set PYTHONHOME ${pyEnv}
          '';
        in
        {
          enable = true;
          entry = lib.mkForce (builtins.toString wrappedPyright);
        };

      # Global setup
      prettier = {
        enable = true;
      };

      lychee = {
        enable = true;
        name = "lychee";
        entry = "${pkgs.lib.getExe pkgs.lychee} --offline --no-progress";
        files = "\\.md$";
      };

      vale =
        let
          sentence-case = pkgs.writeText "SentenceCase.yml" ''
            extends: capitalization
            message: "Should be in sentence case: '%s'"
            level: error
            scope: heading
            # $title, $sentence, $lower, $upper, or a pattern.
            match: $sentence
            exceptions:
              - Nix
              - Nixpkgs
              - CPE
              - CPEs
              - CVE
              - CVEs
              - Sentry
              - Hetzner
              - Hetzner Cloud
              - Terraform
              - OpenTofu
              - SSH
          '';

          styles-dir = pkgs.runCommand "vale-styles" { } ''
            mkdir -p $out/default
            cp ${sentence-case} $out/default/SentenceCase.yml
          '';

          vale-config = pkgs.writeText "vale.ini" ''
            StylesPath = ${styles-dir}
            MinAlertLevel = suggestion

            [*.md]
            BasedOnStyles = default
          '';
        in
        {
          enable = true;
          name = "vale";
          entry = "${pkgs.lib.getExe pkgs.vale} --config=${vale-config}";
          files = "\\.md$";
        };
    };
}
