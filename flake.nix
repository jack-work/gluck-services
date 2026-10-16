{
  description = "gluck-services — authenticated account-minting and todo APIs behind kelliher-web";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    zanni.url = "github:jack-work/zanni";
    zanni.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { self, nixpkgs, zanni, ... }:
    let
      accountsSrc =
        pkgs:
        let
          z = zanni.packages.${pkgs.stdenv.hostPlatform.system}.assets;
        in
        pkgs.runCommand "gluck-accounts-src" { } ''
          mkdir -p $out/static/zanni
          cp ${./accounts/gluck_accounts.py} $out/gluck_accounts.py
          cp ${./accounts/settings.py} $out/settings.py
          cp ${./accounts/mail.py} $out/mail.py
          cp -r ${./accounts/templates} $out/templates
          cp ${z}/gesso/gesso.css ${z}/fontpack/fontpack.css ${z}/fontpack/fonts.css $out/static/zanni/
          cp -r ${z}/fontpack/fonts $out/static/zanni/fonts
        '';

      nixosModule =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          acctCfg = config.services.gluck-accounts;
          todoCfg = config.services.gluck-todo;
          siteCfg = config.services.gluck-site;
          py = pkgs.python3.withPackages (
            ps: with ps; [
              flask
              waitress
              requests
              duckdb
              pyjwt
              cryptography
            ]
          );
          hardened = {
            NoNewPrivileges = true;
            PrivateTmp = true;
            PrivateDevices = true;
            ProtectHome = true;
            ProtectSystem = "strict";
            ProtectKernelTunables = true;
            ProtectKernelModules = true;
            ProtectKernelLogs = true;
            ProtectControlGroups = true;
            RestrictAddressFamilies = [
              "AF_INET"
              "AF_INET6"
              "AF_UNIX"
            ];
            RestrictNamespaces = true;
            RestrictRealtime = true;
            RestrictSUIDSGID = true;
            LockPersonality = true;
            SystemCallArchitectures = "native";
          };
        in
        {
          options.services.gluck-accounts = {
            enable = lib.mkEnableOption "gluck-accounts API (mints lldap users)";

            lldapUrl = lib.mkOption {
              type = lib.types.str;
              default = "http://127.0.0.1:17170";
              description = "Base URL of the lldap HTTP API";
            };

            passwordFile = lib.mkOption {
              type = lib.types.path;
              description = "File containing the lldap service-account password (user gluck-accounts)";
            };

            settingsHost = lib.mkOption {
              type = lib.types.str;
              default = "me.kelliher.info";
              description = "Hostname of the self-service settings site this service also answers";
            };

            smtpUser = lib.mkOption {
              type = lib.types.str;
              default = "";
              description = "SMTP user for the settings site's email-change mail";
            };

            smtpPasswordFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = "File holding the SMTP password. Without it, an email change is refused and nothing changes";
            };
          };

          options.services.gluck-todo = {
            enable = lib.mkEnableOption "gluck-todo API (DuckDB-backed todos with per-item ACLs)";
          };

          options.services.gluck-site = {
            todoSubdomains = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ "todo" ];
              description = ''
                Subdomain labels for the todo API. Expanded across
                `services.kelliher-web.baseDomains` at the platform.
                Defaults to `todo` (→ `todo.<baseDomain>`).
              '';
            };
            settingsSubdomains = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ "me" ];
              description = ''
                Subdomain labels for the self-service settings site, served
                by gluck-accounts to any signed-in user.
              '';
            };
            accountsSubdomains = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ "accounts" ];
              description = ''
                Subdomain labels for the accounts-minting API. Defaults
                to `accounts` (→ `accounts.<baseDomain>`).
              '';
            };
            extraHostnames = lib.mkOption {
              type = lib.types.attrsOf (lib.types.listOf lib.types.str);
              default = { };
              example = {
                todo = [ "gluck.kelliher.info" ];
              };
              description = ''
                Fully-qualified hostnames per site, merged into
                `sites.<site>.hostnames`. Escape hatch for legacy names.
              '';
            };
          };

          config = lib.mkMerge [
            (lib.mkIf acctCfg.enable {
              users.users.gluck-accounts = {
                isSystemUser = true;
                group = "gluck-accounts";
              };
              users.groups.gluck-accounts = { };

              systemd.services.gluck-accounts = {
                description = "gluck-accounts — lldap account minting API";
                after = [
                  "network.target"
                  "lldap.service"
                ];
                wants = [ "lldap.service" ];
                wantedBy = [ "multi-user.target" ];
                environment = {
                  LLDAP_URL = acctCfg.lldapUrl;
                  LLDAP_PASSWORD_FILE = "%d/lldap_password";
                  LLDAP_SET_PASSWORD_BIN = "${pkgs.lldap}/bin/lldap_set_password";
                  KWEB_LISTEN = "socket";
                  SETTINGS_HOST = acctCfg.settingsHost;
                  SETTINGS_SMTP_USER = acctCfg.smtpUser;
                };
                serviceConfig = hardened // {
                  User = "gluck-accounts";
                  Group = "gluck-accounts";
                  ExecStart = "${py}/bin/python ${accountsSrc pkgs}/gluck_accounts.py";
                  StateDirectory = "gluck-accounts";
                  LoadCredential =
                    [ "lldap_password:${acctCfg.passwordFile}" ]
                    ++ lib.optional (acctCfg.smtpPasswordFile != null) "smtp_password:${acctCfg.smtpPasswordFile}";
                  Restart = "on-failure";
                  RestartSec = 5;
                };
              };
            })

            (lib.mkIf todoCfg.enable {
              systemd.services.gluck-todo = {
                description = "gluck-todo — DuckDB todo API with per-item ACLs";
                after = [ "network.target" ];
                wantedBy = [ "multi-user.target" ];
                environment = {
                  GLUCK_TODO_DB = "/var/lib/gluck-todo/todo.duckdb";
                  KWEB_LISTEN = "socket";
                };
                serviceConfig = hardened // {
                  DynamicUser = true;
                  StateDirectory = "gluck-todo";
                  ExecStart = "${py}/bin/python ${./todo/gluck_todo.py}";
                  Restart = "on-failure";
                  RestartSec = 5;
                };
              };
            })

            (lib.mkIf (acctCfg.enable || todoCfg.enable) {
              # Register public sites, all behind Authelia 2FA. Splitting
              # `todo` and `accounts` into two Caddy site blocks means each
              # gets its own hostname (todo.<base>, accounts.<base>) with
              # no path-based routing dance.
              services.kelliher-web.sites.gluck-todo = lib.mkIf todoCfg.enable {
                subdomains = siteCfg.todoSubdomains;
                hostnames = siteCfg.extraHostnames.todo or [ ];
                requireAuth = true;
                requiredGroups = [ "todo-create" ];
                proxySocket = "gluck-todo.service";
              };
              services.kelliher-web.sites.gluck-accounts = lib.mkIf acctCfg.enable {
                subdomains = siteCfg.accountsSubdomains;
                hostnames = siteCfg.extraHostnames.accounts or [ ];
                requireAuth = true;
                requiredGroups = [ "accounts-create" ];
                proxySocket = "gluck-accounts.service";
              };
              services.kelliher-web.uriRedactions = lib.mkIf acctCfg.enable [
                {
                  pattern = "/email/confirm\\?t=[A-Za-z0-9_-]+";
                  replacement = "/email/confirm?t=REDACTED";
                }
              ];
              services.kelliher-web.sites.gluck-settings = lib.mkIf acctCfg.enable {
                subdomains = siteCfg.settingsSubdomains;
                requireAuth = true;
                requiredGroups = [ ];
                proxySocket = "gluck-accounts.service";
                selfAuthorizingPaths = [ { path = "/email/confirm"; methods = [ "GET" "HEAD" "POST" ]; } ];
              };
            })
          ];
        };

      forAllSystems = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
    {
      nixosModules.default = nixosModule;

      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          py = pkgs.python3.withPackages (
            ps: with ps; [
              flask
              waitress
              requests
              duckdb
              pyjwt
              cryptography
            ]
          );
        in
        {
          accounts = pkgs.runCommand "gluck-accounts-tests" { } ''
            set -o pipefail
            cp -r ${accountsSrc pkgs}/. . && chmod -R u+w .
            install -m 0644 ${./accounts/test_gluck_accounts.py} test_gluck_accounts.py
            ${py}/bin/python -u test_gluck_accounts.py 2>&1 | tee $out
          '';

          settings = pkgs.runCommand "gluck-accounts-settings-tests" { } ''
            set -o pipefail
            cp -r ${accountsSrc pkgs}/. . && chmod -R u+w .
            install -m 0644 ${./accounts/test_settings.py} test_settings.py
            ${py}/bin/python -u test_settings.py 2>&1 | tee $out
          '';

          socket = pkgs.runCommand "gluck-services-socket" { } ''
            set -o pipefail
            export SOCKET_ACTIVATE=${pkgs.systemd}/bin/systemd-socket-activate
            export ACCOUNTS_ENTRY=${accountsSrc pkgs}/gluck_accounts.py
            export TODO_ENTRY=${./todo/gluck_todo.py}
            ${py}/bin/python -u ${./tests/test_socket.py} 2>&1 | tee $out
          '';
        }
      );
    };
}
