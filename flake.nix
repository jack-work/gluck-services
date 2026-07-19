{
  description = "gluck-services — authenticated account-minting and todo APIs behind kelliher-web";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
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

            port = lib.mkOption {
              type = lib.types.port;
              default = 9092;
              description = "Loopback port for the accounts API";
            };

            lldapUrl = lib.mkOption {
              type = lib.types.str;
              default = "http://127.0.0.1:17170";
              description = "Base URL of the lldap HTTP API";
            };

            passwordFile = lib.mkOption {
              type = lib.types.path;
              description = "File containing the lldap service-account password (user gluck-accounts)";
            };
          };

          options.services.gluck-todo = {
            enable = lib.mkEnableOption "gluck-todo API (DuckDB-backed todos with per-item ACLs)";

            port = lib.mkOption {
              type = lib.types.port;
              default = 9093;
              description = "Loopback port for the todo API";
            };
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
                path = [ pkgs.lldap ]; # provides lldap_set_password
                environment = {
                  LLDAP_URL = acctCfg.lldapUrl;
                  LLDAP_PASSWORD_FILE = "%d/lldap_password";
                  PORT = toString acctCfg.port;
                };
                serviceConfig = hardened // {
                  User = "gluck-accounts";
                  Group = "gluck-accounts";
                  ExecStart = "${py}/bin/python ${./accounts/gluck_accounts.py}";
                  LoadCredential = [ "lldap_password:${acctCfg.passwordFile}" ];
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
                  PORT = toString todoCfg.port;
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
                proxyTo = todoCfg.port;
              };
              services.kelliher-web.sites.gluck-accounts = lib.mkIf acctCfg.enable {
                subdomains = siteCfg.accountsSubdomains;
                hostnames = siteCfg.extraHostnames.accounts or [ ];
                requireAuth = true;
                proxyTo = acctCfg.port;
              };
            })
          ];
        };
    in
    {
      nixosModules.default = nixosModule;
    };
}
