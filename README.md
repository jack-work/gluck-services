# gluck-services

Two small authenticated APIs served behind the
[kelliher-web](https://github.com/jack-work/kelliher-web) hosting platform
and gated by Authelia forward-auth (password + 2FA):

- **gluck-accounts** (`POST /accounts`) — mints user accounts in lldap via
  its GraphQL API. Requires the `accounts-create` group. New users
  get a random temporary password, returned exactly once.
- **gluck-todo** (`/todos`) — CRUD over a DuckDB-backed todo table with
  per-item ACLs (`Read`/`Write`/`Delete`/`Share`). Creating requires the
  `todo-create` group; the creator gets all four permissions and can
  grant them to others via `POST /todos/{id}/share`. Items you cannot Read
  return 404.

Both services bind to loopback and trust the `Remote-User`/`Remote-Groups`
headers — safe only because Caddy strips client-supplied `Remote-*` headers
and sets them from Authelia's forward-auth response. Never expose these
ports directly.

The NixOS module registers `services.kelliher-web.sites.gluck`
(`gluck.kelliher.info`, `requireAuth = true`) with `/accounts*` routed to
gluck-accounts and everything else to gluck-todo.

## Usage

```nix
inputs.gluck-services.url = "github:jack-work/gluck-services";

# in the host config:
imports = [ inputs.gluck-services.nixosModules.default ];
services.gluck-accounts = {
  enable = true;
  passwordFile = config.sops.secrets.gluck-accounts-lldap-password.path;
};
services.gluck-todo.enable = true;
```
