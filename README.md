# No-Auth OIDC Server

This repository provides a minimal OpenID Connect (OIDC) server for personal use in private networks. No user management or authentication is implemented—this is for internal, non-public setups only.

## Description
A simple OIDC server for development, testing, or private use. All configuration is done via environment variables. No authentication or user management is included. **Do not use in public or production environments!**

## Endpoints
| Endpoint                                 | Description                                 |
|------------------------------------------|---------------------------------------------|
| `/`                                      | Health check (returns status)               |
| `/.well-known/openid-configuration`      | OIDC discovery endpoint                     |
| `/.well-known/oidc-discovery`            | Alternative OIDC discovery endpoint         |
| `/authorize`                             | Issues a static code for OIDC flow          |
| `/token`                                 | Issues a JWT token if the code is valid     |
| `/userinfo`                              | Returns static user info                    |
| `/jwks`                                  | Returns empty JWKS                         |

## Environment Variables
| Variable                     | Description                                 | Example Value                        |
|:-----------------------------|:--------------------------------------------|--------------------------------------|
| `NO_AUTH_REDIRECT_URL`       | Redirect URI for OIDC client                | `http://localhost:3000/auth/oidc/callback` |
| `NO_AUTH_OIDC_HOST`          | Hostname/URL of this OIDC server            | `http://localhost:4000`                |
| `NO_AUTH_OIDC_CLIENT_ID`     | OIDC client ID                              | `client-id`                       |
| `NO_AUTH_OIDC_CLIENT_SECRET` | OIDC client secret                        | `client-secret`                       |
| `USERS_JSON_PATH`            | Path to users.json file (default: `/config/users.json`) | `/config/users.json`     |

Set these variables in your Docker environment or `.env` file to configure the server for your needs.

## User Configuration

User data is loaded from an external `users.json` file. This allows you to customize user information without rebuilding the Docker image.

### users.json Structure

Create a `users.json` file with the following structure:

```json
{
  "user": {
    "sub": "user123",
    "preferred_username": "john.doe",
    "name": "John Doe",
    "email": "john@example.com",
    "roles": ["umami-admin", "app-user"],
    "realm_access": {
      "roles": ["umami-admin", "app-user"]
    },
    "groups": ["team-developers", "team-admins", "project-alpha"]
  }
}
```

### Loading users.json

**For Docker:**
Mount your `users.json` file to `/config/users.json` in the container using a volume:

```yaml
services:
  oidc:
    container_name: oidc
    image: ghcr.io/ceviixx/no-auth-oidc-server:latest
    ports:
      - "4000:4000"
    volumes:
      - ./users.json:/config/users.json:ro
    restart: unless-stopped
    environment:
      - NO_AUTH_REDIRECT_URL=REPLACE_ME
      - NO_AUTH_OIDC_HOST=REPLACE_ME
      - NO_AUTH_OIDC_CLIENT_ID=REPLACE_ME
      - NO_AUTH_OIDC_CLIENT_SECRET=REPLACE_ME
```

**For Local Development:**
Place `users.json` in the same directory as `server.py`. The server will automatically find and load it.

**Custom Path:**
Set the `USERS_JSON_PATH` environment variable to specify a different path.

**Fallback:**
If no `users.json` file is found, the server uses a default user configuration.
  

## Example docker-compose.yml
```yaml
services:
	oidc:
		container_name: oidc
		image: ghcr.io/ceviixx/no-auth-oidc-server:latest
		ports:
			- "4000:4000"
		volumes:
			- ./users.json:/config/users.json:ro
		restart: unless-stopped
		environment:
			- NO_AUTH_REDIRECT_URL=REPLACE_ME
			- NO_AUTH_OIDC_HOST=REPLACE_ME
			- NO_AUTH_OIDC_CLIENT_ID=REPLACE_ME
			- NO_AUTH_OIDC_CLIENT_SECRET=REPLACE_ME
```


