=== Infomaniak Connect for OpenID ===
Tags: oauth, openid, infomaniak
Tested up to: 6.8
Stable tag: 1.0.5
License: GPLv2 or later

The Infomaniak Connect for OpenID plugin allows easy integration of OAuth2 authentication with Infomaniak into your WordPress site. With this plugin, users can log into your WordPress site using their Infomaniak credentials, which simplifies the authentication process and enhances security.

== Changelog ==

= 1.0.5 =

* Security: Strip access and refresh tokens from user meta, storing id_token only
* Security: Prevent open redirect after OIDC authentication by using wp_safe_redirect
* Security: Sanitize $_GET input at the authentication entry point
* Fix: Address PR review findings for JWT and PKCE code
* Feat: Add PKCE and nonce support to the OIDC authentication flow
* Fix: Verify aggregated claim JWTs using JWKS
* Fix: Refuse empty endpoint_jwks configuration
* Docs: Update token-response meta docblock to reflect id_token-only storage

= 1.0.4 =

* Security: Add JWT signature verification via JWKS endpoint
* Security: Validate ID token claims (expiration, audience, issuer, issued-at)
* Security: Fix open redirect vulnerability via redirect cookie
* Security: Restrict SSL verification bypass to local development environments only
* Security: Add SSRF protection using wp_safe_remote_post/wp_safe_remote_get
* Security: Use cryptographically secure random_bytes for state generation
* Security: Sanitize IDP error codes and descriptions
* Security: Add esc_url_raw sanitization on authentication URL after filter
* Add JWKS endpoint and issuer configuration for Infomaniak IDP
