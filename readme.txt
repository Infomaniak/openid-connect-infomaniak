=== Infomaniak Connect for OpenID ===
Tags: oauth, openid, infomaniak
Tested up to: 6.8
Stable tag: 1.0.4
License: GPLv2 or later

The Infomaniak Connect for OpenID plugin allows easy integration of OAuth2 authentication with Infomaniak into your WordPress site. With this plugin, users can log into your WordPress site using their Infomaniak credentials, which simplifies the authentication process and enhances security.

== Changelog ==

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
