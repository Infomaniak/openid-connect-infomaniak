# OpenID Connect Infomaniak Client

## Description

The OpenID Connect Infomaniak Client plugin allows easy integration of OAuth2 authentication with Infomaniak into your WordPress site. With this plugin, users can log into your WordPress site using their Infomaniak credentials, which simplifies the authentication process and enhances security.

## Features

- User authentication via Infomaniak accounts
- Simplified OAuth2/OpenID Connect integration configuration
- Login button customization
- Automatic creation of WordPress accounts linked to Infomaniak accounts
- Compatibility with existing WordPress roles and permissions
- Options logging for debugging

## Installation

1. Download the plugin and extract its contents to the `/wp-content/plugins/` directory of your WordPress site
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Access the plugin settings via 'Settings > OpenID Connect Infomaniak'

## External Service Usage

This plugin integrates with Infomaniak's OIDC (OpenID Connect) service to handle user authentication. When using this plugin, certain user data will be transmitted to and processed by Infomaniak's authentication servers.

### Data Transmission

The following data may be transmitted to Infomaniak's servers during the authentication process:
- User credentials (handled securely by Infomaniak's login service)
- Authentication tokens
- Basic user profile information (email, name, etc.)
- Session information

### Service Information

- **Service Provider**: Infomaniak Network SA
- **Service Website**: [https://www.infomaniak.com](https://www.infomaniak.com)
- **Authentication Endpoint**: [https://login.infomaniak.com/authorize](https://login.infomaniak.com/authorize)
- **User Information Endpoint**: [https://login.infomaniak.com/oauth2/userinfo](https://login.infomaniak.com/oauth2/userinfo)
- **Token Endpoint**: [https://login.infomaniak.com/token](https://login.infomaniak.com/token)

### Legal Information

By using this plugin, you agree to Infomaniak's terms of service and privacy policy:
- [Terms of Service](https://www.infomaniak.com/en/terms)
- [Privacy Policy](https://www.infomaniak.com/en/privacy)

The plugin developer is not responsible for the privacy practices or content of Infomaniak's services. Please review Infomaniak's policies to understand how they handle your data.

## Configuration

### Prerequisites

Before configuring the plugin, you must create an OAuth2 application in your Infomaniak space:

1. Log into your Infomaniak account
2. Access the Cloud Computing > Auth product page: https://manager.infomaniak.com/v3/ng/products/cloud/ik-auth
3. Create a new application
4. Note the client ID and client secret that will be provided to you
5. Configure the redirect URL to: `https://your-site.com/openid-connect-authorize`

### Plugin Settings

Access the plugin configuration page (Settings > OpenID Connect Infomaniak) and fill in the following information:

- **Client ID**: The identifier of your Infomaniak OAuth2 application
- **Client Secret**: The secret of your Infomaniak OAuth2 application
- **Authorization URL**: URL of the Infomaniak authorization endpoint
- **Token URL**: URL of the Infomaniak token endpoint
- **User Information URL**: URL of the Infomaniak user information endpoint
- **Authentication Scope**: The required OAuth2 scopes (typically "openid email profile")

## Usage

Once configured, the plugin will automatically add a "Login with Infomaniak" button to your WordPress login form. Users can click this button to be redirected to the Infomaniak authentication page.

After successful authentication, users will be redirected to your WordPress site and automatically logged in. If it's their first login, a WordPress account will be automatically created with their Infomaniak profile information.

## Customization

The plugin offers several customization options:

- Login button text and appearance
- Post-authentication redirect behavior
- Automatic user account creation and updates
- User information mapping between Infomaniak and WordPress

## Troubleshooting

If you encounter issues with the plugin:

1. Verify that the client ID and client secret are correctly entered
2. Ensure that the redirect URL is properly configured in the Infomaniak application
3. Check the plugin's options log for more information about potential errors
4. Verify that Infomaniak's OAuth2 endpoints are accessible from your server

## Contributing

Contributions to this plugin are welcome! Feel free to submit pull requests or report issues via the project's GitHub repository.

## License

This plugin is distributed under GPL v2 or later license.

## Credits

This plugin is based on the OpenID Connect Generic library and has been specifically adapted for integration with Infomaniak.
