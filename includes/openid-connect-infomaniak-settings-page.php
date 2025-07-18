<?php
/**
 * Plugin Admin settings page class.
 *
 * @package   OpenID_Connect_Infomaniak
 * @category  Settings
 * @author    Jonathan infomaniak <jonathan@infomaniak.com>
 * @copyright 2015-2023 infomaniak
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 */

/**
 * OpenID_Connect_Infomaniak_Settings_Page class.
 *
 * Admin settings page.
 *
 * @package OpenID_Connect_Infomaniak
 * @category  Settings
 */
class OpenID_Connect_Infomaniak_Settings_Page {

	/**
	 * Local copy of the settings provided by the base plugin.
	 *
	 * @var OpenID_Connect_Infomaniak_Option_Settings
	 */
	private $settings;

	/**
	 * Instance of the plugin logger.
	 *
	 * @var OpenID_Connect_Infomaniak_Option_Logger
	 */
	private $logger;

	/**
	 * The controlled list of settings & associated defined during
	 * construction for i18n reasons.
	 *
	 * @var array
	 */
	private $settings_fields = array();

	/**
	 * Options page slug.
	 *
	 * @var string
	 */
	private $options_page_name = 'openid-connect-infomaniak-settings';

	/**
	 * Options page settings group name.
	 *
	 * @var string
	 */
	private $settings_field_group;

	/**
	 * Settings page class constructor.
	 *
	 * @param OpenID_Connect_Infomaniak_Option_Settings $settings The plugin settings object.
	 * @param OpenID_Connect_Infomaniak_Option_Logger   $logger   The plugin logging class object.
	 */
	public function __construct( OpenID_Connect_Infomaniak_Option_Settings $settings, OpenID_Connect_Infomaniak_Option_Logger $logger ) {

		$this->settings             = $settings;
		$this->logger               = $logger;
		$this->settings_field_group = $this->settings->get_option_name() . '-group';

		$fields = $this->get_settings_fields();

		// Some simple pre-processing.
		foreach ( $fields as $key => &$field ) {
			$field['key']  = $key;
			$field['name'] = $this->settings->get_option_name() . '[' . $key . ']';
		}

		// Allow alterations of the fields.
		$this->settings_fields = $fields;
	}

	/**
	 * Hook the settings page into WordPress.
	 *
	 * @param OpenID_Connect_Infomaniak_Option_Settings $settings A plugin settings object instance.
	 * @param OpenID_Connect_Infomaniak_Option_Logger   $logger   A plugin logger object instance.
	 *
	 * @return void
	 */
	public static function register( OpenID_Connect_Infomaniak_Option_Settings $settings, OpenID_Connect_Infomaniak_Option_Logger $logger ) {
		$settings_page = new self( $settings, $logger );

		// Add our options page the the admin menu.
		add_action( 'admin_menu', array( $settings_page, 'admin_menu' ) );

		// Register our settings.
		add_action( 'admin_init', array( $settings_page, 'admin_init' ) );
	}

	/**
	 * Implements hook admin_menu to add our options/settings page to the
	 *  dashboard menu.
	 *
	 * @return void
	 */
	public function admin_menu() {
		add_options_page(
			__( 'Infomaniak OpenID Connect - Generic Client', 'infomaniak-openid-connect' ),
			__( 'Infomaniak OpenID Connect Client', 'infomaniak-openid-connect' ),
			'manage_options',
			$this->options_page_name,
			array( $this, 'settings_page' )
		);
	}

	/**
	 * Implements hook admin_init to register our settings.
	 *
	 * @return void
	 */
	public function admin_init() {
		register_setting(
			$this->settings_field_group,
			$this->settings->get_option_name(),
			array(
				$this,
				'sanitize_settings',
			)
		);

		add_settings_section(
			'client_settings',
			__( 'Client Settings', 'infomaniak-openid-connect' ),
			array( $this, 'client_settings_description' ),
			$this->options_page_name
		);

		add_settings_section(
			'user_settings',
			__( 'WordPress User Settings', 'infomaniak-openid-connect' ),
			array( $this, 'user_settings_description' ),
			$this->options_page_name
		);

		add_settings_section(
			'authorization_settings',
			__( 'Authorization Settings', 'infomaniak-openid-connect' ),
			array( $this, 'authorization_settings_description' ),
			$this->options_page_name
		);

		add_settings_section(
			'log_settings',
			__( 'Log Settings', 'infomaniak-openid-connect' ),
			array( $this, 'log_settings_description' ),
			$this->options_page_name
		);

		// Preprocess fields and add them to the page.
		foreach ( $this->settings_fields as $key => $field ) {
			// Make sure each key exists in the settings array.
			if ( ! isset( $this->settings->{ $key } ) ) {
				$this->settings->{ $key } = null;
			}

			// Determine appropriate output callback.
			switch ( $field['type'] ) {
				case 'checkbox':
					$callback = 'do_checkbox';
					break;

				case 'select':
					$callback = 'do_select';
					break;

				case 'text':
				default:
					$callback = 'do_text_field';
					break;
			}

			// Add the field.
			add_settings_field(
				$key,
				$field['title'],
				array( $this, $callback ),
				$this->options_page_name,
				$field['section'],
				$field
			);
		}
	}

	/**
	 * Get the plugin settings fields definition.
	 *
	 * @return array
	 */
	private function get_settings_fields() {

		/**
		 * Simple settings fields have:
		 *
		 * - title
		 * - description
		 * - type ( checkbox | text | select )
		 * - section - settings/option page section ( client_settings | authorization_settings )
		 * - example (optional example will appear beneath description and be wrapped in <code>)
		 */
		$fields = array(
			'login_type'        => array(
				'title'       => __( 'Login Type', 'infomaniak-openid-connect' ),
				'description' => __( 'Select how the client (login form) should provide login options.', 'infomaniak-openid-connect' ),
				'type'        => 'select',
				'options'     => array(
					'button' => __( 'OpenID Connect button on login form', 'infomaniak-openid-connect' ),
					'auto'   => __( 'Auto Login - SSO', 'infomaniak-openid-connect' ),
				),
				'disabled'    => defined( 'INFOMANIAK_OIDC_LOGIN_TYPE' ),
				'section'     => 'client_settings',
			),
			'client_id'         => array(
				'title'       => __( 'Client ID', 'infomaniak-openid-connect' ),
				'description' => __( 'The ID this client will be recognized as when connecting the to Identity provider server.', 'infomaniak-openid-connect' ),
				'example'     => 'my-wordpress-client-id',
				'type'        => 'text',
				'disabled'    => defined( 'INFOMANIAK_OIDC_CLIENT_ID' ),
				'section'     => 'client_settings',
			),
			'client_secret'     => array(
				'title'       => __( 'Client Secret Key', 'infomaniak-openid-connect' ),
				'description' => __( 'Arbitrary secret key the server expects from this client. Can be anything, but should be very unique.', 'infomaniak-openid-connect' ),
				'type'        => 'text',
				'disabled'    => defined( 'INFOMANIAK_OIDC_CLIENT_SECRET' ),
				'section'     => 'client_settings',
			),
			'scope'             => array(
				'title'       => __( 'OpenID Scope', 'infomaniak-openid-connect' ),
				'description' => __( 'Space separated list of scopes this client should access.', 'infomaniak-openid-connect' ),
				'example'     => 'email profile openid',
				'type'        => 'text',
				'disabled'    => defined( 'INFOMANIAK_OIDC_CLIENT_SCOPE' ),
				'section'     => 'client_settings',
			),
			'endpoint_login'    => array(
				'title'       => __( 'Login Endpoint URL', 'infomaniak-openid-connect' ),
				'description' => __( 'Identify provider authorization endpoint.', 'infomaniak-openid-connect' ),
				//'example'     => 'https://example.com/oauth2/authorize',
				'type'        => 'text',
				'disabled'    => true,
				'readonly'    => true,
				'section'     => 'client_settings',
			),
			'endpoint_userinfo' => array(
				'title'       => __( 'Userinfo Endpoint URL', 'infomaniak-openid-connect' ),
				'description' => __( 'Identify provider User information endpoint.', 'infomaniak-openid-connect' ),
				//'example'     => 'https://example.com/oauth2/UserInfo',
				'type'        => 'text',
				'disabled'    => true,
                'readonly'    => true,
				'section'     => 'client_settings',
			),
			'endpoint_token'    => array(
				'title'       => __( 'Token Validation Endpoint URL', 'infomaniak-openid-connect' ),
				'description' => __( 'Identify provider token endpoint.', 'infomaniak-openid-connect' ),
				//'example'     => 'https://example.com/oauth2/token',
				'type'        => 'text',
				'disabled'    => true,
                'readonly'    => true,
				'section'     => 'client_settings',
			),
            /*
			'endpoint_end_session'    => array(
				'title'       => __( 'End Session Endpoint URL', 'infomaniak-openid-connect' ),
				'description' => __( 'Identify provider logout endpoint.', 'infomaniak-openid-connect' ),
				'example'     => 'https://example.com/oauth2/logout',
				'type'        => 'text',
				'disabled'    => defined( 'INFOMANIAK_OIDC_ENDPOINT_LOGOUT_URL' ),
				'section'     => 'client_settings',
			),
            */
			'acr_values'    => array(
				'title'       => __( 'ACR values', 'infomaniak-openid-connect' ),
				'description' => __( 'Use a specific defined authentication contract from the IDP - optional.', 'infomaniak-openid-connect' ),
				'type'        => 'text',
				'disabled'    => defined( 'INFOMANIAK_OIDC_ACR_VALUES' ),
				'section'     => 'client_settings',
			),
			'identity_key'     => array(
				'title'       => __( 'Identity Key', 'infomaniak-openid-connect' ),
				'description' => __( 'Where in the user claim array to find the user\'s identification data. Possible standard values: preferred_username, name, or sub. If you\'re having trouble, use "sub".', 'infomaniak-openid-connect' ),
				'example'     => 'sub',
				'type'        => 'text',
				'section'     => 'client_settings',
			),
			'no_sslverify'      => array(
				'title'       => __( 'Disable SSL Verify', 'infomaniak-openid-connect' ),
				// translators: %1$s HTML tags for layout/styles, %2$s closing HTML tag for styles.
				'description' => sprintf( __( 'Do not require SSL verification during authorization. The OAuth extension uses curl to make the request. By default CURL will generally verify the SSL certificate to see if its valid an issued by an accepted CA. This setting disabled that verification.%1$sNot recommended for production sites.%2$s', 'infomaniak-openid-connect' ), '<br><strong>', '</strong>' ),
				'type'        => 'checkbox',
				'section'     => 'client_settings',
			),
			'http_request_timeout'      => array(
				'title'       => __( 'HTTP Request Timeout', 'infomaniak-openid-connect' ),
				'description' => __( 'Set the timeout for requests made to the IDP. Default value is 5.', 'infomaniak-openid-connect' ),
				'example'     => 30,
				'type'        => 'text',
				'section'     => 'client_settings',
			),
			'enforce_privacy'   => array(
				'title'       => __( 'Enforce Privacy', 'infomaniak-openid-connect' ),
				'description' => __( 'Require users be logged in to see the site.', 'infomaniak-openid-connect' ),
				'type'        => 'checkbox',
				'disabled'    => defined( 'OIDC_ENFORCE_PRIVACY' ),
				'section'     => 'authorization_settings',
			),
			'alternate_redirect_uri'   => array(
				'title'       => __( 'Alternate Redirect URI', 'infomaniak-openid-connect' ),
				'description' => __( 'Provide an alternative redirect route. Useful if your server is causing issues with the default admin-ajax method. You must flush rewrite rules after changing this setting. This can be done by saving the Permalinks settings page.', 'infomaniak-openid-connect' ),
				'type'        => 'checkbox',
				'section'     => 'authorization_settings',
			),
			'nickname_key'     => array(
				'title'       => __( 'Nickname Key', 'infomaniak-openid-connect' ),
				'description' => __( 'Where in the user claim array to find the user\'s nickname. Possible standard values: preferred_username, name, or sub.', 'infomaniak-openid-connect' ),
				'example'     => 'name',
				'type'        => 'text',
				'section'     => 'client_settings',
			),
			'email_format'     => array(
				'title'       => __( 'Email Formatting', 'infomaniak-openid-connect' ),
				'description' => __( 'String from which the user\'s email address is built. Specify "{email}" as long as the user claim contains an email claim.', 'infomaniak-openid-connect' ),
				'example'     => '{email}',
				'type'        => 'text',
				'section'     => 'client_settings',
			),
			'displayname_format'     => array(
				'title'       => __( 'Display Name Formatting', 'infomaniak-openid-connect' ),
				'description' => __( 'String from which the user\'s display name is built.', 'infomaniak-openid-connect' ),
				'example'     => '{given_name} {family_name}',
				'type'        => 'text',
				'section'     => 'client_settings',
			),
			'identify_with_username'     => array(
				'title'       => __( 'Identify with User Name', 'infomaniak-openid-connect' ),
				'description' => __( 'If checked, the user\'s identity will be determined by the user name instead of the email address.', 'infomaniak-openid-connect' ),
				'type'        => 'checkbox',
				'section'     => 'client_settings',
			),
			'state_time_limit'     => array(
				'title'       => __( 'State time limit', 'infomaniak-openid-connect' ),
				'description' => __( 'State valid time in seconds. Defaults to 180', 'infomaniak-openid-connect' ),
				'type'        => 'number',
				'section'     => 'client_settings',
			),
			'token_refresh_enable'   => array(
				'title'       => __( 'Enable Refresh Token', 'infomaniak-openid-connect' ),
				'description' => __( 'If checked, support refresh tokens used to obtain access tokens from supported IDPs.', 'infomaniak-openid-connect' ),
				'type'        => 'checkbox',
				'section'     => 'client_settings',
			),
			'link_existing_users'   => array(
				'title'       => __( 'Link Existing Users', 'infomaniak-openid-connect' ),
				'description' => __( 'If a WordPress account already exists with the same identity as a newly-authenticated user over OpenID Connect, login as that user instead of generating an error.', 'infomaniak-openid-connect' ),
				'type'        => 'checkbox',
				'disabled'    => defined( 'OIDC_LINK_EXISTING_USERS' ),
				'section'     => 'user_settings',
			),
			'create_if_does_not_exist'   => array(
				'title'       => __( 'Create user if does not exist', 'infomaniak-openid-connect' ),
				'description' => __( 'If the user identity is not linked to an existing WordPress user, it is created. If this setting is not enabled, and if the user authenticates with an account which is not linked to an existing WordPress user, then the authentication will fail.', 'infomaniak-openid-connect' ),
				'type'        => 'checkbox',
				'disabled'    => defined( 'OIDC_CREATE_IF_DOES_NOT_EXIST' ),
				'section'     => 'user_settings',
			),
			'redirect_user_back'   => array(
				'title'       => __( 'Redirect Back to Origin Page', 'infomaniak-openid-connect' ),
				'description' => __( 'After a successful OpenID Connect authentication, this will redirect the user back to the page on which they clicked the OpenID Connect login button. This will cause the login process to proceed in a traditional WordPress fashion. For example, users logging in through the default wp-login.php page would end up on the WordPress Dashboard and users logging in through the WooCommerce "My Account" page would end up on their account page.', 'infomaniak-openid-connect' ),
				'type'        => 'checkbox',
				'disabled'    => defined( 'OIDC_REDIRECT_USER_BACK' ),
				'section'     => 'user_settings',
			),
			'redirect_on_logout'   => array(
				'title'       => __( 'Redirect to the login screen when session is expired', 'infomaniak-openid-connect' ),
				'description' => __( 'When enabled, this will automatically redirect the user back to the WordPress login page if their access token has expired.', 'infomaniak-openid-connect' ),
				'type'        => 'checkbox',
				'disabled'    => defined( 'OIDC_REDIRECT_ON_LOGOUT' ),
				'section'     => 'user_settings',
			),
			'enable_logging'    => array(
				'title'       => __( 'Enable Logging', 'infomaniak-openid-connect' ),
				'description' => __( 'Very simple log messages for debugging purposes.', 'infomaniak-openid-connect' ),
				'type'        => 'checkbox',
				'disabled'    => defined( 'OIDC_ENABLE_LOGGING' ),
				'section'     => 'log_settings',
			),
			'log_limit'         => array(
				'title'       => __( 'Log Limit', 'infomaniak-openid-connect' ),
				'description' => __( 'Number of items to keep in the log. These logs are stored as an option in the database, so space is limited.', 'infomaniak-openid-connect' ),
				'type'        => 'number',
				'disabled'    => defined( 'OIDC_LOG_LIMIT' ),
				'section'     => 'log_settings',
			),
		);

		return apply_filters( 'openid-connect-infomaniak-settings-fields', $fields );
	}

	/**
	 * Sanitization callback for settings/option page.
	 *
	 * @param array $input The submitted settings values.
	 *
	 * @return array
	 */
	public function sanitize_settings( $input ) {
		$options = array();

		// Loop through settings fields to control what we're saving.
		foreach ( $this->settings_fields as $key => $field ) {
			if ( isset( $input[ $key ] ) ) {
				$options[ $key ] = sanitize_text_field( trim( $input[ $key ] ) );
			} else {
				$options[ $key ] = '';
			}
		}

		return $options;
	}

	/**
	 * Output the options/settings page.
	 *
	 * @return void
	 */
	public function settings_page() {
		wp_enqueue_style( 'infomaniak-openid-connect-admin', plugin_dir_url( __DIR__ ) . 'css/styles-admin.css', array(), OpenID_Connect_Infomaniak::VERSION, 'all' );

		$redirect_uri = admin_url( 'admin-ajax.php?action=openid-connect-authorize' );

		if ( $this->settings->alternate_redirect_uri ) {
			$redirect_uri = site_url( '/openid-connect-authorize' );
		}
		?>
		<div class="wrap">
            <div class="infomaniak-admin-header">
                <h2><?php print esc_html( get_admin_page_title() ); ?></h2>
                <image class="logo" src="<?php print plugin_dir_url( __DIR__ ) . 'images/logo-k.svg'; ?>" alt="Infomaniak Logo" width="50" height="50" />
            </div>

			<form method="post" action="options.php">
				<?php
				settings_fields( $this->settings_field_group );
				do_settings_sections( $this->options_page_name );
				submit_button();
				?>
			</form>

			<h4><?php esc_html_e( 'Notes', 'infomaniak-openid-connect' ); ?></h4>

			<p class="description">
				<strong><?php esc_html_e( 'Redirect URI', 'infomaniak-openid-connect' ); ?></strong>
				<code><?php print esc_url( $redirect_uri ); ?></code>
			</p>
			<p class="description">
				<strong><?php esc_html_e( 'Login Button Shortcode', 'infomaniak-openid-connect' ); ?></strong>
				<code>[infomaniak_connect_generic_login_button]</code>
			</p>
			<p class="description">
				<strong><?php esc_html_e( 'Authentication URL Shortcode', 'infomaniak-openid-connect' ); ?></strong>
				<code>[infomaniak_connect_generic_auth_url]</code>
			</p>

			<?php if ( $this->settings->enable_logging ) { ?>
				<h2><?php esc_html_e( 'Logs', 'infomaniak-openid-connect' ); ?></h2>
				<div id="logger-table-wrapper">
					<?php print wp_kses_post( $this->logger->get_logs_table() ); ?>
				</div>

			<?php } ?>
		</div>
		<?php
	}

	/**
	 * Output a standard text field.
	 *
	 * @param array $field The settings field definition array.
	 *
	 * @return void
	 */
	public function do_text_field( $field ) {
		?>
		<input type="<?php print esc_attr( $field['type'] ); ?>"
			id="<?php print esc_attr( $field['key'] ); ?>"
			class="large-text<?php echo ( ! empty( $field['disabled'] ) && boolval( $field['disabled'] ) === true ) ? ' disabled' : ''; ?>"
			name="<?php print esc_attr( $field['name'] ); ?>"
			<?php echo ( ! empty( $field['disabled'] ) && boolval( $field['disabled'] ) === true ) ? ' disabled' : ''; ?>
			<?php echo ( ! empty( $field['readonly'] ) && boolval( $field['readonly'] ) === true ) ? ' readonly' : ''; ?>
			value="<?php print esc_attr( $this->settings->{ $field['key'] } ); ?>">
		<?php
		$this->do_field_description( $field );
	}

	/**
	 * Output a checkbox for a boolean setting.
	 *  - hidden field is default value so we don't have to check isset() on save.
	 *
	 * @param array $field The settings field definition array.
	 *
	 * @return void
	 */
	public function do_checkbox( $field ) {
		$hidden_value = 0;
		if ( ! empty( $field['disabled'] ) && boolval( $field['disabled'] ) === true ) {
			$hidden_value = intval( $this->settings->{ $field['key'] } );
		}
		?>
		<input type="hidden" name="<?php print esc_attr( $field['name'] ); ?>" value="<?php print esc_attr( strval( $hidden_value ) ); ?>">
		<input type="checkbox"
			   id="<?php print esc_attr( $field['key'] ); ?>"
				 name="<?php print esc_attr( $field['name'] ); ?>"
				 <?php echo ( ! empty( $field['disabled'] ) && boolval( $field['disabled'] ) === true ) ? ' disabled="disabled"' : ''; ?>
			   value="1"
			<?php checked( $this->settings->{ $field['key'] }, 1 ); ?>>
		<?php
		$this->do_field_description( $field );
	}

	/**
	 * Output a select control.
	 *
	 * @param array $field The settings field definition array.
	 *
	 * @return void
	 */
	public function do_select( $field ) {
		$current_value = isset( $this->settings->{ $field['key'] } ) ? $this->settings->{ $field['key'] } : '';
		?>
		<select
			id="<?php print esc_attr( $field['key'] ); ?>"
			name="<?php print esc_attr( $field['name'] ); ?>"
			<?php echo ( ! empty( $field['disabled'] ) && boolval( $field['disabled'] ) === true ) ? ' disabled' : ''; ?>
			>
			<?php foreach ( $field['options'] as $value => $text ) : ?>
				<option value="<?php print esc_attr( $value ); ?>" <?php selected( $value, $current_value ); ?>><?php print esc_html( $text ); ?></option>
			<?php endforeach; ?>
		</select>
		<?php
		$this->do_field_description( $field );
	}

	/**
	 * Output the field description, and example if present.
	 *
	 * @param array $field The settings field definition array.
	 *
	 * @return void
	 */
	public function do_field_description( $field ) {
		?>
		<p class="description">
			<?php print wp_kses_post( $field['description'] ); ?>
			<?php if ( isset( $field['example'] ) ) : ?>
				<br/><strong><?php esc_html_e( 'Example', 'infomaniak-openid-connect' ); ?>: </strong>
				<code><?php print esc_html( $field['example'] ); ?></code>
			<?php endif; ?>
		</p>
		<?php
	}

	/**
	 * Output the 'Client Settings' plugin setting section description.
	 *
	 * @return void
	 */
	public function client_settings_description() {
		esc_html_e( 'Enter your Infomaniak OpenID Connect identity provider settings.', 'infomaniak-openid-connect' );
	}

	/**
	 * Output the 'WordPress User Settings' plugin setting section description.
	 *
	 * @return void
	 */
	public function user_settings_description() {
		esc_html_e( 'Modify the interaction between OpenID Connect and WordPress users.', 'infomaniak-openid-connect' );
	}

	/**
	 * Output the 'Authorization Settings' plugin setting section description.
	 *
	 * @return void
	 */
	public function authorization_settings_description() {
		esc_html_e( 'Control the authorization mechanics of the site.', 'infomaniak-openid-connect' );
	}

	/**
	 * Output the 'Log Settings' plugin setting section description.
	 *
	 * @return void
	 */
	public function log_settings_description() {
		esc_html_e( 'Log information about login attempts through OpenID Connect Infomaniak.', 'infomaniak-openid-connect' );
	}
}
