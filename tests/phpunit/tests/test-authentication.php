<?php
/**
 * Test case for the authentication functionality.
 *
 * @package Infomaniak_OpenID_Connect
 */

/**
 * Test case for the authentication functionality.
 */
class Test_Authentication extends Infomaniak_OpenID_Connect_TestCase {

    /**
     * @var OpenID_Connect_Infomaniak_Client_Wrapper
     */
    private $client_wrapper;

    /**
     * @var OpenID_Connect_Infomaniak_Client
     */
    private $mock_client;

    /**
     * @var OpenID_Connect_Infomaniak_Option_Settings
     */
    private $mock_settings;

    /**
     * @var OpenID_Connect_Infomaniak_Option_Logger
     */
    private $mock_logger;

    /**
     * Set up the test fixture.
     */
    public function set_up() {
        parent::set_up();

        // Create mock dependencies
        $this->mock_client = $this->createMock('OpenID_Connect_Infomaniak_Client');
        $this->mock_settings = $this->createMock('OpenID_Connect_Infomaniak_Option_Settings');
        $this->mock_logger = $this->createMock('OpenID_Connect_Infomaniak_Option_Logger');

        // Create the client wrapper with mocked dependencies
        $this->client_wrapper = new OpenID_Connect_Infomaniak_Client_Wrapper(
            $this->mock_client,
            $this->mock_settings,
            $this->mock_logger
        );
    }

    /**
     * Test authentication URL generation.
     */
    public function test_authentication_url() {

        $auth_url = $this->client_wrapper->get_authentication_url('test-state');

        $this->assertStringContainsString('response_type=code', $auth_url);
        $this->assertStringContainsString('client_id', $auth_url);
        $this->assertStringContainsString('scope=', $auth_url);
    }

    /**
     * Test validate_user with a valid WP_User
     */
    public function test_validate_user_with_valid_user() {
        // Create a mock WP_User
        $user = $this->createMock('WP_User');
        $user->ID = 1;
        $user->user_login = 'testuser';

        // Mock the exists() method to return true
        $user->method('exists')->willReturn(true);

        // Test the method
        $result = $this->client_wrapper->validate_user($user);

        // Assert the result is true
        $this->assertTrue($result);
    }

    /**
     * Test validate_user with an invalid user (not a WP_User)
     */
    public function test_validate_user_with_invalid_user() {
        // Test with a non-WP_User object
        $invalid_user = new stdClass();
        $invalid_user->ID = 1;

        // Test the method
        $result = $this->client_wrapper->validate_user($invalid_user);

        // Assert the result is a WP_Error with the expected code
        $this->assertWPError($result);
        $this->assertEquals('invalid-user', $result->get_error_code());
    }

    /**
     * Test validate_user with a WP_User that doesn't exist
     */
    public function test_validate_user_with_nonexistent_user() {
        // Create a mock WP_User that doesn't exist
        $user = $this->createMock('WP_User');
        $user->ID = 999; // Non-existent user ID

        // Mock the exists() method to return false
        $user->method('exists')->willReturn(false);

        // Test the method
        $result = $this->client_wrapper->validate_user($user);

        // Assert the result is a WP_Error with the expected code
        $this->assertWPError($result);
        $this->assertEquals('invalid-user', $result->get_error_code());
    }

    /**
     * Test validate_user with a WP_Error
     */
    public function test_validate_user_with_wp_error() {
        // Create a WP_Error
        $error = new WP_Error('test-error', 'Test error message');

        // Test the method
        $result = $this->client_wrapper->validate_user($error);

        // Assert the result is a WP_Error with the expected code
        $this->assertWPError($result);
        $this->assertEquals('invalid-user', $result->get_error_code());
    }

    /**
     * Test validate_user with null
     */
    public function test_validate_user_with_null() {
        // Test with null
        $result = $this->client_wrapper->validate_user(null);

        // Assert the result is a WP_Error with the expected code
        $this->assertWPError($result);
        $this->assertEquals('invalid-user', $result->get_error_code());
    }

    /**
     * Test validate_user with false
     */
    public function test_validate_user_with_false() {
        // Test with false
        $result = $this->client_wrapper->validate_user(false);

        // Assert the result is a WP_Error with the expected code
        $this->assertWPError($result);
        $this->assertEquals('invalid-user', $result->get_error_code());
    }

    /**
     * Test get_redirect_to with default values.
     */
    public function test_get_redirect_to_default() {
        // Test default redirect to home URL
        $this->assertEquals(home_url(), $this->client_wrapper->get_redirect_to());
    }

    /**
     * Test get_redirect_to from login form redirects to admin.
     */
    public function test_get_redirect_to_from_login_form() {
        // Set global pagenow to simulate wp-login.php
        global $pagenow;
        $pagenow = 'wp-login.php';

        // Test redirect to admin when coming from login form
        $this->assertEquals(admin_url(), $this->client_wrapper->get_redirect_to());
    }

    /**
     * Test get_redirect_to with redirect_to parameter.
     */
    public function test_get_redirect_to_with_redirect_parameter() {
        $test_url = 'https://example.com/custom-page';

        // Set the redirect_to parameter
        $_REQUEST['redirect_to'] = $test_url;

        // Test that the redirect_to parameter is respected
        $this->assertEquals($test_url, $this->client_wrapper->get_redirect_to());

        // Clean up
        unset($_REQUEST['redirect_to']);
    }

    /**
     * Test get_redirect_to with redirect_user_back enabled.
     */
    public function test_get_redirect_to_with_redirect_user_back() {
        global $wp;

        // Enable redirect_user_back
        $this->mock_settings->method('__get')->with('redirect_user_back')->willReturn(true);
        // Set up test query string
        $test_query = 'test=value&another=test';
        $wp->query_string = $test_query;

        // Test with query string
        $this->assertEquals(home_url('?' . $test_query), $this->client_wrapper->get_redirect_to());

        /*
        // Test with pretty permalinks
        $wp->query_string = '';
        $wp->request = 'test-page';
        $wp->did_permalink = true;

        $_GET = array('param' => 'value');

        $expected = home_url(add_query_arg($_GET, trailingslashit($wp->request)));
        $this->assertEquals($expected, $this->client_wrapper->get_redirect_to());
        */
    }

    /**
     * Test get_redirect_to during logout.
     */
    public function test_get_redirect_to_during_logout() {
        global $pagenow;

        // Simulate logout action
        $pagenow = 'wp-login.php';
        $_GET['action'] = 'logout';

        // Should return empty string during logout
        $this->assertEquals('', $this->client_wrapper->get_redirect_to());

        // Clean up
        unset($_GET['action']);
    }

    /**
     * Test get_redirect_to with filters.
     */
    public function test_get_redirect_to_with_filters() {
        // Test with the new filter
        add_filter('infomaniak-connect-openid-client-redirect-to', function($url) {
            return 'https://example.com/new-filter';
        });

        $this->assertEquals('https://example.com/new-filter', $this->client_wrapper->get_redirect_to());
    }

    /**
     * Test update_allowed_redirect_hosts with a valid end_session URL.
     */
    public function test_update_allowed_redirect_hosts_with_valid_url() {
        // Configure the mock to return a test URL
        $test_url = 'https://example.com/end_session';
        $this->mock_settings->method('__get')->with('endpoint_end_session')->willReturn($test_url);

        // Initial allowed hosts
        $allowed_hosts = array('wordpress.org');

        // Expected result should include the host from the end_session URL
        $expected = array('wordpress.org', 'example.com');

        // Test the method
        $result = $this->client_wrapper->update_allowed_redirect_hosts($allowed_hosts);

        $this->assertEquals($expected, $result);
    }

    /**
     * Test update_allowed_redirect_hosts with an invalid end_session URL.
     */
    public function test_update_allowed_redirect_hosts_with_invalid_url() {
        // Configure the mock to return an invalid URL
        $this->mock_settings->method('__get')->with('endpoint_end_session')->willReturn('not-a-valid-url');

        // Initial allowed hosts
        $allowed_hosts = array('wordpress.org');

        // Test the method with an invalid URL should return false
        $result = $this->client_wrapper->update_allowed_redirect_hosts($allowed_hosts);

        $this->assertFalse($result);
    }

    /**
     * Test update_allowed_redirect_hosts with an empty end_session URL.
     */
    public function test_update_allowed_redirect_hosts_with_empty_url() {
        // Configure the mock to return an empty URL
        $this->mock_settings->method('__get')->with('endpoint_end_session')->willReturn('');

        // Initial allowed hosts
        $allowed_hosts = array('wordpress.org');

        // Test the method with an empty URL should return false
        $result = $this->client_wrapper->update_allowed_redirect_hosts($allowed_hosts);

        $this->assertFalse($result);
    }


    /**
     * Test get_end_session_logout_redirect_url with auto login type and WP logout URL.
     */
    public function test_get_end_session_logout_redirect_url_with_auto_login_and_wp_logout() {
        // Create a mock user
        $user = $this->factory()->user->create_and_get();

        // Set up the token response and claim
        $token_response = array('id_token' => 'test-id-token');
        $claim = array('iss' => 'https://idp.example.com');

         // Set user meta for the test
        update_user_meta($user->ID, 'infomaniak-connect-openid-last-token-response', $token_response);
        update_user_meta($user->ID, 'infomaniak-connect-openid-last-id-token-claim', $claim);

        // Configure the mock settings
        $this->mock_settings->method('__get')
            ->will($this->returnValueMap([
                ['endpoint_end_session', 'https://example.com/end_session'],
                ['login_type', 'auto']
            ]));

        // Test with WP logout URL
        $result = $this->client_wrapper->get_end_session_logout_redirect_url(
            site_url('wp-login.php?loggedout=true'),
            '',
            $user
        );

        $expected = 'https://example.com/end_session?id_token_hint=test-id-token&post_logout_redirect_uri=' .
                   urlencode('http://example.org');

        // Should return the home URL for auto login type with WP logout
        $this->assertEquals($expected, $result);
    }

    /**
     * Test get_end_session_logout_redirect_url with Google as IDP.
     */
    public function test_get_end_session_logout_redirect_url_with_google_idp() {
        // Create a mock user
        $user = $this->factory()->user->create_and_get();

        // Set up the token response and claim for Google
        $token_response = array('id_token' => 'test-google-id-token');
        $claim = array('iss' => 'https://accounts.google.com');

        // Set user meta for the test
        update_user_meta($user->ID, 'infomaniak-connect-openid-last-token-response', $token_response);
        update_user_meta($user->ID, 'infomaniak-connect-openid-last-id-token-claim', $claim);

        // Configure the mock settings
        $this->mock_settings->method('__get')
            ->will($this->returnValueMap([
                ['endpoint_end_session', 'https://example.com/end_session'],
                ['login_type', 'auto']
            ]));

        // Test the method
        $result = $this->client_wrapper->get_end_session_logout_redirect_url(
            'https://example.com/redirect',
            'https://example.com/requested-redirect',
            $user
        );

        // Should return the original redirect URL for Google
        $this->assertEquals('https://example.com/redirect', $result);
    }

    /**
     * Test get_end_session_logout_redirect_url with standard IDP.
     */
    public function test_get_end_session_logout_redirect_url_with_standard_idp() {
        // Create a mock user
        $user = $this->factory()->user->create_and_get();

        // Set up the token response and claim for a standard IDP
        $token_response = array('id_token' => 'test-id-token');
        $claim = array('iss' => 'https://idp.example.com');

        // Set user meta for the test
        update_user_meta($user->ID, 'infomaniak-connect-openid-last-token-response', $token_response);
        update_user_meta($user->ID, 'infomaniak-connect-openid-last-id-token-claim', $claim);

        // Configure the mock settings
        $this->mock_settings->method('__get')
            ->will($this->returnValueMap([
                ['endpoint_end_session', 'https://example.com/end_session'],
                ['login_type', 'button']
            ]));

        // Test the method
        $result = $this->client_wrapper->get_end_session_logout_redirect_url(
            'https://example.com/redirect',
            'https://example.com/requested-redirect',
            $user
        );

        // Should return the end session URL with the id_token and redirect URL
        $expected = 'https://example.com/end_session?id_token_hint=test-id-token&post_logout_redirect_uri=' .
                   urlencode('https://example.com/redirect');
        $this->assertEquals($expected, $result);
    }

    /**
     * Test get_end_session_logout_redirect_url with relative redirect URL.
     */
    public function test_get_end_session_logout_redirect_url_with_relative_url() {
        // Create a mock user
        $user = $this->factory()->user->create_and_get();

        // Set up the token response and claim
        $token_response = array('id_token' => 'test-id-token');
        $claim = array('iss' => 'https://idp.example.com');

        // Set user meta for the test
        update_user_meta($user->ID, 'infomaniak-connect-openid-last-token-response', $token_response);
        update_user_meta($user->ID, 'infomaniak-connect-openid-last-id-token-claim', $claim);

        // Configure the mock settings
        $this->mock_settings->method('__get')
            ->will($this->returnValueMap([
                ['endpoint_end_session', 'https://example.com/end_session'],
                ['login_type', 'button']
            ]));

        // Test with relative URL
        $relative_url = '/wp-admin';
        $result = $this->client_wrapper->get_end_session_logout_redirect_url(
            $relative_url,
            '',
            $user
        );

        // Should convert relative URL to absolute
        $expected = 'https://example.com/end_session?id_token_hint=test-id-token&post_logout_redirect_uri=' .
                   urlencode(site_url($relative_url));
        $this->assertEquals($expected, $result);
    }

    /**
     * Test get_end_session_logout_redirect_url without token response.
     */
    public function test_get_end_session_logout_redirect_url_without_token_response() {
        // Create a mock user without token response
        $user = $this->factory()->user->create_and_get();

        // Configure the mock settings
        $this->mock_settings->method('__get')
            ->will($this->returnValueMap([
                ['endpoint_end_session', 'https://example.com/end_session'],
                ['login_type', 'button']
            ]));

        // Test the method
        $result = $this->client_wrapper->get_end_session_logout_redirect_url(
            'https://example.com/redirect',
            '',
            $user
        );

        // Should return the original redirect URL when no token response is found
        $this->assertEquals('https://example.com/redirect', $result);
    }

    /**
     * Helper to run authentication_request_callback and capture the redirect target.
     *
     * Hooks wp_redirect to capture the location, then throws to prevent exit.
     *
     * @param array $get         The $_GET superglobal for the callback.
     * @param array $cookie      The $_COOKIE superglobal for the callback.
     * @param array $state_value  State transient value to set up.
     * @return string The captured redirect location.
     */
    private function capture_callback_redirect( $get, $cookie, $state_value ) {
        // Set up the state transient.
        $state = $get['state'];
        set_transient( 'infomaniak-connect-openid-state--' . $state, $state_value, 180 );

        // Set the $_GET and $_COOKIE superglobals.
        $_GET = $get;
        $_COOKIE = $cookie;

        $captured = null;
        $capture = function ( $location ) use ( &$captured ) {
            $captured = $location;
            throw new \RuntimeException( 'redirect_intercepted' );
        };
        add_filter( 'wp_redirect', $capture );

        try {
            $this->client_wrapper->authentication_request_callback();
        } catch ( \RuntimeException $e ) {
            // Expected: thrown to prevent exit() after wp_redirect().
        }

        remove_filter( 'wp_redirect', $capture );
        $_GET = array();
        $_COOKIE = array();

        return $captured;
    }

    /**
     * Set up a fully mocked client wrapper for the full authentication callback.
     *
     * @param WP_User $user The user that will be found by identity.
     */
    private function setup_mocked_callback( $user ) {
        // Set user meta so get_user_by_identity finds this user.
        update_user_meta( $user->ID, 'infomaniak-connect-openid-subject-identity', 'test-subject-123' );

        // Mock client methods to walk through the full callback.
        $auth_request = array( 'code' => 'auth-code', 'state' => 'test-state-abc' );
        $this->mock_client->method( 'validate_authentication_request' )->willReturn( $auth_request );
        $this->mock_client->method( 'get_authentication_code' )->willReturn( 'auth-code' );
        $this->mock_client->method( 'get_authentication_state' )->willReturn( 'test-state-abc' );
        $this->mock_client->method( 'request_authentication_token' )->willReturn( array( 'body' => '{}' ) );
        $this->mock_client->method( 'get_token_response' )->willReturn(
            array(
                'id_token'     => 'id-token',
                'token_type'   => 'Bearer',
                'access_token' => 'access-token',
            )
        );
        $this->mock_client->method( 'validate_token_response' )->willReturn( true );
        $this->mock_client->method( 'get_id_token_claim' )->willReturn(
            array(
                'iss' => 'https://login.infomaniak.com',
                'sub' => 'test-subject-123',
                'aud' => 'client_id',
                'exp' => time() + 3600,
                'iat' => time(),
            )
        );
        $this->mock_client->method( 'validate_id_token_claim' )->willReturn( true );
        $this->mock_client->method( 'get_user_claim' )->willReturn(
            array(
                'sub'  => 'test-subject-123',
                'email' => $user->user_email,
            )
        );
        $this->mock_client->method( 'validate_user_claim' )->willReturn( true );
        $this->mock_client->method( 'get_subject_identity' )->willReturn( 'test-subject-123' );

        // Mock settings: no userinfo (use id_token claim), no redirect_user_back.
        $this->mock_settings->method( '__get' )->willReturnCallback(
            function ( $key ) {
                $values = array(
                    'endpoint_userinfo' => '',
                    'redirect_user_back' => false,
                    'link_existing_users' => false,
                    'create_if_does_not_exist' => false,
                );
                return isset( $values[ $key ] ) ? $values[ $key ] : null;
            }
        );
    }

    /**
     * Final redirect after authentication must use wp_safe_redirect,
     * blocking redirects to external/attacker-controlled URLs.
     *
     * The state transient stores an external URL (simulating a tampered or
     * injected state). After successful auth, the redirect must fall back to
     * a safe local URL (home_url), not the external one.
     */
    public function test_final_redirect_blocks_external_url() {
        // Create a real WP user.
        $user = $this->factory()->user->create_and_get();
        $this->setup_mocked_callback( $user );

        // State transient contains an external (attacker) redirect URL.
        $state_value = array(
            'test-state-abc' => array(
                'redirect_to' => 'https://evil.com/phishing-page',
            ),
        );

        $get = array(
            'code'  => 'auth-code',
            'state' => 'test-state-abc',
        );

        $captured = $this->capture_callback_redirect( $get, array(), $state_value );

        $this->assertNotNull( $captured, 'wp_redirect was not called' );
        $this->assertStringNotContainsString( 'evil.com', $captured,
            'External redirect URL must be blocked by wp_safe_redirect' );
    }

    /**
     * Final redirect to a local URL (same host) is still allowed.
     */
    public function test_final_redirect_allows_local_url() {
        $user = $this->factory()->user->create_and_get();
        $this->setup_mocked_callback( $user );

        $local_url = home_url( '/wp-admin/profile.php' );
        $state_value = array(
            'test-state-abc' => array(
                'redirect_to' => $local_url,
            ),
        );

        $get = array(
            'code'  => 'auth-code',
            'state' => 'test-state-abc',
        );

        $captured = $this->capture_callback_redirect( $get, array(), $state_value );

        $this->assertNotNull( $captured, 'wp_redirect was not called' );
        $this->assertEquals( $local_url, $captured );
    }

    /**
     * Deprecated cookie-based redirect must NOT override the redirect
     * stored in the state transient.
     *
     * Even when the cookie contains a URL, the state-stored redirect should
     * take precedence (or the cookie should be ignored entirely).
     */
    public function test_cookie_redirect_does_not_override_state() {
        $user = $this->factory()->user->create_and_get();
        $this->setup_mocked_callback( $user );

        $state_url = home_url( '/wp-admin/' );
        $state_value = array(
            'test-state-abc' => array(
                'redirect_to' => $state_url,
            ),
        );

        $get = array(
            'code'  => 'auth-code',
            'state' => 'test-state-abc',
        );

        // Cookie contains a different URL.
        $cookie = array(
            'infomaniak-connect-openid-redirect' => home_url( '/other-page/' ),
        );

        $captured = $this->capture_callback_redirect( $get, $cookie, $state_value );

        $this->assertNotNull( $captured, 'wp_redirect was not called' );
        $this->assertEquals( $state_url, $captured,
            'Cookie redirect must not override the state-stored redirect' );
    }

    /**
     * Cookie containing an external URL must not cause an open redirect
     * even when there is no state-stored redirect.
     */
    public function test_cookie_external_url_is_blocked() {
        $user = $this->factory()->user->create_and_get();
        $this->setup_mocked_callback( $user );

        // State transient has no redirect_to.
        $state_value = array(
            'test-state-abc' => array(),
        );

        $get = array(
            'code'  => 'auth-code',
            'state' => 'test-state-abc',
        );

        // Cookie contains an external URL.
        $cookie = array(
            'infomaniak-connect-openid-redirect' => 'https://evil.com/phishing',
        );

        $captured = $this->capture_callback_redirect( $get, $cookie, $state_value );

        $this->assertNotNull( $captured, 'wp_redirect was not called' );
        $this->assertStringNotContainsString( 'evil.com', $captured,
            'External cookie redirect must be blocked' );
    }
}
