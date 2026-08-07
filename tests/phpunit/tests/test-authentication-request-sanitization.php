<?php
/**
 * Test case for H3: sanitization of $_GET at the authentication entry point.
 *
 * @package Infomaniak_OpenID_Connect
 */

/**
 * Test case for the authentication request input sanitization.
 */
class Test_Authentication_Request_Sanitization extends Infomaniak_OpenID_Connect_TestCase {

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

		$this->mock_client   = $this->createMock( 'OpenID_Connect_Infomaniak_Client' );
		$this->mock_settings = $this->createMock( 'OpenID_Connect_Infomaniak_Option_Settings' );
		$this->mock_logger   = $this->createMock( 'OpenID_Connect_Infomaniak_Option_Logger' );

		$this->client_wrapper = new OpenID_Connect_Infomaniak_Client_Wrapper(
			$this->mock_client,
			$this->mock_settings,
			$this->mock_logger
		);
	}

	/**
	 * Tear down the test fixture.
	 */
	public function tear_down() {
		parent::tear_down();
		$_GET = array();
	}

	/**
	 * Assert that the request array passed to validate_authentication_request
	 * has code and state sanitized of tags and stripped of magic-quote slashes.
	 *
	 * @param array $request The captured request argument.
	 */
	private function assert_sanitized( $request ) {
		$this->assertIsArray( $request );
		$this->assertArrayHasKey( 'code', $request );
		$this->assertArrayHasKey( 'state', $request );
		// sanitize_text_field strips tags and extra whitespace.
		$this->assertStringNotContainsString( '<', $request['code'], 'code must not contain tags' );
		$this->assertStringNotContainsString( '<', $request['state'], 'state must not contain tags' );
		$this->assertStringNotContainsString( '>', $request['code'], 'code must not contain tags' );
		$this->assertStringNotContainsString( '>', $request['state'], 'state must not contain tags' );
		// wp_unslash strips backslashes added by magic quotes.
		$this->assertStringNotContainsString( "\'", $request['code'], 'code must be unslashed' );
		$this->assertStringNotContainsString( "\'", $request['state'], 'state must be unslashed' );
	}

	/**
	 * Test that get_authentication_request unslashes and sanitizes code and state.
	 */
	public function test_get_authentication_request_sanitizes_code_and_state() {
		$_GET = array(
			'code'  => "test\\'code<script>alert(1)</script>",
			'state' => "test\\'state<img src=x>",
		);

		$request = $this->client_wrapper->get_authentication_request();

		$this->assert_sanitized( $request );
		// The apostrophe is legitimate text and must survive unslashing.
		$this->assertStringContainsString( "'code", $request['code'] );
		$this->assertStringContainsString( "'state", $request['state'] );
	}

	/**
	 * Test that get_authentication_request preserves the error and
	 * error_description fields (sanitized) and other keys.
	 */
	public function test_get_authentication_request_preserves_other_fields() {
		$_GET = array(
			'error'            => "access\\'denied",
			'error_description' => "The user denied\\'the request",
		);

		$request = $this->client_wrapper->get_authentication_request();

		$this->assertIsArray( $request );
		$this->assertEquals( "access'denied", $request['error'] );
		$this->assertEquals( "The user denied'the request", $request['error_description'] );
	}

	/**
	 * Test that authentication_request_callback passes a sanitized request
	 * to the client's validate_authentication_request method.
	 */
	public function test_authentication_request_callback_passes_sanitized_get() {
		$_GET = array(
			'code'  => "abc\\'123<b>",
			'state' => "xyz\\'456<i>",
		);

		$captured = null;
		$this->mock_client->method( 'validate_authentication_request' )
			->willReturnCallback( function ( $request ) use ( &$captured ) {
				$captured = $request;
				// Return a WP_Error to short-circuit before the exit in error_redirect.
				return new WP_Error( 'test-short-circuit', 'short-circuit' );
			} );

		// Prevent the actual redirect and exit: throw from the wp_redirect filter.
		add_filter( 'wp_redirect', array( $this, 'block_redirect' ) );

		try {
			$this->client_wrapper->authentication_request_callback();
		} catch ( RuntimeException $e ) {
			// Expected: error_redirect calls wp_redirect then exit. The filter
			// turns wp_redirect into a thrown exception which we catch here.
		}

		remove_filter( 'wp_redirect', array( $this, 'block_redirect' ) );

		$this->assertNotNull( $captured, 'validate_authentication_request was not called' );
		$this->assert_sanitized( $captured );
		// Apostrophes survive wp_unslash; tags are stripped by sanitize_text_field.
		$this->assertStringContainsString( "'123", $captured['code'] );
		$this->assertStringContainsString( "'456", $captured['state'] );
	}

	/**
	 * Block wp_redirect by throwing an exception, so error_redirect's exit
	 * is never reached and the test can continue.
	 *
	 * @param string $location The redirect URL.
	 * @return void
	 * @throws RuntimeException Always.
	 */
	public function block_redirect( $location = '' ) {
		throw new RuntimeException( 'redirect blocked for test' );
	}
}
