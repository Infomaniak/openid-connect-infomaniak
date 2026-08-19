<?php
/**
 * Test case for token storage security (H6).
 *
 * @package Infomaniak_OpenID_Connect
 */

/**
 * Test case for secure token storage in user meta.
 */
class Test_Token_Storage extends Infomaniak_OpenID_Connect_TestCase {

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
	 * Test that store_token_response does not store access_token in user meta.
	 */
	public function test_store_token_response_does_not_store_access_token() {
		$user = $this->factory()->user->create_and_get();

		$token_response = array(
			'access_token'  => 'secret-access-token',
			'refresh_token' => 'secret-refresh-token',
			'id_token'      => 'test-id-token',
			'token_type'    => 'Bearer',
			'expires_in'    => 3600,
		);

		$this->client_wrapper->store_token_response( $user->ID, $token_response );

		$stored = get_user_meta( $user->ID, 'infomaniak-connect-openid-last-token-response', true );

		$this->assertStringNotContainsString( 'secret-access-token', serialize( $stored ) );
	}

	/**
	 * Test that store_token_response does not store refresh_token in user meta.
	 */
	public function test_store_token_response_does_not_store_refresh_token() {
		$user = $this->factory()->user->create_and_get();

		$token_response = array(
			'access_token'  => 'secret-access-token',
			'refresh_token' => 'secret-refresh-token',
			'id_token'      => 'test-id-token',
			'token_type'    => 'Bearer',
			'expires_in'    => 3600,
		);

		$this->client_wrapper->store_token_response( $user->ID, $token_response );

		$stored = get_user_meta( $user->ID, 'infomaniak-connect-openid-last-token-response', true );

		$this->assertStringNotContainsString( 'secret-refresh-token', serialize( $stored ) );
	}

	/**
	 * Test that store_token_response stores the id_token (needed for logout).
	 */
	public function test_store_token_response_stores_id_token() {
		$user = $this->factory()->user->create_and_get();

		$token_response = array(
			'access_token'  => 'secret-access-token',
			'refresh_token' => 'secret-refresh-token',
			'id_token'      => 'test-id-token',
			'token_type'    => 'Bearer',
			'expires_in'    => 3600,
		);

		$this->client_wrapper->store_token_response( $user->ID, $token_response );

		$stored = get_user_meta( $user->ID, 'infomaniak-connect-openid-last-token-response', true );

		$this->assertNotEmpty( $stored );
		$this->assertArrayHasKey( 'id_token', $stored );
		$this->assertEquals( 'test-id-token', $stored['id_token'] );
	}

	/**
	 * Test that store_token_response works when id_token is absent.
	 */
	public function test_store_token_response_without_id_token() {
		$user = $this->factory()->user->create_and_get();

		$token_response = array(
			'access_token'  => 'secret-access-token',
			'refresh_token' => 'secret-refresh-token',
			'token_type'    => 'Bearer',
			'expires_in'    => 3600,
		);

		$this->client_wrapper->store_token_response( $user->ID, $token_response );

		$stored = get_user_meta( $user->ID, 'infomaniak-connect-openid-last-token-response', true );

		$this->assertStringNotContainsString( 'secret-access-token', serialize( $stored ) );
		$this->assertStringNotContainsString( 'secret-refresh-token', serialize( $stored ) );
	}
}
