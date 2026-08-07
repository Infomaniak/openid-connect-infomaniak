<?php
/**
 * Test class for OpenID_Connect_Infomaniak_Client
 */
class Test_OpenID_Connect_Infomaniak_Client extends Infomaniak_OpenID_Connect_TestCase {

    /**
     * @var OpenID_Connect_Infomaniak_Client
     */
    private $client;

    /**
     * @var OpenID_Connect_Infomaniak_Option_Logger
     */
    private $mock_logger;

    /**
     * Test configuration
     */
    private $config = [
        'client_id' => 'test-client-id',
        'client_secret' => 'test-client-secret',
        'scope' => 'openid email profile',
        'endpoint_login' => 'https://login.example.com/authorize',
        'endpoint_userinfo' => 'https://login.example.com/userinfo',
        'endpoint_token' => 'https://login.example.com/token',
        'redirect_uri' => 'https://example.com/redirect',
        'acr_values' => 'test-acr',
        'endpoint_jwks' => '',
        'issuer' => '',
        'jwks_cache_ttl' => 3600,
        'allow_internal_idp' => false,
        'state_time_limit' => 180,
    ];

    /**
     * Set up the test case.
     */
    public function set_up() {
        parent::set_up();
        
        // Create mock logger
        $this->mock_logger = $this->createMock('OpenID_Connect_Infomaniak_Option_Logger');
        
        // Create the client instance
        $this->client = new OpenID_Connect_Infomaniak_Client(
            $this->config['client_id'],
            $this->config['client_secret'],
            $this->config['scope'],
            $this->config['endpoint_login'],
            $this->config['endpoint_userinfo'],
            $this->config['endpoint_token'],
            $this->config['redirect_uri'],
            $this->config['acr_values'],
            $this->config['endpoint_jwks'],
            $this->config['issuer'],
            $this->config['jwks_cache_ttl'],
            $this->config['allow_internal_idp'],
            $this->config['state_time_limit'],
            $this->mock_logger
        );
        
    }

    /**
     * Test constructor and getters
     */
    public function test_constructor_and_getters() {
        $this->assertEquals($this->config['client_id'], $this->get_private_property($this->client, 'client_id'));
        $this->assertEquals($this->config['client_secret'], $this->get_private_property($this->client, 'client_secret'));
        $this->assertEquals($this->config['scope'], $this->get_private_property($this->client, 'scope'));
        $this->assertEquals($this->config['endpoint_login'], $this->get_private_property($this->client, 'endpoint_login'));
        $this->assertEquals($this->config['endpoint_userinfo'], $this->get_private_property($this->client, 'endpoint_userinfo'));
        $this->assertEquals($this->config['endpoint_token'], $this->get_private_property($this->client, 'endpoint_token'));
        $this->assertEquals($this->config['redirect_uri'], $this->get_private_property($this->client, 'redirect_uri'));
        $this->assertEquals($this->config['acr_values'], $this->get_private_property($this->client, 'acr_values'));
        $this->assertEquals($this->config['state_time_limit'], $this->get_private_property($this->client, 'state_time_limit'));
    }

    /**
     * Test get_redirect_uri
     */
    public function test_get_redirect_uri() {
        $this->assertEquals($this->config['redirect_uri'], $this->client->get_redirect_uri());
    }

    /**
     * Test get_endpoint_login_url
     */
    public function test_get_endpoint_login_url() {
        $this->assertEquals($this->config['endpoint_login'], $this->client->get_endpoint_login_url());
    }

    /**
     * Test validate_authentication_request with valid request
     */
    public function test_validate_authentication_request_valid() {
        // First create a valid state
        $state = $this->client->new_state('https://example.com/redirect');
        
        $request = [
            'code' => 'test-code',
            'state' => $state
        ];
        
        $result = $this->client->validate_authentication_request($request);
        $this->assertIsArray($result);
        $this->assertEquals('test-code', $result['code']);
        $this->assertEquals($state, $result['state']);
    }

    /**
     * Test validate_authentication_request with error in request
     */
    public function test_validate_authentication_request_with_error() {
        $request = [
            'error' => 'test-error',
            'error_description' => 'Test error description'
        ];
        
        $result = $this->client->validate_authentication_request($request);
        $this->assertWPError($result);
        $this->assertEquals('test-error', $result->get_error_code());
    }

    /**
     * Test validate_authentication_request with missing code
     */
    public function test_validate_authentication_request_missing_code() {
        // First create a valid state
        $state = $this->client->new_state('https://example.com/redirect');
        
        $request = [
            'state' => $state
        ];
        
        $result = $this->client->validate_authentication_request($request);
        $this->assertWPError($result);
        $this->assertEquals('no-code', $result->get_error_code());
    }

    /**
     * Test get_authentication_code
     */
    public function test_get_authentication_code() {
        $request = [
            'code' => 'test-code',
            'state' => 'test-state'
        ];
        
        $result = $this->client->get_authentication_code($request);
        $this->assertEquals('test-code', $result);
    }

    /**
     * Test get_authentication_code with missing code
     */
    public function test_get_authentication_code_missing() {
        $request = [
            'state' => 'test-state'
        ];
        
        $result = $this->client->get_authentication_code($request);
        $this->assertWPError($result);
        $this->assertEquals('missing-authentication-code', $result->get_error_code());
    }

    /**
     * Test get_authentication_state
     */
    public function test_get_authentication_state() {
        $request = [
            'state' => 'test-state',
            'code' => 'test-code'
        ];
        
        $result = $this->client->get_authentication_state($request);
        $this->assertEquals('test-state', $result);
    }

    /**
     * Test get_authentication_state with missing state
     */
    public function test_get_authentication_state_missing() {
        $request = [
            'code' => 'test-code'
        ];
        
        $result = $this->client->get_authentication_state($request);
        $this->assertWPError($result);
        $this->assertEquals('missing-authentication-state', $result->get_error_code());
    }

    /**
     * Test validate_token_response with valid response
     */
    public function test_validate_token_response_valid() {
        $token_response = [
            'id_token' => 'test-id-token',
            'token_type' => 'Bearer',
            'access_token' => 'test-access-token'
        ];
        
        $result = $this->client->validate_token_response($token_response);
        $this->assertTrue($result);
    }

    /**
     * Test validate_token_response with missing id_token
     */
    public function test_validate_token_response_missing_id_token() {
        $token_response = [
            'token_type' => 'Bearer',
            'access_token' => 'test-access-token'
        ];
        
        $result = $this->client->validate_token_response($token_response);
        $this->assertWPError($result);
        $this->assertEquals('invalid-token-response', $result->get_error_code());
    }

    /**
     * Test validate_token_response with invalid token_type
     */
    public function test_validate_token_response_invalid_token_type() {
        $token_response = [
            'id_token' => 'test-id-token',
            'token_type' => 'Invalid',
            'access_token' => 'test-access-token'
        ];
        
        $result = $this->client->validate_token_response($token_response);
        $this->assertWPError($result);
        $this->assertEquals('invalid-token-response', $result->get_error_code());
    }

    /**
     * Test get_id_token_claim refuses to proceed when JWKS endpoint is not configured.
     *
     * Regression test for legacy JWT decoding fallback
     * without signature verification must return a WP_Error instead of silently
     * accepting an unsigned token.
     */
    public function test_get_id_token_claim_without_jwks_returns_error() {
        $header = base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'RS256']));
        $payload = base64_encode(json_encode([
            'sub' => '1234567890',
            'name' => 'Test User',
            'iat' => time()
        ]));
        $signature = 'test-signature';
        $token = "$header.$payload.$signature";

        $token_response = [
            'id_token' => $token,
            'token_type' => 'Bearer'
        ];

        $result = $this->client->get_id_token_claim($token_response);
        $this->assertWPError($result);
        $this->assertEquals('jwks-not-configured', $result->get_error_code());
    }

    /**
     * Test validate_id_token_claim with valid claim
     */
    public function test_validate_id_token_claim_valid() {
        $id_token_claim = [
            'sub' => '1234567890',
            'name' => 'Test User',
            'exp' => time() + 3600,
            'iat' => time(),
            'aud' => $this->config['client_id'],
            'iss' => 'https://login.example.com',
        ];
        
        $result = $this->client->validate_id_token_claim($id_token_claim);
        $this->assertTrue($result);
    }

    /**
     * Test get_subject_identity
     */
    public function test_get_subject_identity() {
        $id_token_claim = [
            'sub' => '1234567890',
            'name' => 'Test User'
        ];
        
        $result = $this->client->get_subject_identity($id_token_claim);
        $this->assertEquals('1234567890', $result);
    }

    /**
     * Test new_state and check_state
     */
    public function test_new_state_and_check_state() {
        $redirect_to = 'https://example.com/wp-admin/';
        
        // Generate a new state
        $state = $this->client->new_state($redirect_to);
        $this->assertNotEmpty($state);
        
        // Check that the state is valid
        $result = $this->client->check_state($state);
        $this->assertTrue($result);
        
        // Check that a random state is not valid
        $result = $this->client->check_state('invalid-state');
        $this->assertFalse($result);
    }
}
