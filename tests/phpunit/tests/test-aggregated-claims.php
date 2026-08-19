<?php
/**
 * Test class for aggregated claim JWT verification (H2 security fix).
 *
 * Verifies that get_claim() refuses to use aggregated claim JWTs whose
 * signatures are not verified via JWKS.
 */
class Test_Aggregated_Claims extends Infomaniak_OpenID_Connect_TestCase {

    /**
     * @var OpenID_Connect_Infomaniak_Client_Wrapper
     */
    private $client_wrapper;

    /**
     * @var OpenID_Connect_Infomaniak_Client
     */
    private $client;

    /**
     * @var OpenID_Connect_Infomaniak_Option_Logger
     */
    private $logger;

    /**
     * @var array RSA key pair for signing/verifying JWTs in tests.
     */
    private static $rsa_keys = array();

    /**
     * Set up the test fixture.
     */
    public function set_up() {
        parent::set_up();

        $this->logger = new OpenID_Connect_Infomaniak_Option_Logger( 'error', 0, 1000 );

        // Create a real client with JWKS config so the validator is exercised.
        $this->client = new OpenID_Connect_Infomaniak_Client(
            'test-client-id',
            'test-client-secret',
            'openid email profile',
            'https://login.example.com/authorize',
            'https://login.example.com/userinfo',
            'https://login.example.com/token',
            'https://example.com/redirect',
            '',
            'https://login.example.com/oauth2/jwks',
            'https://login.example.com',
            3600,
            false,
            180,
            $this->logger
        );

        $settings = new OpenID_Connect_Infomaniak_Option_Settings( array(), false );
        $settings->identity_key       = 'sub';
        $settings->nickname_key       = 'name';
        $settings->email_format       = '{email}';
        $settings->displayname_format = '';
        $settings->endpoint_end_session = '';
        $settings->login_type        = 'button';

        $this->client_wrapper = new OpenID_Connect_Infomaniak_Client_Wrapper(
            $this->client,
            $settings,
            $this->logger
        );
    }

    /**
     * Generate (once) an RSA key pair and JWKS for tests.
     */
    private function get_test_keys() {
        if ( ! empty( self::$rsa_keys ) ) {
            return self::$rsa_keys;
        }

        $config = array(
            'digest_alg'       => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        );
        $resource = openssl_pkey_new( $config );

        $private_pem = '';
        openssl_pkey_export( $resource, $private_pem );
        $private_key = openssl_pkey_get_private( $private_pem );

        $details     = openssl_pkey_get_details( $resource );
        $public_pem  = $details['key'];

        // Extract modulus and exponent for JWKS.
        $key_info = openssl_pkey_get_details( openssl_pkey_get_public( $public_pem ) );
        $modulus  = $key_info['rsa']['n'];
        $exponent = $key_info['rsa']['e'];

        $mod_b64  = rtrim( strtr( base64_encode( $modulus ), '+/', '-_' ), '=' );
        $exp_b64  = rtrim( strtr( base64_encode( $exponent ), '+/', '-_' ), '=' );

        self::$rsa_keys = array(
            'private_key' => $private_key,
            'public_pem'  => $public_pem,
            'jwks'        => array(
                'keys' => array(
                    array(
                        'kty' => 'RSA',
                        'kid' => 'test-key-1',
                        'alg' => 'RS256',
                        'n'   => $mod_b64,
                        'e'   => $exp_b64,
                    ),
                ),
            ),
        );

        return self::$rsa_keys;
    }

    /**
     * Build a signed JWT with the test private key.
     *
     * @param array  $payload The JWT payload claims.
     * @param string $kid     Optional. The key ID to put in the header.
     * @return string The signed JWT.
     */
    private function make_signed_jwt( $payload, $kid = 'test-key-1' ) {
        $keys = $this->get_test_keys();

        $header = array(
            'typ' => 'JWT',
            'alg' => 'RS256',
            'kid' => $kid,
        );

        $header_encoded  = rtrim( strtr( base64_encode( json_encode( $header ) ), '+/', '-_' ), '=' );
        $payload_encoded = rtrim( strtr( base64_encode( json_encode( $payload ) ), '+/', '-_' ), '=' );

        $signing_input = $header_encoded . '.' . $payload_encoded;

        openssl_sign( $signing_input, $signature, $keys['private_key'], OPENSSL_ALGO_SHA256 );

        $signature_encoded = rtrim( strtr( base64_encode( $signature ), '+/', '-_' ), '=' );

        return $signing_input . '.' . $signature_encoded;
    }

    /**
     * Build an unsigned (tampered signature) JWT.
     *
     * @param array  $payload The JWT payload claims.
     * @return string The forged JWT with invalid signature.
     */
    private function make_forged_jwt( $payload ) {
        $keys = $this->get_test_keys();

        // Sign with a different key, then claim to be test-key-1.
        $config = array(
            'digest_alg'       => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        );
        $other_resource = openssl_pkey_new( $config );
        $other_pem      = '';
        openssl_pkey_export( $other_resource, $other_pem );
        $other_private  = openssl_pkey_get_private( $other_pem );

        $header = array(
            'typ' => 'JWT',
            'alg' => 'RS256',
            'kid' => 'test-key-1',
        );

        $header_encoded  = rtrim( strtr( base64_encode( json_encode( $header ) ), '+/', '-_' ), '=' );
        $payload_encoded = rtrim( strtr( base64_encode( json_encode( $payload ) ), '+/', '-_' ), '=' );

        $signing_input = $header_encoded . '.' . $payload_encoded;

        openssl_sign( $signing_input, $signature, $other_private, OPENSSL_ALGO_SHA256 );

        $signature_encoded = rtrim( strtr( base64_encode( $signature ), '+/', '-_' ), '=' );

        return $signing_input . '.' . $signature_encoded;
    }

    /**
     * Mock the JWKS endpoint response by pre-populating the validator cache.
     */
    private function mock_jwks_cache() {
        $keys = $this->get_test_keys();
        $cache_key = 'infomaniak_oidc_jwks_' . md5( 'https://login.example.com/oauth2/jwks' );
        set_transient( $cache_key, $keys['jwks'], 3600 );
    }

    /**
     * Test get_claim returns a simple (non-aggregated) claim directly.
     */
    public function test_get_claim_returns_simple_claim() {
        $userinfo = array(
            'email' => 'user@example.com',
            'name'  => 'Test User',
        );

        $claimvalue = null;
        $result = $this->invoke_private_method(
            $this->client_wrapper,
            'get_claim',
            array( 'email', $userinfo, &$claimvalue )
        );

        $this->assertTrue( $result );
        $this->assertEquals( 'user@example.com', $claimvalue );
    }

    /**
     * Test get_claim returns false when the claim is not present and no
     * aggregated claim sources exist.
     */
    public function test_get_claim_returns_false_when_missing() {
        $userinfo = array( 'name' => 'Test User' );

        $claimvalue = null;
        $result = $this->invoke_private_method(
            $this->client_wrapper,
            'get_claim',
            array( 'email', $userinfo, &$claimvalue )
        );

        $this->assertFalse( $result );
    }

    /**
     * Test get_claim REFUSES an aggregated claim JWT with a forged signature.
     *
     * This is the core H2 regression test: a MitM attacker who injects a
     * forged aggregated claim must NOT be able to override user identity data.
     */
    public function test_get_claim_refuses_forged_aggregated_jwt() {
        $this->mock_jwks_cache();

        $forged_jwt = $this->make_forged_jwt( array(
            'email' => 'attacker@evil.com',
            'name'  => 'Attacker',
        ) );

        $userinfo = array(
            'sub' => 'user-123',
            '_claim_names' => array(
                'email' => 'src1',
            ),
            '_claim_sources' => array(
                'src1' => array( 'JWT' => $forged_jwt ),
            ),
        );

        $claimvalue = null;
        $result = $this->invoke_private_method(
            $this->client_wrapper,
            'get_claim',
            array( 'email', $userinfo, &$claimvalue )
        );

        $this->assertFalse( $result, 'Forged aggregated claim JWT must be rejected' );
    }

    /**
     * Test get_claim accepts an aggregated claim JWT with a valid signature.
     */
    public function test_get_claim_accepts_valid_aggregated_jwt() {
        $this->mock_jwks_cache();

        $valid_jwt = $this->make_signed_jwt( array(
            'email' => 'user@example.com',
            'name'  => 'Test User',
            'iss'   => 'https://login.example.com',
        ) );

        $userinfo = array(
            'sub' => 'user-123',
            '_claim_names' => array(
                'email' => 'src1',
            ),
            '_claim_sources' => array(
                'src1' => array( 'JWT' => $valid_jwt ),
            ),
        );

        $claimvalue = null;
        $result = $this->invoke_private_method(
            $this->client_wrapper,
            'get_claim',
            array( 'email', $userinfo, &$claimvalue )
        );

        $this->assertTrue( $result, 'Validly signed aggregated claim JWT should be accepted' );
        $this->assertEquals( 'user@example.com', $claimvalue );
    }

    /**
     * Test get_claim refuses aggregated claim JWTs when JWKS is not configured.
     *
     * Defense-in-depth: if no JWKS endpoint is available, aggregated claims
     * must be rejected rather than decoded without verification.
     */
    public function test_get_claim_refuses_aggregated_jwt_without_jwks() {
        $client_no_jwks = new OpenID_Connect_Infomaniak_Client(
            'test-client-id',
            'test-client-secret',
            'openid email profile',
            'https://login.example.com/authorize',
            'https://login.example.com/userinfo',
            'https://login.example.com/token',
            'https://example.com/redirect',
            '',
            '',
            'https://login.example.com',
            3600,
            false,
            180,
            $this->logger
        );

        $settings = new OpenID_Connect_Infomaniak_Option_Settings( array(), false );
        $settings->identity_key       = 'sub';
        $settings->nickname_key       = 'name';
        $settings->email_format       = '{email}';
        $settings->displayname_format = '';
        $settings->endpoint_end_session = '';
        $settings->login_type        = 'button';

        $wrapper_no_jwks = new OpenID_Connect_Infomaniak_Client_Wrapper(
            $client_no_jwks,
            $settings,
            $this->logger
        );

        $forged_jwt = $this->make_forged_jwt( array(
            'email' => 'attacker@evil.com',
        ) );

        $userinfo = array(
            'sub' => 'user-123',
            '_claim_names' => array(
                'email' => 'src1',
            ),
            '_claim_sources' => array(
                'src1' => array( 'JWT' => $forged_jwt ),
            ),
        );

        $claimvalue = null;
        $result = $this->invoke_private_method(
            $wrapper_no_jwks,
            'get_claim',
            array( 'email', $userinfo, &$claimvalue )
        );

        $this->assertFalse( $result, 'Aggregated claims must be rejected when JWKS is not configured' );
    }

    /**
     * Test get_claim refuses an aggregated claim JWT whose issuer does not match.
     */
    public function test_get_claim_refuses_aggregated_jwt_with_wrong_issuer() {
        $this->mock_jwks_cache();

        $valid_signed_wrong_issuer = $this->make_signed_jwt( array(
            'email' => 'user@example.com',
            'iss'   => 'https://evil.com',
        ) );

        $userinfo = array(
            'sub' => 'user-123',
            '_claim_names' => array(
                'email' => 'src1',
            ),
            '_claim_sources' => array(
                'src1' => array( 'JWT' => $valid_signed_wrong_issuer ),
            ),
        );

        $claimvalue = null;
        $result = $this->invoke_private_method(
            $this->client_wrapper,
            'get_claim',
            array( 'email', $userinfo, &$claimvalue )
        );

        $this->assertFalse( $result, 'Aggregated claim JWT with wrong issuer must be rejected' );
    }

    /**
     * Test get_claim refuses a malformed JWT (not 3 parts).
     */
    public function test_get_claim_refuses_malformed_jwt() {
        $this->mock_jwks_cache();

        $userinfo = array(
            'sub' => 'user-123',
            '_claim_names' => array(
                'email' => 'src1',
            ),
            '_claim_sources' => array(
                'src1' => array( 'JWT' => 'not.a.valid.jwt.extra' ),
            ),
        );

        $claimvalue = null;
        $result = $this->invoke_private_method(
            $this->client_wrapper,
            'get_claim',
            array( 'email', $userinfo, &$claimvalue )
        );

        $this->assertFalse( $result );
    }
}
