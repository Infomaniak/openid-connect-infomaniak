<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * JWT validation and verification class.
 *
 * @package   OpenID_Connect_Infomaniak
 * @category  Authentication
 * @copyright 2025-2030 infomaniak
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 */

/**
 * OpenID_Connect_Infomaniak_JWT_Validator class.
 *
 * Handles JWT signature verification and claim validation using JWKS.
 * Uses native PHP OpenSSL extension for cryptographic verification.
 *
 * @package  OpenID_Connect_Infomaniak
 * @category Authentication
 */
class OpenID_Connect_Infomaniak_JWT_Validator {

	/**
	 * The JWKS endpoint URL.
	 *
	 * @var string
	 */
	private $jwks_uri;

	/**
	 * The expected client ID (audience).
	 *
	 * @var string
	 */
	private $client_id;

	/**
	 * The expected issuer.
	 *
	 * @var string
	 */
	private $issuer;

	/**
	 * JWKS cache TTL in seconds.
	 *
	 * @var int
	 */
	private $cache_ttl;

	/**
	 * Allow HTTP requests to internal/private network endpoints.
	 *
	 * @var bool
	 */
	private $allow_internal_idp;

	/**
	 * Logger instance.
	 *
	 * @var OpenID_Connect_Infomaniak_Option_Logger
	 */
	private $logger;

	/**
	 * Constructor.
	 *
	 * @param string                               $jwks_uri           The JWKS endpoint URL.
	 * @param string                               $client_id          The client ID for audience validation.
	 * @param string                               $issuer             The expected issuer.
	 * @param int                                  $cache_ttl          JWKS cache TTL in seconds.
	 * @param bool                                 $allow_internal_idp Allow internal/private network endpoints.
	 * @param OpenID_Connect_Infomaniak_Option_Logger $logger             Logger instance.
	 */
	public function __construct( $jwks_uri, $client_id, $issuer, $cache_ttl, $allow_internal_idp, $logger ) {
		$this->jwks_uri           = $jwks_uri;
		$this->client_id          = $client_id;
		$this->issuer             = $issuer;
		$this->cache_ttl          = $cache_ttl;
		$this->allow_internal_idp = $allow_internal_idp;
		$this->logger             = $logger;
	}

	/**
	 * Make a safe HTTP GET request with optional internal endpoint support.
	 *
	 * @param string $url  The URL to request.
	 * @param array  $args Optional. Request arguments.
	 *
	 * @return array|WP_Error Response array or WP_Error on failure.
	 */
	private function http_get( $url, $args = array() ) {
		if ( $this->allow_internal_idp ) {
			return wp_remote_get( $url, $args );
		}
		return wp_safe_remote_get( $url, $args );
	}

	/**
	 * Base64URL decode a string.
	 *
	 * @param string $data The base64url-encoded data.
	 *
	 * @return string|false The decoded data or false on failure.
	 */
	private function base64url_decode( $data ) {
		$decoded = base64_decode( str_replace( array( '-', '_' ), array( '+', '/' ), $data ), true );
		return $decoded;
	}

	/**
	 * Encode a DER length.
	 *
	 * @param int $length The length to encode.
	 *
	 * @return string The DER-encoded length.
	 */
	private function der_encode_length( $length ) {
		if ( $length < 0x80 ) {
			return chr( $length );
		}
		$bytes = '';
		while ( $length > 0 ) {
			$bytes = chr( $length & 0xFF ) . $bytes;
			$length >>= 8;
		}
		return chr( 0x80 | strlen( $bytes ) ) . $bytes;
	}

	/**
	 * Encode a DER integer from a binary string.
	 *
	 * @param string $value The big-endian binary integer.
	 *
	 * @return string The DER-encoded integer.
	 */
	private function der_encode_integer( $value ) {
		if ( strlen( $value ) === 0 ) {
			$value = "\x00";
		}
		if ( ord( $value[0] ) & 0x80 ) {
			$value = "\x00" . $value;
		}
		return "\x02" . $this->der_encode_length( strlen( $value ) ) . $value;
	}

	/**
	 * Encode a DER SEQUENCE.
	 *
	 * @param string $elements The concatenated DER elements.
	 *
	 * @return string The DER-encoded SEQUENCE.
	 */
	private function der_encode_sequence( $elements ) {
		return "\x30" . $this->der_encode_length( strlen( $elements ) ) . $elements;
	}

	/**
	 * Encode a DER BIT STRING.
	 *
	 * @param string $value The raw bit string content.
	 *
	 * @return string The DER-encoded BIT STRING.
	 */
	private function der_encode_bit_string( $value ) {
		$data = "\x00" . $value;
		return "\x03" . $this->der_encode_length( strlen( $data ) ) . $data;
	}

	/**
	 * Convert a JWK (RSA) to PEM format.
	 *
	 * @param array $jwk The JSON Web Key.
	 *
	 * @return string|false The PEM-encoded public key or false on failure.
	 */
	private function jwk_to_pem( $jwk ) {
		if ( ! isset( $jwk['kty'] ) || $jwk['kty'] !== 'RSA' ) {
			return false;
		}

		if ( ! isset( $jwk['n'] ) || ! isset( $jwk['e'] ) ) {
			return false;
		}

		$modulus  = $this->base64url_decode( $jwk['n'] );
		$exponent = $this->base64url_decode( $jwk['e'] );

		if ( ! $modulus || ! $exponent ) {
			return false;
		}

		$rsa_key = $this->der_encode_sequence(
			$this->der_encode_integer( $modulus ) .
			$this->der_encode_integer( $exponent )
		);

		$alg_id = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

		$spki = $this->der_encode_sequence(
			$alg_id .
			$this->der_encode_bit_string( $rsa_key )
		);

		$pem = "-----BEGIN PUBLIC KEY-----\n";
		$pem .= chunk_split( base64_encode( $spki ), 64, "\n" );
		$pem .= "-----END PUBLIC KEY-----\n";

		return $pem;
	}

	/**
	 * Fetch JWKS from the IDP endpoint with caching.
	 *
	 * @return array|WP_Error Array of keys or WP_Error on failure.
	 */
	private function fetch_jwks() {
		$cache_key = 'infomaniak_oidc_jwks_' . md5( $this->jwks_uri );
		$cached_jwks = get_transient( $cache_key );

		if ( false !== $cached_jwks && is_array( $cached_jwks ) ) {
			return $cached_jwks;
		}

		$response = $this->http_get( $this->jwks_uri, array( 'timeout' => 10 ) );

		if ( is_wp_error( $response ) ) {
			$this->logger->log( $response, 'jwks-fetch-failed' );
			return new WP_Error(
				'jwks-fetch-failed',
				__( 'Failed to fetch JWKS from identity provider.', 'infomaniak-connect-openid' ),
				$response
			);
		}

		$response_code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== (int) $response_code ) {
			$error = new WP_Error(
				'jwks-fetch-failed',
				sprintf(
					__( 'JWKS endpoint returned HTTP %d', 'infomaniak-connect-openid' ),
					$response_code
				)
			);
			$this->logger->log( $error, 'jwks-fetch-failed' );
			return $error;
		}

		$body = wp_remote_retrieve_body( $response );
		$jwks = json_decode( $body, true );

		if ( ! $jwks || ! isset( $jwks['keys'] ) ) {
			$error = new WP_Error(
				'jwks-invalid-format',
				__( 'Invalid JWKS format received from identity provider.', 'infomaniak-connect-openid' )
			);
			$this->logger->log( $error, 'jwks-invalid-format' );
			return $error;
		}

		set_transient( $cache_key, $jwks, $this->cache_ttl );

		return $jwks;
	}

	/**
	 * Validate JWT claims.
	 *
	 * @param array $claims The decoded JWT claims.
	 *
	 * @return true|WP_Error True if valid, WP_Error on failure.
	 */
	private function validate_jwt_claims( $claims ) {
		if ( ! isset( $claims['sub'] ) || empty( $claims['sub'] ) ) {
			return new WP_Error(
				'missing-sub',
				__( 'Token missing subject claim.', 'infomaniak-connect-openid' )
			);
		}

		if ( ! isset( $claims['exp'] ) ) {
			return new WP_Error(
				'missing-exp',
				__( 'Token missing expiration claim.', 'infomaniak-connect-openid' )
			);
		}

		if ( time() >= (int) $claims['exp'] ) {
			return new WP_Error(
				'token-expired',
				__( 'Token has expired.', 'infomaniak-connect-openid' )
			);
		}

		if ( ! isset( $claims['iat'] ) ) {
			return new WP_Error(
				'missing-iat',
				__( 'Token missing issued at claim.', 'infomaniak-connect-openid' )
			);
		}

		if ( ! isset( $claims['aud'] ) ) {
			return new WP_Error(
				'missing-aud',
				__( 'Token missing audience claim.', 'infomaniak-connect-openid' )
			);
		}

		$aud = $claims['aud'];
		$audience_valid = false;

		if ( is_array( $aud ) ) {
			$audience_valid = in_array( $this->client_id, $aud, true );
		} elseif ( is_string( $aud ) ) {
			$audience_valid = ( $aud === $this->client_id );
		}

		if ( ! $audience_valid ) {
			return new WP_Error(
				'invalid-aud',
				__( 'Token audience does not match client.', 'infomaniak-connect-openid' )
			);
		}

		if ( ! empty( $this->issuer ) ) {
			if ( ! isset( $claims['iss'] ) ) {
				return new WP_Error(
					'missing-iss',
					__( 'Token missing issuer claim.', 'infomaniak-connect-openid' )
				);
			}

			if ( rtrim( $claims['iss'], '/' ) !== rtrim( $this->issuer, '/' ) ) {
				$this->logger->log(
					sprintf(
						'Issuer mismatch - Expected: "%s", Received: "%s".',
						$this->issuer,
						$claims['iss']
					),
					'issuer-mismatch'
				);
				return new WP_Error(
					'invalid-iss',
					__( 'Token issuer does not match expected issuer.', 'infomaniak-connect-openid' )
				);
			}
		}

		return true;
	}

	/**
	 * Verify a JWT signature using JWKS and decode its payload.
	 *
	 * Performs cryptographic signature verification using the configured JWKS
	 * endpoint and validates the issuer claim when an issuer is configured.
	 * Unlike validate_id_token(), this does not enforce ID token-specific
	 * claims (aud, exp, iat, sub), making it suitable for aggregated claim
	 * JWTs which are containers for arbitrary claims rather than ID tokens.
	 *
	 * @param string $jwt The JWT to verify and decode.
	 * @return array|WP_Error Array of claims if valid, WP_Error on failure.
	 */
	public function verify_and_decode_jwt( $jwt ) {
		$claims = $this->verify_signature( $jwt );
		if ( is_wp_error( $claims ) ) {
			return $claims;
		}

		if ( ! empty( $this->issuer ) ) {
			if ( ! isset( $claims['iss'] ) ) {
				$error = new WP_Error(
					'missing-iss',
					__( 'Token missing issuer claim.', 'infomaniak-connect-openid' )
				);
				$this->logger->log( $error, 'jwt-claims-invalid' );
				return $error;
			}

			if ( rtrim( $claims['iss'], '/' ) !== rtrim( $this->issuer, '/' ) ) {
				$this->logger->log(
					sprintf(
						'Issuer mismatch - Expected: "%s", Received: "%s".',
						$this->issuer,
						$claims['iss']
					),
					'issuer-mismatch'
				);
				$error = new WP_Error(
					'invalid-iss',
					__( 'Token issuer does not match expected issuer.', 'infomaniak-connect-openid' )
				);
				return $error;
			}
		}

		return $claims;
	}

	/**
	 * Verify a JWT signature using JWKS and return the decoded claims.
	 *
	 * Shared signature verification logic used by both validate_id_token()
	 * and verify_and_decode_jwt(). Does not perform claim validation.
	 *
	 * @param string $jwt The JWT to verify.
	 * @return array|WP_Error Array of claims if signature is valid, WP_Error on failure.
	 */
	private function verify_signature( $jwt ) {
		if ( empty( $this->jwks_uri ) ) {
			$error = new WP_Error(
				'jwks-not-configured',
				__( 'JWKS URI not configured. JWT signature verification requires JWKS endpoint.', 'infomaniak-connect-openid' )
			);
			$this->logger->log( $error, 'jwks-not-configured' );
			return $error;
		}

		$parts = explode( '.', $jwt );
		if ( count( $parts ) !== 3 ) {
			return new WP_Error(
				'invalid-jwt-structure',
				__( 'Invalid JWT structure.', 'infomaniak-connect-openid' )
			);
		}

		list( $header_b64, $payload_b64, $signature_b64 ) = $parts;

		$header_json = $this->base64url_decode( $header_b64 );
		if ( ! $header_json ) {
			return new WP_Error(
				'invalid-jwt-header',
				__( 'Invalid JWT header.', 'infomaniak-connect-openid' )
			);
		}

		$header = json_decode( $header_json, true );
		if ( ! is_array( $header ) ) {
			return new WP_Error(
				'invalid-jwt-header',
				__( 'Invalid JWT header.', 'infomaniak-connect-openid' )
			);
		}

		$kid = isset( $header['kid'] ) ? $header['kid'] : null;
		$alg = isset( $header['alg'] ) ? $header['alg'] : null;

		if ( empty( $kid ) ) {
			return new WP_Error(
				'missing-kid',
				__( 'JWT header missing key ID.', 'infomaniak-connect-openid' )
			);
		}

		$jwks = $this->fetch_jwks();
		if ( is_wp_error( $jwks ) ) {
			return $jwks;
		}

		$key = null;
		foreach ( $jwks['keys'] as $k ) {
			if ( isset( $k['kid'] ) && $k['kid'] === $kid ) {
				$key = $k;
				break;
			}
		}

		if ( ! $key ) {
			return new WP_Error(
				'key-not-found',
				__( 'No matching key found in JWKS for the JWT key ID.', 'infomaniak-connect-openid' )
			);
		}

		$pem = $this->jwk_to_pem( $key );
		if ( ! $pem ) {
			return new WP_Error(
				'jwk-conversion-failed',
				__( 'Failed to convert JWK to PEM format.', 'infomaniak-connect-openid' )
			);
		}

		$public_key = openssl_pkey_get_public( $pem );
		if ( ! $public_key ) {
			return new WP_Error(
				'invalid-public-key',
				__( 'Failed to load public key from PEM.', 'infomaniak-connect-openid' )
			);
		}

		$signature = $this->base64url_decode( $signature_b64 );
		if ( ! $signature ) {
			return new WP_Error(
				'invalid-signature',
				__( 'Invalid JWT signature encoding.', 'infomaniak-connect-openid' )
			);
		}

		$signing_input = $header_b64 . '.' . $payload_b64;

		$algo = OPENSSL_ALGO_SHA256;
		if ( $alg === 'RS384' ) {
			$algo = OPENSSL_ALGO_SHA384;
		} elseif ( $alg === 'RS512' ) {
			$algo = OPENSSL_ALGO_SHA512;
		}

		$result = openssl_verify( $signing_input, $signature, $public_key, $algo );

		if ( PHP_MAJOR_VERSION < 8 ) {
			openssl_free_key( $public_key );
		} else {
			unset( $public_key );
		}

		if ( $result !== 1 ) {
			$error_msg = $result === 0
				? __( 'JWT signature verification failed: signature does not match.', 'infomaniak-connect-openid' )
				: sprintf( __( 'JWT signature verification failed: %s', 'infomaniak-connect-openid' ), openssl_error_string() ?: 'Unknown error' );
			return new WP_Error( 'signature-verification-failed', $error_msg );
		}

		$payload_json = $this->base64url_decode( $payload_b64 );
		if ( ! $payload_json ) {
			return new WP_Error(
				'invalid-jwt-payload',
				__( 'Invalid JWT payload.', 'infomaniak-connect-openid' )
			);
		}

		$claims = json_decode( $payload_json, true );
		if ( ! is_array( $claims ) ) {
			return new WP_Error(
				'invalid-jwt-claims',
				__( 'Invalid JWT claims.', 'infomaniak-connect-openid' )
			);
		}

		return $claims;
	}

	/**
	 * Validate and verify an ID token.
	 *
	 * @param string $id_token The JWT ID token to validate.
	 *
	 * @return array|WP_Error Array of claims if valid, WP_Error on failure.
	 */
	public function validate_id_token( $id_token ) {
		$claims = $this->verify_signature( $id_token );
		if ( is_wp_error( $claims ) ) {
			return $claims;
		}

		$claims_valid = $this->validate_jwt_claims( $claims );
		if ( is_wp_error( $claims_valid ) ) {
			$this->logger->log( $claims_valid, 'jwt-claims-invalid' );
			return $claims_valid;
		}

		return $claims;
	}
}
