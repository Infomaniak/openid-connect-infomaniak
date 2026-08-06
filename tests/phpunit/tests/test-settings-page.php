<?php
/**
 * Test class for OpenID_Connect_Infomaniak_Settings_Page
 */
class Test_OpenID_Connect_Infomaniak_Settings_Page extends Infomaniak_OpenID_Connect_TestCase {

    /**
     * @var OpenID_Connect_Infomaniak_Settings_Page
     */
    private $settings_page;

    /**
     * @var OpenID_Connect_Infomaniak_Option_Settings
     */
    private $mock_settings;

    /**
     * @var OpenID_Connect_Infomaniak_Option_Logger
     */
    private $mock_logger;

    /**
     * Set up the test case.
     */
    public function set_up() {
        parent::set_up();
        
        // Create mock dependencies
        $this->mock_settings = $this->createMock('OpenID_Connect_Infomaniak_Option_Settings');
        $this->mock_logger = $this->createMock('OpenID_Connect_Infomaniak_Option_Logger');
        
        // Create the settings page instance with the correct parameters
        $this->settings_page = new OpenID_Connect_Infomaniak_Settings_Page(
            $this->mock_settings,
            $this->mock_logger
        );
    }

    /**
     * Test get_settings_fields returns expected fields
     */
    public function test_get_settings_fields_returns_expected_fields() {
        // Get the fields using reflection since the method is private
        $method = new ReflectionMethod('OpenID_Connect_Infomaniak_Settings_Page', 'get_settings_fields');
        $method->setAccessible(true);
        $fields = $method->invoke($this->settings_page);

        // Check that we have the expected fields
        $expected_fields = [
            'login_type',
            'client_id',
            'client_secret',
            'scope',
            'endpoint_login',
            'endpoint_userinfo',
            'endpoint_token',
            'endpoint_jwks',
            'issuer',
            'acr_values',
            'identity_key',
            'no_sslverify',
            'http_request_timeout',
            'enforce_privacy',
            'alternate_redirect_uri',
            'link_existing_users',
            'create_if_does_not_exist',
            'redirect_user_back',
            'redirect_on_logout',
            'enable_logging',
            'log_limit',
        ];

        // Check all expected fields exist
        foreach ($expected_fields as $field_name) {
            $this->assertArrayHasKey($field_name, $fields, "Field {$field_name} should exist in settings fields");
        }

        // Test specific field properties
        $this->assertEquals('text', $fields['client_id']['type']);
        $this->assertEquals('client_settings', $fields['client_id']['section']);
        $this->assertArrayHasKey('title', $fields['client_id']);
        $this->assertArrayHasKey('description', $fields['client_id']);

        // Test login_type options
        $this->assertEquals('select', $fields['login_type']['type']);
        $this->assertArrayHasKey('options', $fields['login_type']);
        $this->assertArrayHasKey('button', $fields['login_type']['options']);
        $this->assertArrayHasKey('auto', $fields['login_type']['options']);

        // Test scope default value
        $this->assertEquals('email profile openid', $fields['scope']['example']);
    }

    /**
     * Test get_settings_fields returns disabled fields when constants are defined
     */
    public function test_get_settings_fields_disabled_when_constants_defined() {
        // Define some constants
        define('INFOMANIAK_OIDC_CLIENT_ID', 'test-client-id');
        define('INFOMANIAK_OIDC_CLIENT_SECRET', 'test-secret');
        define('INFOMANIAK_OIDC_CLIENT_SCOPE', 'test-scope');
        define('INFOMANIAK_OIDC_LOGIN_TYPE', 'button');

        // Get the fields
        $method = new ReflectionMethod('OpenID_Connect_Infomaniak_Settings_Page', 'get_settings_fields');
        $method->setAccessible(true);
        $fields = $method->invoke($this->settings_page);

        // Check that fields are disabled when constants are defined
        $this->assertTrue($fields['client_id']['disabled']);
        $this->assertTrue($fields['client_secret']['disabled']);
        $this->assertTrue($fields['scope']['disabled']);
        $this->assertTrue($fields['login_type']['disabled']);
    }

    /**
     * Test get_settings_fields sections
     */
    public function test_get_settings_fields_has_correct_sections() {
        // Get the fields
        $method = new ReflectionMethod('OpenID_Connect_Infomaniak_Settings_Page', 'get_settings_fields');
        $method->setAccessible(true);
        $fields = $method->invoke($this->settings_page);

        // Group fields by section
        $sections = [];
        foreach ($fields as $field) {
            $section = $field['section'];
            if (!isset($sections[$section])) {
                $sections[$section] = 0;
            }
            $sections[$section]++;
        }

        // Check we have the expected sections
        $this->assertArrayHasKey('client_settings', $sections);
        $this->assertArrayHasKey('authorization_settings', $sections);
        $this->assertArrayHasKey('log_settings', $sections);

        // Check we have fields in each section
        $this->assertGreaterThan(0, $sections['client_settings']);
        $this->assertGreaterThan(0, $sections['authorization_settings']);
        $this->assertGreaterThan(0, $sections['log_settings']);
    }

    /**
     * Test get_settings_fields field types
     */
    public function test_get_settings_fields_has_correct_field_types() {
        // Get the fields
        $method = new ReflectionMethod('OpenID_Connect_Infomaniak_Settings_Page', 'get_settings_fields');
        $method->setAccessible(true);
        $fields = $method->invoke($this->settings_page);

        // Define expected field types
        $field_types = [
            'login_type' => 'select',
            'client_id' => 'text',
            'client_secret' => 'text',
            'scope' => 'text',
            'endpoint_login' => 'text',
            'endpoint_userinfo' => 'text',
            'endpoint_token' => 'text',
            'endpoint_jwks' => 'text',
            'issuer' => 'text',
            'acr_values' => 'text',
            'identity_key' => 'text',
            'no_sslverify' => 'checkbox',
            'http_request_timeout' => 'text',
            'enforce_privacy' => 'checkbox',
            'alternate_redirect_uri' => 'checkbox',
            'link_existing_users' => 'checkbox',
            'create_if_does_not_exist' => 'checkbox',
            'redirect_user_back' => 'checkbox',
            'redirect_on_logout' => 'checkbox',
            'enable_logging' => 'checkbox',
            'log_limit' => 'number',
        ];

        // Check each field has the correct type
        foreach ($field_types as $field_name => $expected_type) {
            if (isset($fields[$field_name])) {
                $this->assertEquals(
                    $expected_type, 
                    $fields[$field_name]['type'],
                    "Field {$field_name} should be of type {$expected_type}"
                );
            }
        }
    }
}
