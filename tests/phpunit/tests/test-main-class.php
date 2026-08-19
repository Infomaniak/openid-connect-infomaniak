<?php
/**
 * Test case for the main plugin class.
 *
 * @package Infomaniak_OpenID_Connect
 */

/**
 * Test case for the main plugin class.
 */
class Test_Main_Class extends Infomaniak_OpenID_Connect_TestCase {

    /**
     * Test plugin instance.
     */
    public function test_plugin_instance() {
        $this->assertInstanceOf('OpenID_Connect_Infomaniak', $this->plugin);
    }

    /**
     * Test plugin constants.
     */
    public function test_constants() {
        $this->assertTrue(defined('INFOMANIAK_OIDC_ENDPOINT_LOGIN_URL'));
        $this->assertTrue(defined('INFOMANIAK_OIDC_ENDPOINT_USERINFO_URL'));
        $this->assertEquals('1.0.5', OpenID_Connect_Infomaniak::VERSION);
    }

    /**
     * Test plugin initialization.
     */
    public function test_plugin_initialization() {
        // Test that the plugin is properly initialized
        $this->assertInstanceOf('OpenID_Connect_Infomaniak_Option_Settings', $this->get_private_property($this->plugin, 'settings'));
        $this->assertInstanceOf('OpenID_Connect_Infomaniak_Client_Wrapper', $this->get_private_property($this->plugin, 'client_wrapper'));
    }

    /**
     * Test singleton pattern.
     */
    public function test_singleton_pattern() {
        $instance1 = OpenID_Connect_Infomaniak::instance();
        $instance2 = OpenID_Connect_Infomaniak::instance();

        $this->assertSame($instance1, $instance2);
    }
}
