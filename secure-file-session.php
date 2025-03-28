<?php
/**
 * Plugin Name: Secure File Session
 * Plugin URI: https://yourwebsite.com/secure-file-session
 * Description: Secure your WordPress uploads by generating session-based secure URLs for files.
 * Version: 1.0.0
 * Author: Your Name
 * Author URI: https://yourwebsite.com
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: secure-file-session
 * Domain Path: /languages
 *
 * @package SecureFileSession
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    // Direct file access - handle secure file request
    if (isset($_GET['sfs_file']) && isset($_GET['sfs_token'])) {
        // Turn off any PHP errors or warnings that might be output before headers
        ini_set('display_errors', 0);
        error_reporting(0);
        
        // Make sure no output has happened yet
        if (headers_sent($filename, $linenum)) {
            // If headers already sent, log this and exit
            error_log("SecureFileSession: Headers already sent in $filename on line $linenum");
            header('HTTP/1.0 500 Internal Server Error');
            echo 'Error: Headers already sent. Cannot serve file.';
            exit;
        }
        
        require_once dirname(__FILE__) . '/includes/direct-access.php';
        exit;
    }
    die;
}

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

// Define plugin constants
define('SECURE_FILE_SESSION_VERSION', '1.0.0');
define('SECURE_FILE_SESSION_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('SECURE_FILE_SESSION_PLUGIN_URL', plugin_dir_url(__FILE__));

// Set direct access method (used for file delivery)
define('SFS_USE_DIRECT_ACCESS', true);

/**
 * The code that runs during plugin activation.
 */
function activate_secure_file_session() {
    // Create default settings
    $default_settings = array(
        'protection_enabled' => true,
        'token_expiration' => 86400, // Default: 24 hours (was 10 minutes)
        'post_types' => array('all'),
        'enable_logging' => false,
        'auto_clear_logs' => true,
        'log_retention_days' => 30,
        'ip_lock' => false,
        'disable_styling_in_tables' => false,
        'protect_svg_icons' => true,  // Default to true to prevent conflicts
        'excluded_pages' => '/login/', // Default to exclude login page
        'debug_mode' => false
    );
    
    // Only add if not exists
    if (!get_option('secure_file_session_options')) {
        add_option('secure_file_session_options', $default_settings);
    }
}

/**
 * The code that runs during plugin deactivation.
 */
function deactivate_secure_file_session() {
    // Clear any scheduled hooks
    wp_clear_scheduled_hook('secure_file_session_cleanup');
}

register_activation_hook(__FILE__, 'activate_secure_file_session');
register_deactivation_hook(__FILE__, 'deactivate_secure_file_session');

/**
 * Begins execution of the plugin.
 */
function run_secure_file_session() {
    global $secure_file_session;
    
    // Load required files
    require_once SECURE_FILE_SESSION_PLUGIN_DIR . 'includes/class-secure-file-session.php';
    require_once SECURE_FILE_SESSION_PLUGIN_DIR . 'includes/class-secure-file-session-integrations.php';
    
    // Initialize the main plugin class
    $secure_file_session = new Secure_File_Session();
    $secure_file_session->init();
    
    // Schedule cleanup - once daily
    if (!wp_next_scheduled('secure_file_session_cleanup')) {
        wp_schedule_event(time(), 'daily', 'secure_file_session_cleanup');
    }
    
    // Register cleanup hook
    add_action('secure_file_session_cleanup', function() {
        global $wpdb;
        
        // Clean up expired transients
        $time = time();
        $expired = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT option_name 
                FROM {$wpdb->options} 
                WHERE option_name LIKE %s 
                AND option_value < %d",
                $wpdb->esc_like('_transient_timeout_sfs_token_') . '%',
                $time
            )
        );
        
        if (!empty($expired)) {
            foreach ($expired as $transient) {
                $name = str_replace('_transient_timeout_', '', $transient);
                delete_transient($name);
            }
        }
        
        // Auto-clean logs older than 30 days if logging is enabled
        $logs = get_option('sfs_access_logs', array());
        if (!empty($logs)) {
            $settings = get_option('secure_file_session_options', array());
            $auto_clear_logs = isset($settings['auto_clear_logs']) ? (bool) $settings['auto_clear_logs'] : true;
            $retention_days = isset($settings['log_retention_days']) ? (int) $settings['log_retention_days'] : 30;
            
            if ($auto_clear_logs && $retention_days > 0) {
                $cutoff_time = strtotime("-{$retention_days} days");
                $filtered_logs = array();
                
                foreach ($logs as $log) {
                    $log_time = strtotime($log['timestamp']);
                    if ($log_time >= $cutoff_time) {
                        $filtered_logs[] = $log;
                    }
                }
                
                if (count($filtered_logs) !== count($logs)) {
                    update_option('sfs_access_logs', $filtered_logs);
                }
            }
        }
        
        // Prune logs if they exceed the maximum size
        $logs = get_option('sfs_access_logs', array());
        $max_logs = 1000;
        if (count($logs) > $max_logs) {
            $logs = array_slice($logs, -$max_logs);
            update_option('sfs_access_logs', $logs);
        }
    });
    
    // Register assets
    add_action('admin_enqueue_scripts', function($hook) {
        if ('settings_page_secure-file-session' !== $hook) {
            return;
        }
        
        wp_enqueue_style(
            'secure-file-session-admin',
            SECURE_FILE_SESSION_PLUGIN_URL . 'assets/css/admin.css',
            array(),
            SECURE_FILE_SESSION_VERSION
        );
        
        wp_enqueue_script(
            'secure-file-session-admin',
            SECURE_FILE_SESSION_PLUGIN_URL . 'assets/js/admin.js',
            array('jquery'),
            SECURE_FILE_SESSION_VERSION,
            true
        );
    });
}

run_secure_file_session();

// Register our options in the allowed options list directly
add_filter('allowed_options', function($allowed_options) {
    $allowed_options['secure_file_session'] = array('secure_file_session_options');
    return $allowed_options;
});

// Ensure the admin menu is registered, but only if it hasn't been added already
add_action('admin_menu', function() {
    // Skip if not in admin area
    if (!is_admin()) {
        return;
    }
    
    // Check if our menu is already registered via the main plugin class
    global $submenu;
    $menu_exists = false;
    
    if (!empty($submenu['options-general.php'])) {
        foreach ($submenu['options-general.php'] as $item) {
            if (isset($item[2]) && $item[2] === 'secure-file-session-settings') {
                $menu_exists = true;
                break;
            }
        }
    }
    
    // If menu already exists, don't add it again
    if ($menu_exists) {
        return;
    }
    
    // Register menu item
    add_options_page(
        'Secure File Session',
        'Secure File Session',
        'edit_posts',
        'secure-file-session-settings',
        function() {
            // Register settings if not already registered
            if (!get_registered_settings()['secure_file_session_options']) {
                register_setting(
                    'secure_file_session',
                    'secure_file_session_options',
                    array('sanitize_callback' => function($input) {
                        // Basic sanitization - ensures we have an array
                        return is_array($input) ? $input : array();
                    })
                );
            }
            
            // Include admin class if it doesn't exist yet
            if (!class_exists('Secure_File_Session_Admin')) {
                require_once SECURE_FILE_SESSION_PLUGIN_DIR . 'includes/class-secure-file-session-admin.php';
                $admin = new Secure_File_Session_Admin();
                $admin->init();
            }
            
            global $secure_file_session;
            if ($secure_file_session && isset($secure_file_session->admin)) {
                $secure_file_session->admin->render_settings_page();
            } else {
                $admin = new Secure_File_Session_Admin();
                $admin->render_settings_page();
            }
        }
    );
}, 999); // Use a very late priority so it runs after the main plugin 