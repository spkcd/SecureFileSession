<?php
/**
 * Direct access handler for Secure File Session
 *
 * This file is placed in the plugin root to handle direct access to secure files
 */

// Start session first thing to ensure it's available
if (!session_id() && !headers_sent()) {
    session_start();
}

// Exit if accessed directly without proper parameters
if (!isset($_GET['sfs_file']) || !isset($_GET['sfs_token'])) {
    http_response_code(403);
    die('Access denied');
}

// Load WordPress core
$wp_load_file = dirname(dirname(dirname(__FILE__))) . '/wp-load.php';
if (file_exists($wp_load_file)) {
    require_once($wp_load_file);
} else {
    http_response_code(500);
    die('WordPress core files not found');
}

// Load main plugin class
require_once dirname(__FILE__) . '/includes/class-secure-file-session.php';

// Get file and token from request
$encoded_file = sanitize_text_field($_GET['sfs_file']);
$token = sanitize_text_field($_GET['sfs_token']);

// Initialize plugin instance
global $secure_file_session;
if (!$secure_file_session) {
    $secure_file_session = new Secure_File_Session();
}

// Get plugin settings
$settings = get_option('secure_file_session_options', array());

// SECURITY CHECK: Default to requiring login unless explicitly disabled
$force_login = isset($settings['force_login']) ? (bool) $settings['force_login'] : true;
if ($force_login) {
    if (!is_user_logged_in()) {
        // Log the access attempt
        if (method_exists($secure_file_session, 'log_file_access')) {
            $secure_file_session->log_file_access(base64_decode($encoded_file), 'failed', 'User not logged in');
        }
        
        // Redirect to login page with return URL
        $login_url = wp_login_url($_SERVER['REQUEST_URI']);
        wp_redirect($login_url);
        exit;
    }
}

// Verify token
if (!$secure_file_session->verify_token($encoded_file, $token)) {
    // Check if token exists but session changed (common issue)
    $transient_key = 'sfs_token_' . $token;
    $token_data = get_transient($transient_key);
    
    if ($token_data && isset($token_data['session_id']) && $token_data['session_id'] !== session_id()) {
        // Session mismatch - log for debugging
        if (method_exists($secure_file_session, 'log_file_access')) {
            $secure_file_session->log_file_access(base64_decode($encoded_file), 'denied', 
                'Session mismatch: Expected ' . $token_data['session_id'] . ', got ' . session_id());
        }
    }
    
    http_response_code(403);
    die('Invalid or expired token. Please return to the page and try again.');
}

// Get file path
$file_path = $secure_file_session->get_file_path_from_encoded_file($encoded_file);

// Check if file exists
if (!file_exists($file_path)) {
    http_response_code(404);
    die('File not found');
}

// Serve the file
$secure_file_session->serve_file($file_path);
exit; 