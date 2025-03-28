<?php
/**
 * Direct access handler for secure files
 * This file is loaded outside of WordPress when someone tries to access a secure file
 */

// Try multiple approaches to find the WordPress environment
$wp_load_path = false;

// First attempt - standard relative path
$standard_path = dirname(__FILE__) . '/../../../wp-load.php';
if (file_exists($standard_path)) {
    $wp_load_path = $standard_path;
}

// Second attempt - use plugin directory to find WordPress root
if (!$wp_load_path) {
    $plugin_dir = dirname(dirname(__FILE__)); // Get plugin root dir
    $wp_content_dir = dirname(dirname($plugin_dir)); // Get wp-content
    $wp_root = dirname($wp_content_dir); // Get WordPress root
    $second_path = $wp_root . '/wp-load.php';
    
    if (file_exists($second_path)) {
        $wp_load_path = $second_path;
    }
}

// Third attempt - try to detect from server path
if (!$wp_load_path) {
    // Look for wp-config.php in current directory and parent directories
    $path = dirname(__FILE__);
    
    do {
        if (file_exists($path . '/wp-config.php')) {
            $wp_load_path = $path . '/wp-load.php';
            break;
        }
        
        $path = dirname($path);
        // Stop if we reach the root directory
    } while ($path !== '/' && $path !== '\\' && $path !== '.');
}

// Final check if we found wp-load.php
if (!$wp_load_path || !file_exists($wp_load_path)) {
    header('HTTP/1.0 500 Internal Server Error');
    echo 'Error: WordPress environment not found. Please contact the site administrator.';
    exit;
}

// Check for some common server configuration issues
function sfs_check_server_config() {
    $issues = array();
    
    // Check if we can access the filesystem
    if (!function_exists('readfile')) {
        $issues[] = "PHP function 'readfile' is disabled. This is required for file delivery.";
    }
    
    // Check for output buffering status
    if (ob_get_level() > 3) {
        $issues[] = "Multiple levels of output buffering detected (" . ob_get_level() . " levels). This might interfere with file delivery.";
    }
    
    // Check for zlib compression which can interfere with binary files
    if (ini_get('zlib.output_compression')) {
        $issues[] = "zlib.output_compression is enabled. This can interfere with binary file delivery.";
    }
    
    return $issues;
}

// Run the server config check
$server_issues = sfs_check_server_config();
if (!empty($server_issues) && isset($_GET['sfs_debug'])) {
    header('Content-Type: text/html');
    echo '<h1>Server Configuration Issues</h1>';
    echo '<p>The following server configuration issues might prevent proper file delivery:</p>';
    echo '<ul>';
    foreach ($server_issues as $issue) {
        echo '<li>' . htmlspecialchars($issue) . '</li>';
    }
    echo '</ul>';
    exit;
}

// Load WordPress environment
require_once $wp_load_path;

// Get plugin settings
$settings = get_option('secure_file_session_options', array(
    'protection_enabled' => true,
    'token_expiration' => 600,
    'post_types' => array('all'),
    'enable_logging' => false,
    'ip_lock' => false,
    'debug_mode' => false
));

// Check if protection is enabled
if (empty($settings['protection_enabled'])) {
    header('HTTP/1.0 403 Forbidden');
    echo 'Error: File protection is disabled.';
    exit;
}

// Function to log events if logging is enabled
function sfs_log_event($event_type, $event_data) {
    global $settings;
    
    if (empty($settings['enable_logging'])) {
        return;
    }
    
    $log_data = array(
        'event_type' => $event_type,
        'event_data' => maybe_serialize($event_data),
        'user_id' => get_current_user_id(),
        'user_ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'],
        'session_id' => session_id(),
        'timestamp' => current_time('mysql')
    );
    
    // Store log entry
    $logs = get_option('sfs_access_logs', array());
    $logs[] = $log_data;
    
    // Limit log size to prevent database bloat
    $max_logs = 1000;
    if (count($logs) > $max_logs) {
        $logs = array_slice($logs, -$max_logs);
    }
    
    update_option('sfs_access_logs', $logs);
}

/**
 * Check if an IP address is in a specified CIDR range
 * 
 * @param string $ip The IP address to check
 * @param string $cidr The CIDR range (e.g., 192.168.1.0/24)
 * @return bool Whether the IP is in the range
 */
function sfs_ip_in_range($ip, $cidr) {
    // Split CIDR notation
    list($subnet, $mask) = explode('/', $cidr);
    
    // Convert IP addresses to decimal format
    $ip_dec = ip2long($ip);
    $subnet_dec = ip2long($subnet);
    
    // Return false if either conversion failed
    if ($ip_dec === false || $subnet_dec === false) {
        return false;
    }
    
    // Create mask based on CIDR prefix
    $wildcard_dec = pow(2, (32 - $mask)) - 1;
    $netmask_dec = ~$wildcard_dec;
    
    // Check if the IP is in the subnet
    return (($ip_dec & $netmask_dec) == ($subnet_dec & $netmask_dec));
}

// Exit if no file or token
if (!isset($_GET['sfs_file']) || !isset($_GET['sfs_token'])) {
    if (!empty($settings['enable_logging'])) {
        sfs_log_event('direct_access_failed', array(
            'reason' => 'Missing file or token parameters'
        ));
    }
    
    header('HTTP/1.0 403 Forbidden');
    echo 'Error: Missing file or token parameters.';
    exit;
}

// Get parameters
$file = sanitize_text_field($_GET['sfs_file']);
$token = sanitize_text_field($_GET['sfs_token']);

// Apply rate limiting to prevent abuse
$rate_limit_enabled = isset($settings['rate_limit_enabled']) ? (bool)$settings['rate_limit_enabled'] : true; // Default to enabled
if ($rate_limit_enabled) {
    $user_ip = $_SERVER['REMOTE_ADDR'];
    $user_id = get_current_user_id();
    
    // Determine rate limit based on user role
    $rate_limit = isset($settings['rate_limit']) ? intval($settings['rate_limit']) : 10; // Default limit
    $rate_window = isset($settings['rate_window']) ? intval($settings['rate_window']) : 60; // Default window
    
    // Adjust limits for admins, editors, and authors
    if ($user_id > 0) {
        $user = get_userdata($user_id);
        if ($user) {
            if (user_can($user_id, 'manage_options')) {
                // Admin users get higher limits
                $rate_limit = isset($settings['rate_limit_admin']) ? intval($settings['rate_limit_admin']) : 50;
            } elseif (user_can($user_id, 'edit_others_posts')) {
                // Editors get somewhat higher limits
                $rate_limit = isset($settings['rate_limit_editor']) ? intval($settings['rate_limit_editor']) : 30;
            } elseif (user_can($user_id, 'publish_posts')) {
                // Authors get slightly higher limits
                $rate_limit = isset($settings['rate_limit_author']) ? intval($settings['rate_limit_author']) : 20;
            }
        }
    }
    
    $rate_key = 'sfs_rate_' . md5($user_ip . '_' . $user_id);
    
    // Get current rate data
    $rate_data = get_transient($rate_key);
    if (!$rate_data) {
        // First request in this window
        $rate_data = array(
            'count' => 1,
            'timestamp' => time(),
            'user_id' => $user_id
        );
        set_transient($rate_key, $rate_data, $rate_window);
    } else {
        // If within window, increment counter
        if (time() - $rate_data['timestamp'] < $rate_window) {
            $rate_data['count']++;
            set_transient($rate_key, $rate_data, $rate_window - (time() - $rate_data['timestamp']));
            
            // Check if limit is exceeded
            if ($rate_data['count'] > $rate_limit) {
                if (!empty($settings['enable_logging'])) {
                    $user_role = ($user_id > 0) ? implode(', ', $user->roles) : 'guest';
                    sfs_log_event('rate_limit_exceeded', array(
                        'ip' => $user_ip,
                        'user_id' => $user_id,
                        'user_role' => $user_role,
                        'requests' => $rate_data['count'],
                        'window' => $rate_window,
                        'limit' => $rate_limit
                    ));
                }
                
                // Return 429 Too Many Requests
                header('HTTP/1.1 429 Too Many Requests');
                header('Retry-After: ' . ($rate_window - (time() - $rate_data['timestamp'])));
                echo 'Error: Rate limit exceeded. Please try again later.';
                exit;
            }
        } else {
            // Window expired, reset counter
            $rate_data = array(
                'count' => 1,
                'timestamp' => time(),
                'user_id' => $user_id
            );
            set_transient($rate_key, $rate_data, $rate_window);
        }
    }
}

// Start session if not already started
if (!session_id() && !headers_sent()) {
    session_start();
}

// Debug mode - output details if requested
$debug = isset($_GET['sfs_debug']) ? true : false;
if ($debug && !empty($settings['debug_mode'])) {
    echo "<pre>";
    echo "Session ID: " . session_id() . "\n";
    echo "File: " . $file . "\n";
    echo "Token: " . $token . "\n";
    echo "Settings: \n";
    print_r($settings);
}

// Get token data from transient
$token_data = get_transient('sfs_token_' . $token);

// Verify token exists
if (!$token_data) {
    if ($debug && !empty($settings['debug_mode'])) {
        echo "Token data not found in transient\n";
        echo "</pre>";
    } else {
        error_log('[SecureFileSession] Token check failed: Token not found in transient or expired. Token: ' . $token); // Log error
        if (!empty($settings['enable_logging'])) {
            sfs_log_event('token_verification_failed', array(
                'token' => $token,
                'file' => $file,
                'reason' => 'Token not found or expired'
            ));
        }
        
        header('HTTP/1.0 403 Forbidden');
        echo 'Error: Invalid or expired token. Please request a new secure link.';
    }
    exit;
}

if ($debug && !empty($settings['debug_mode'])) {
    echo "Token data found:\n";
    print_r($token_data);
}

// Verify file matches
if ($token_data['file'] !== $file) {
    if ($debug && !empty($settings['debug_mode'])) {
        echo "File mismatch:\n";
        echo "Expected: " . $token_data['file'] . "\n";
        echo "Actual: " . $file . "\n";
        echo "</pre>";
    } else {
        error_log('[SecureFileSession] File mismatch. Expected: ' . $token_data['file'] . ' Actual: ' . $file . ' Token: ' . $token); // Log error
        if (!empty($settings['enable_logging'])) {
            sfs_log_event('token_verification_failed', array(
                'token' => $token,
                'file' => $file,
                'reason' => 'File mismatch'
            ));
        }
        
        header('HTTP/1.0 403 Forbidden');
        // echo 'Error: File mismatch.'; // Replaced with error_log
    }
    exit;
}

/*
// Verify session ID - skip in debug mode for testing
// REMOVED: This check caused issues with PHP session expiration mismatching WP login session.
// Access is now primarily based on is_user_logged_in() and ownership checks below.
if (!$debug && $token_data['session_id'] !== session_id()) {
    if (!empty($settings['enable_logging'])) {
        sfs_log_event('token_verification_failed', array(
            'token' => $token,
            'file' => $file,
            'reason' => 'Session mismatch'
        ));
    }
    
    // Redirect to the custom login page
    wp_redirect(site_url('/login/')); // Use site_url() for robustness
    exit; // Ensure script stops after redirect
}
*/

// Verify expiration
if ($token_data['expiration'] < time()) {
    if ($debug && !empty($settings['debug_mode'])) {
        echo "Token expired at: " . date('Y-m-d H:i:s', $token_data['expiration']) . "\n";
        echo "Current time: " . date('Y-m-d H:i:s') . "\n";
        echo "</pre>";
    } else {
        error_log('[SecureFileSession] Token expired. Expiration: ' . $token_data['expiration'] . ' Current: ' . time() . ' Token: ' . $token); // Log error
        if (!empty($settings['enable_logging'])) {
            sfs_log_event('token_verification_failed', array(
                'token' => $token,
                'file' => $file,
                'reason' => 'Token expired'
            ));
        }
        
        header('HTTP/1.0 403 Forbidden');
        // echo 'Error: Token expired.'; // Replaced with error_log
    }
    exit;
}

// Verify IP address if IP lock is enabled
if (!empty($settings['ip_lock']) && $token_data['user_ip'] !== $_SERVER['REMOTE_ADDR']) {
    if ($debug && !empty($settings['debug_mode'])) {
        echo "IP address mismatch:\n";
        echo "Expected: " . $token_data['user_ip'] . "\n";
        echo "Actual: " . $_SERVER['REMOTE_ADDR'] . "\n";
        echo "</pre>";
    } else {
        error_log('[SecureFileSession] IP mismatch. Expected: ' . $token_data['user_ip'] . ' Actual: ' . $_SERVER['REMOTE_ADDR'] . ' Token: ' . $token); // Log error
        if (!empty($settings['enable_logging'])) {
            sfs_log_event('token_verification_failed', array(
                'token' => $token,
                'file' => $file,
                'reason' => 'IP address mismatch'
            ));
        }
        
        header('HTTP/1.0 403 Forbidden');
        // echo 'Error: IP address mismatch.'; // Replaced with error_log
    }
    exit;
}

// Get the file path from the encoded filename
$relative_path = base64_decode($file);

if ($debug && !empty($settings['debug_mode'])) {
    echo "Relative path: " . $relative_path . "\n";
}

// Handle the case where the decoded path is a full URL instead of a relative path
if (strpos($relative_path, 'http') === 0) {
    error_log('SecureFileSession: Decoded path is a full URL: ' . $relative_path);
    
    // Extract the path from the URL, removing the domain
    $url_parts = parse_url($relative_path);
    if (isset($url_parts['path'])) {
        // Get just the path component
        $path_only = $url_parts['path'];
        
        // Remove any potential /uploads/ prefix
        $upload_dir_name = basename($upload_dir['basedir']);
        if (strpos($path_only, '/' . $upload_dir_name . '/') !== false) {
            $relative_path = substr($path_only, strpos($path_only, '/' . $upload_dir_name . '/') + strlen('/' . $upload_dir_name . '/'));
        } else {
            // If we can't find the uploads directory, just use the path
            $relative_path = ltrim($path_only, '/');
        }
        
        if ($debug && !empty($settings['debug_mode'])) {
            echo "Fixed relative path from URL: " . $relative_path . "\n";
        }
    }
}

// Always allow SVG and ICO files without security checks
$file_ext = strtolower(pathinfo($relative_path, PATHINFO_EXTENSION));
$is_ui_file = in_array($file_ext, ['svg', 'ico']);

$upload_dir = wp_upload_dir();
$uploads_path = $upload_dir['basedir'];
$file_path = path_join($uploads_path, $relative_path);

if ($debug && !empty($settings['debug_mode'])) {
    echo "Upload dir: " . $uploads_path . "\n";
    echo "Full file path: " . $file_path . "\n";
    echo "File extension: " . $file_ext . "\n";
    echo "Is UI file: " . ($is_ui_file ? "Yes" : "No") . "\n";
}

// Check if file exists first
if (!file_exists($file_path)) {
    // Check if remote storage is enabled and try to load from there
    $remote_file_found = false;
    
    if (!empty($settings['remote_storage_enabled'])) {
        require_once dirname(__FILE__) . '/class-secure-file-session.php';
        require_once dirname(__FILE__) . '/class-secure-file-session-remote-storage.php';
        
        $remote_storage = new Secure_File_Session_Remote_Storage($settings);
        
        if ($remote_storage->is_enabled() && $remote_storage->file_exists($relative_path)) {
            // File exists in remote storage, download it to a temporary location
            $temp_dir = $upload_dir['basedir'] . '/sfs-temp';
            if (!file_exists($temp_dir)) {
                wp_mkdir_p($temp_dir);
                
                // Create index.php to prevent directory listing
                $index_file = $temp_dir . '/index.php';
                if (!file_exists($index_file)) {
                    file_put_contents($index_file, '<?php // Silence is golden');
                }
                
                // Create .htaccess to prevent direct access
                $htaccess_file = $temp_dir . '/.htaccess';
                if (!file_exists($htaccess_file)) {
                    file_put_contents($htaccess_file, "Order deny,allow\nDeny from all");
                }
            }
            
            // Create a temporary file path
            $temp_file = $temp_dir . '/' . md5($file_path . time()) . '_' . basename($file_path);
            
            // Download the file
            if ($remote_storage->get_file($relative_path, $temp_file)) {
                // Use the temporary file
                $file_path = $temp_file;
                $remote_file_found = true;
                
                // Register a shutdown function to delete the temporary file
                register_shutdown_function(function() use ($temp_file) {
                    if (file_exists($temp_file)) {
                        @unlink($temp_file);
                    }
                });
                
                if (!empty($settings['enable_logging'])) {
                    sfs_log_event('remote_file_access_success', array(
                        'file_path' => $relative_path,
                        'temp_path' => $temp_file
                    ));
                }
            }
        }
    }
    
    if (!$remote_file_found) {
        if ($debug && !empty($settings['debug_mode'])) {
            echo "File does not exist: " . $file_path . "\n";
            echo "</pre>";
        } else {
            if (!empty($settings['enable_logging'])) {
                sfs_log_event('file_access_failed', array(
                    'file_path' => $file_path,
                    'reason' => 'File not found'
                ));
            }
            
            header('HTTP/1.0 404 Not Found');
        }
        exit;
    }
}

// Validate the path is within uploads directory
$real_uploads_path = realpath($uploads_path);
$real_file_path = realpath($file_path);

if ($debug && !empty($settings['debug_mode'])) {
    echo "Real uploads path: " . $real_uploads_path . "\n";
    echo "Real file path: " . ($real_file_path ? $real_file_path : "NOT FOUND") . "\n";
}

if ($real_file_path === false || strpos($real_file_path, $real_uploads_path) !== 0) {
    if ($debug && !empty($settings['debug_mode'])) {
        echo "Invalid file path - not within uploads directory\n";
        echo "</pre>";
    } else {
        error_log('[SecureFileSession] Invalid file path. Path: ' . $file_path . ' Real Path: ' . $real_file_path . ' Uploads Path: ' . $real_uploads_path);
        if (!empty($settings['enable_logging'])) {
            sfs_log_event('file_access_failed', array(
                'file_path' => $file_path,
                'reason' => 'Invalid file path'
            ));
        }
        
        header('HTTP/1.0 403 Forbidden');
    }
    exit;
}

// ---- BEGIN SECURITY & OWNERSHIP CHECK ----
$allowed_access = false;
$current_user_id = get_current_user_id();

// If security is not enabled in settings, don't enforce any more checks
if (empty($settings['protection_enabled'])) {
    $allowed_access = true;
} else {
    // Construct URL to find attachment ID
    $attachment_url = path_join($upload_dir['baseurl'], $relative_path);
    $attachment_id = attachment_url_to_postid($attachment_url);

    // Check if user is logged in - required for accessing secure files
    if (is_user_logged_in()) {
        // If we found an attachment ID, check if it's marked as exempted
        if ($attachment_id > 0) {
            $is_exempted = get_post_meta($attachment_id, '_sfs_exempted', true);
            if ($is_exempted) {
                // This file is explicitly exempted from security, allow access
                $allowed_access = true;
            }
        }

        // Check IP whitelist if enabled and attachment has specific flag
        if (!empty($settings['ip_whitelist_enabled']) && $attachment_id > 0) {
            // Check if this file requires IP whitelisting
            $requires_ip_whitelist = get_post_meta($attachment_id, '_sfs_requires_whitelist', true);
            
            if ($requires_ip_whitelist) {
                $user_ip = $_SERVER['REMOTE_ADDR'];
                $allowed_ips = !empty($settings['ip_whitelist']) ? explode(',', str_replace(' ', '', $settings['ip_whitelist'])) : [];
                $ip_whitelist_valid = false;
                
                // Check if user's IP is in the whitelist
                foreach ($allowed_ips as $allowed_ip) {
                    // Check exact match
                    if ($allowed_ip === $user_ip) {
                        $ip_whitelist_valid = true;
                        break;
                    }
                    
                    // Check CIDR notation (e.g., 192.168.1.0/24)
                    if (strpos($allowed_ip, '/') !== false) {
                        if (sfs_ip_in_range($user_ip, $allowed_ip)) {
                            $ip_whitelist_valid = true;
                            break;
                        }
                    }
                }
                
                if (!$ip_whitelist_valid) {
                    if (!empty($settings['enable_logging'])) {
                        sfs_log_event('ip_whitelist_denied', array(
                            'file_path' => $file_path,
                            'user_id' => $current_user_id,
                            'ip' => $user_ip
                        ));
                    }
                    
                    header('HTTP/1.0 403 Forbidden');
                    echo !empty($settings['ip_whitelist_message']) ? $settings['ip_whitelist_message'] : 'Access denied: Your IP is not authorized.';
                    exit;
                }
            }
        }

        // Always allow access to SVG and ICO files for logged-in users
        if (in_array($file_ext, ['svg', 'ico'])) {
            $allowed_access = true;
        } 
        // Check if user is admin (always allow access for admins)
        elseif (current_user_can('manage_options')) {
            $allowed_access = true;
        } 
        // Check file ownership and security status
        elseif ($attachment_id > 0) {
            $is_secured = get_post_meta($attachment_id, '_sfs_secured', true);
            $post_author_id = get_post_field('post_author', $attachment_id);
            
            // Authors always get access to their own files
            if ($post_author_id == $current_user_id) {
                $allowed_access = true;
            }
            // For other users, check role-based permissions if file is secured
            elseif ($is_secured) {
                // We need to load the plugin class to check permissions
                require_once dirname(__FILE__) . '/class-secure-file-session.php';
                $sfs = new Secure_File_Session();
                $sfs->init();
                
                if ($sfs->user_can_access_file_type($file_path)) {
                    $allowed_access = true;
                }
            } 
            // If file is not explicitly secured, check global security setting
            else {
                // Check if auto-securing uploads is enabled in settings
                if (!empty($settings['auto_secure_uploads'])) {
                    // We need to load the plugin class to check permissions
                    require_once dirname(__FILE__) . '/class-secure-file-session.php';
                    $sfs = new Secure_File_Session();
                    $sfs->init();
                    
                    if ($sfs->user_can_access_file_type($file_path)) {
                        $allowed_access = true;
                    }
                } else {
                    // If auto-securing is disabled and file is not secured, allow access
                    $allowed_access = true;
                }
            }
        } else {
            // No attachment ID found, fallback to default permissions
            if (!empty($settings['auto_secure_uploads'])) {
                require_once dirname(__FILE__) . '/class-secure-file-session.php';
                $sfs = new Secure_File_Session();
                $sfs->init();
                
                if ($sfs->user_can_access_file_type($file_path)) {
                    $allowed_access = true;
                }
            } else {
                // If auto-securing is disabled, allow access
                $allowed_access = true;
            }
        }
    } else {
        // User is not logged in - redirect to login page with redirect_to parameter
        if (!empty($settings['enable_logging'])) {
            sfs_log_event('file_access_redirect_to_login', array(
                'file_path' => $file_path,
                'reason' => 'User not logged in'
            ));
        }
        
        // Use the custom login page instead of wp_login_url
        $custom_login_url = home_url('/login/');
        $current_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
        
        // Add the redirect parameter to the custom login URL
        $redirect_url = add_query_arg('redirect_to', urlencode($current_url), $custom_login_url);
        
        // Redirect to the custom login page
        header('Location: ' . $redirect_url);
        exit;
    }
}

// If access is not allowed, redirect to login or show access denied
if (!$allowed_access) {
    if (!empty($settings['enable_logging'])) {
        sfs_log_event('file_access_denied', array(
            'file_path' => $file_path,
            'user_id' => isset($current_user_id) ? $current_user_id : 0,
            'reason' => 'User does not have required permissions'
        ));
    }
    
    if (!is_user_logged_in()) {
        // Redirect to login for guests
        wp_redirect(wp_login_url(home_url($_SERVER['REQUEST_URI'])));
    } else {
        // Show access denied for logged-in users without permission
        header('HTTP/1.0 403 Forbidden');
        echo 'Access denied: You do not have permission to access this file.';
    }
    exit;
}
// ---- END SECURITY & OWNERSHIP CHECK ----

if ($debug && !empty($settings['debug_mode'])) {
    echo "File exists and is valid.\n";
    echo "</pre>";
    exit; // Stop here if in debug mode
}

// Log successful file access
if (!empty($settings['enable_logging'])) {
    sfs_log_event('file_access_success', array(
        'file_path' => $file_path,
        'token' => $token
    ));
}

// Get file information
$file_name = basename($file_path);
$file_size = filesize($file_path);
$file_ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));

// Apply watermark if enabled and file type is supported
$watermarked_file = $file_path;
if (!empty($settings['watermark_enabled'])) {
    // Supportable file formats for watermarking
    $watermarkable_types = array(
        'jpg', 'jpeg', 'png', 'gif', 'pdf'
    );
    
    if (in_array($file_ext, $watermarkable_types)) {
        // Load watermarking class
        require_once dirname(__FILE__) . '/class-secure-file-session-watermark.php';
        
        // Create watermark instance
        $watermarker = new Secure_File_Session_Watermark($settings);
        
        // Get user information for watermark
        $user_info = array(
            'username' => $current_user_id > 0 ? get_userdata($current_user_id)->user_login : 'Guest',
            'display_name' => $current_user_id > 0 ? get_userdata($current_user_id)->display_name : 'Guest',
            'email' => $current_user_id > 0 ? get_userdata($current_user_id)->user_email : '',
            'ip' => $_SERVER['REMOTE_ADDR']
        );
        
        // Apply watermark
        $watermarked_file = $watermarker->apply_watermark($file_path, $user_info);
        
        // If watermarking was successful, update file details
        if ($watermarked_file !== $file_path) {
            $file_name = basename($watermarked_file);
            $file_size = filesize($watermarked_file);
            
            if (!empty($settings['enable_logging'])) {
                sfs_log_event('file_watermarked', array(
                    'original_file' => $file_path,
                    'watermarked_file' => $watermarked_file,
                    'user_id' => $current_user_id
                ));
            }
        }
    }
}

// Define common MIME types
$mime_types = array(
    'pdf' => 'application/pdf',
    'jpg' => 'image/jpeg',
    'jpeg' => 'image/jpeg',
    'png' => 'image/png',
    'gif' => 'image/gif',
    'svg' => 'image/svg+xml',
    'webp' => 'image/webp',
    'avif' => 'image/avif',
    'doc' => 'application/msword',
    'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls' => 'application/vnd.ms-excel',
    'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'ppt' => 'application/vnd.ms-powerpoint',
    'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'zip' => 'application/zip',
    'rar' => 'application/x-rar-compressed',
    'mp3' => 'audio/mpeg',
    'mp4' => 'video/mp4',
    'txt' => 'text/plain',
    'csv' => 'text/csv',
    'html' => 'text/html',
    'htm' => 'text/html',
    'json' => 'application/json',
    'xml' => 'application/xml',
);

// Get MIME type - use WP function if available, otherwise fallback to our extension mapping
if (function_exists('wp_check_filetype')) {
    $filetype = wp_check_filetype($file_name);
    if (!empty($filetype['type'])) {
        $file_mime = $filetype['type'];
    } else {
        // Fallback to our extension map
        $file_mime = isset($mime_types[$file_ext]) ? $mime_types[$file_ext] : 'application/octet-stream';
    }
} else {
    // Fallback to our extension map
    $file_mime = isset($mime_types[$file_ext]) ? $mime_types[$file_ext] : 'application/octet-stream';
}

// Force application/octet-stream for unknown types to ensure download 
if ($file_mime === 'application/octet-stream' || empty($file_mime)) {
    $file_mime = 'application/octet-stream';
    // Force download disposition
    $disposition = 'attachment';
} else {
    // Use inline for PDFs, images, etc. to allow preview
    $is_viewable = in_array($file_mime, ['application/pdf', 'image/jpeg', 'image/png', 'image/gif', 'image/webp']);
    $disposition = $is_viewable ? 'inline' : 'attachment';
}

// Before serving the file, log detailed debug info to help diagnose issues
error_log('SecureFileSession: About to serve file ' . $file_path);
error_log('SecureFileSession: File exists: ' . (file_exists($file_path) ? 'Yes' : 'No'));
error_log('SecureFileSession: File is readable: ' . (is_readable($file_path) ? 'Yes' : 'No'));
error_log('SecureFileSession: File size: ' . filesize($file_path) . ' bytes');
error_log('SecureFileSession: MIME type: ' . $file_mime);
error_log('SecureFileSession: Using disposition: ' . $disposition);

// Clean any previous output
if (ob_get_level()) {
    ob_end_clean();
}

// Flush all previous buffers to ensure clean response
while (ob_get_level()) {
    ob_end_clean();
}

// Set cache control headers
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');

// Handle HEAD requests for file size checking
if ($_SERVER['REQUEST_METHOD'] === 'HEAD') {
    // Allow cross-origin requests for HEAD method
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: HEAD, GET');
    header('Access-Control-Allow-Headers: Content-Type, Content-Length');
    header('Access-Control-Expose-Headers: Content-Length');
    
    header('Content-Type: ' . $file_mime);
    header('Content-Disposition: ' . $disposition . '; filename="' . $file_name . '"');
    header('Content-Length: ' . $file_size);
    exit;
}

// Set headers for file download
header('Content-Type: ' . $file_mime);
header('Content-Disposition: ' . $disposition . '; filename="' . $file_name . '"');
header('Content-Length: ' . $file_size);
header('Connection: close');

// Double check that we're in a clean state for output
if (headers_sent($filename, $linenum)) {
    error_log('[SecureFileSession] Warning: Headers already sent before file output in ' . $filename . ' on line ' . $linenum);
}

// Check that the file is actually readable
if (!is_readable($watermarked_file)) {
    error_log('[SecureFileSession] Error: File not readable: ' . $watermarked_file);
    header('HTTP/1.0 404 Not Found');
    echo 'Error: File not readable. Please contact the site administrator.';
    exit;
}

try {
    // Output the file contents
    if (!@readfile($watermarked_file)) {
        throw new Exception('readfile() returned false');
    }
} catch (Exception $e) {
    error_log('[SecureFileSession] Error reading file: ' . $watermarked_file . '. Error: ' . $e->getMessage());
    header('HTTP/1.0 500 Internal Server Error');
    echo 'Error: Failed to read file. Please contact the site administrator.';
}

exit; 