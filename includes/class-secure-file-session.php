<?php
/**
 * Main plugin class
 */
class Secure_File_Session {
    /**
     * Token expiration time in seconds (10 minutes)
     */
    const TOKEN_EXPIRATION = 600;
    
    /**
     * Uploads directory info
     */
    private $upload_dir;
    
    /**
     * Uploads directory URL
     */
    private $upload_url;
    
    /**
     * Integrations instance
     */
    private $integrations;
    
    /**
     * Admin instance
     */
    private $admin;
    
    /**
     * Plugin settings
     */
    private $settings;
    
    /**
     * Remote storage instance
     */
    private $remote_storage;
    
    /**
     * Default plugin settings
     */
    private $default_settings = array(
        'protection_enabled' => true,
        'token_expiration' => self::TOKEN_EXPIRATION,
        'post_types' => array('all'),
        'enable_logging' => false,
        'auto_clear_logs' => true,
        'log_retention_days' => 30,
        'ip_lock' => false,
        'disable_styling_in_tables' => false,
        'protect_svg_icons' => true,  // Default to true to prevent conflicts
        'excluded_pages' => '/login/', // Default to exclude login page
        'debug_mode' => false,
        'role_permissions' => array(),
        'rate_limit_enabled' => true, // Enable rate limiting by default
        'rate_limit' => 10,          // 10 requests per window (for regular users)
        'rate_window' => 60,         // 60 second window
        'rate_limit_admin' => 50,    // Higher limit for admins
        'rate_limit_editor' => 30,   // Higher limit for editors
        'rate_limit_author' => 20,   // Higher limit for authors
        // Watermarking settings
        'watermark_enabled' => false,
        'watermark_images' => true,
        'watermark_pdfs' => true,
        'watermark_text' => 'Downloaded by: %username% on %date%',
        'watermark_color' => 'rgba(0,0,0,0.3)',
        'watermark_position' => 'center',
        'watermark_font_size' => 20,
        // IP Whitelisting settings
        'ip_whitelist_enabled' => false,
        'ip_whitelist' => '',  // Comma-separated list of IP addresses
        'ip_whitelist_message' => 'Access denied: Your IP address is not authorized to access this file.',
        // File validation settings
        'file_validation_enabled' => true,
        'allowed_file_types' => 'jpg,jpeg,png,gif,pdf,doc,docx,xls,xlsx,ppt,pptx,txt,zip,mp3,mp4',
        'disallowed_extensions' => 'php,phtml,php3,php4,php5,phps,pht,phar,cgi,pl,py,asp,aspx,exe,bat,cmd,sh,dll,jsp,js,json',
        'scan_file_contents' => true,
        'file_content_signatures' => '<?php,<%,<script,<iframe,javascript:,eval(',
        // Remote storage settings
        'remote_storage_enabled' => false,
        'remote_storage_type' => 's3', // s3, google, azure, etc.
        'remote_storage_creds' => array(
            's3_access_key' => '',
            's3_secret_key' => '',
            's3_bucket' => '',
            's3_region' => 'us-east-1',
            's3_endpoint' => '', // For custom S3-compatible storage
            's3_path_prefix' => '', // Optional path prefix for all files
        ),
        'remote_storage_cache_enabled' => true,
        'remote_storage_cache_expiration' => 3600, // 1 hour
        'remote_storage_local_fallback' => true,
        'auto_secure_uploads' => true
    );
    
    /**
     * Initialize the plugin
     */
    public function init() {
        // Load settings
        $this->load_settings();
        
        // Define uploads directory
        $upload_dir = wp_upload_dir();
        $this->upload_dir = $upload_dir['basedir'];
        $this->upload_url = $upload_dir['baseurl'];
        
        // Set up filters to replace URLs with secure URLs
        if (!empty($this->settings['protection_enabled'])) {
            // Replace image URLs in content
            add_filter('the_content', array($this, 'replace_file_urls'), 999);
            
            // Replace attachment URLs
            add_filter('wp_get_attachment_url', array($this, 'secure_attachment_url'), 999);
            
            // Replace image src attributes
            add_filter('wp_get_attachment_image_src', array($this, 'secure_image_src'), 999);
            
            // Replace image attributes (including srcset)
            add_filter('wp_get_attachment_image_attributes', array($this, 'secure_image_attributes'), 999);
            
            // Replace image srcset
            add_filter('wp_calculate_image_srcset', array($this, 'secure_image_srcset'), 999);
        }
        
        // Secure attachment URLs in REST API responses
        add_filter('rest_prepare_attachment', array($this, 'secure_rest_attachment'), 999, 3);
        
        // Add post type support for REST API URL rewriting
        $supported_post_types = get_post_types(array('public' => true), 'names');
        foreach ($supported_post_types as $post_type) {
            add_filter("rest_prepare_{$post_type}", array($this, 'secure_rest_post'), 999, 3);
        }
        
        // Add direct defense for uploads directory
        add_action('template_redirect', array($this, 'protect_uploads_directory'), 1);
        
        // Interceptept direct access attempts via our direct-access.php file
        add_action('init', array($this, 'handle_file_access'), 5); // Early priority
        
        // Add filter for excluding files from security
        add_filter('secure_file_session_excluded_files', array($this, 'exclude_theme_files'), 10);
        
        // Add template tags/shortcode to display private files in content
        add_action('init', array($this, 'register_shortcodes'));

        // Handle securing new uploads automatically
        add_action('add_attachment', array($this, 'process_new_attachment'));
        
        // Force download attribute on links
        add_action('wp_footer', array($this, 'add_download_attribute_to_links'));
        
        // Start session if not already started
        $this->maybe_start_session();
        
        // Add rewrite rules
        add_action('init', array($this, 'add_rewrite_rules'), 10);
        
        // Directly register secure endpoint for parsing
        add_action('init', array($this, 'register_secure_endpoint'), 11);
        
        // Add filename display fix for frontend
        add_action('init', array($this, 'replace_link_text_with_filename'), 20);
        
        // Register query vars
        add_filter('query_vars', array($this, 'register_query_vars'));
        
        // Handle secure file requests - only for our specific endpoints
        add_action('parse_request', array($this, 'parse_secure_file_request'), 10);
        add_action('template_redirect', array($this, 'handle_secure_file_request'));
        
        // Prevent securing theme images/media files
        add_filter('secure_file_session_excluded_files', array($this, 'exclude_theme_files'));
        
        // Initialize integrations
        $this->initialize_integrations();
        
        // Initialize remote storage
        $this->initialize_remote_storage();
        
        // Initialize admin on admin_init hook - This fixes the "undefined function" error
        if (is_admin()) {
            add_action('admin_init', array($this, 'initialize_admin'));
            
            // Add IP whitelist checkbox to attachment edit screen
            add_filter('attachment_fields_to_edit', array($this, 'add_ip_whitelist_field'), 10, 2);
            add_filter('attachment_fields_to_save', array($this, 'save_ip_whitelist_field'), 10, 2);
        }
        
        // Register cleanup hook for watermarked files
        add_action('sfs_cleanup_watermarked_file', array($this, 'cleanup_watermarked_file'));
        
        // Add file validation hooks if enabled
        if (!empty($this->settings['file_validation_enabled'])) {
            add_filter('wp_handle_upload_prefilter', array($this, 'validate_file_upload'));
            add_filter('upload_mimes', array($this, 'filter_upload_mimes'));
        }
    }
    
    /**
     * Handle file access requests
     */
    public function handle_file_access() {
        // This method is only needed if we're intercepting file access requests
        // It would check for direct file access and process secure file requests
        
        // Check if this is a secure file request
        if (isset($_GET['sfs_file']) && isset($_GET['sfs_token'])) {
            $file = isset($_GET['sfs_file']) ? sanitize_text_field($_GET['sfs_file']) : '';
            $token = isset($_GET['sfs_token']) ? sanitize_text_field($_GET['sfs_token']) : '';
            
            if (empty($file) || empty($token)) {
                wp_die(__('Invalid file access request', 'secure-file-session'));
            }
            
            // Get file path from encoded file parameter
            $file_path = $this->get_file_path_from_encoded_file($file);
            
            // Verify token
            if (!$this->verify_token($file, $token)) {
                wp_die(__('Invalid or expired token', 'secure-file-session'));
            }
            
            // Log successful access
            $this->log_file_access($file_path, 'success');
            
            // Serve the file
            $this->serve_file($file_path);
            exit;
        }
    }
    
    /**
     * Register shortcodes for displaying secure files
     */
    public function register_shortcodes() {
        // Register shortcode for displaying a secure file link
        add_shortcode('secure_file', array($this, 'secure_file_shortcode'));
        
        // Register shortcode for displaying a secure file gallery
        add_shortcode('secure_gallery', array($this, 'secure_gallery_shortcode'));
    }
    
    /**
     * Shortcode for displaying a secure file link
     * 
     * @param array $atts Shortcode attributes
     * @return string HTML output
     */
    public function secure_file_shortcode($atts) {
        $atts = shortcode_atts(array(
            'id' => 0,            // Attachment ID
            'url' => '',          // File URL (alternative to ID)
            'text' => '',         // Link text
            'class' => '',        // CSS class
            'download' => 'true'  // Force download
        ), $atts, 'secure_file');
        
        // Get secure URL
        $secure_url = '';
        $file_name = '';
        
        if (!empty($atts['id'])) {
            // Get URL from attachment ID
            $url = wp_get_attachment_url($atts['id']);
            if ($url) {
                $file_name = basename(get_attached_file($atts['id']));
                
                // Make sure we're using a relative path, not a full URL
                if (strpos($url, $this->upload_url) === 0) {
                    $file_path = substr($url, strlen($this->upload_url));
                    $file_path = ltrim($file_path, '/');
                } else {
                    $file_path = $url; // Fallback if URL doesn't start with upload URL
                    error_log('SecureFileSession: File path does not match upload URL pattern: ' . $url);
                }
                
                $secure_url = $this->get_secure_url($file_path);
            }
        } elseif (!empty($atts['url'])) {
            // Get URL directly
            $url = $atts['url'];
            $file_name = basename($url);
            
            // Make sure we're using a relative path, not a full URL
            if (strpos($url, $this->upload_url) === 0) {
                $file_path = substr($url, strlen($this->upload_url));
                $file_path = ltrim($file_path, '/');
            } else {
                $file_path = $url; // Fallback if URL doesn't start with upload URL
                error_log('SecureFileSession: File path does not match upload URL pattern: ' . $url);
            }
            
            $secure_url = $this->get_secure_url($file_path);
        }
        
        if (empty($secure_url)) {
            return ''; // No valid URL found
        }
        
        // Set link text
        $link_text = !empty($atts['text']) ? $atts['text'] : $file_name;
        
        // Build link
        $download_attr = ($atts['download'] === 'true') ? ' download' : '';
        $class_attr = !empty($atts['class']) ? ' class="' . esc_attr($atts['class']) . '"' : '';
        
        return sprintf('<a href="%s"%s%s>%s</a>', 
            esc_url($secure_url), 
            $download_attr, 
            $class_attr, 
            esc_html($link_text)
        );
    }
    
    /**
     * Shortcode for displaying a secure file gallery
     * 
     * @param array $atts Shortcode attributes
     * @return string HTML output
     */
    public function secure_gallery_shortcode($atts) {
        $atts = shortcode_atts(array(
            'ids' => '',          // Comma-separated attachment IDs
            'columns' => 3,       // Number of columns
            'size' => 'thumbnail', // Image size
            'class' => '',        // CSS class
            'download' => 'true'  // Force download
        ), $atts, 'secure_gallery');
        
        if (empty($atts['ids'])) {
            return ''; // No IDs provided
        }
        
        // Get attachment IDs
        $ids = explode(',', $atts['ids']);
        $ids = array_map('trim', $ids);
        $ids = array_filter($ids);
        
        if (empty($ids)) {
            return ''; // No valid IDs
        }
        
        // Start gallery output
        $output = '<div class="secure-file-gallery columns-' . intval($atts['columns']) . (!empty($atts['class']) ? ' ' . esc_attr($atts['class']) : '') . '">';
        
        // Loop through attachments
        foreach ($ids as $id) {
            $url = wp_get_attachment_url($id);
            if (!$url) {
                continue; // Skip invalid attachments
            }
            
            // Get file info
            $file_name = basename(get_attached_file($id));
            $file_path = str_replace($this->upload_url, '', $url);
            $secure_url = $this->get_secure_url($file_path);
            
            // Get thumbnail
            $thumbnail = wp_get_attachment_image($id, $atts['size']);
            if (!$thumbnail) {
                // If not an image, use a generic icon
                $thumbnail = '<div class="file-icon">' . substr(pathinfo($file_name, PATHINFO_EXTENSION), 0, 4) . '</div>';
            }
            
            // Download attribute
            $download_attr = ($atts['download'] === 'true') ? ' download' : '';
            
            // Add item to gallery
            $output .= '<div class="gallery-item">';
            $output .= '<a href="' . esc_url($secure_url) . '"' . $download_attr . '>';
            $output .= $thumbnail;
            $output .= '<span class="filename">' . esc_html($file_name) . '</span>';
            $output .= '</a>';
            $output .= '</div>';
        }
        
        $output .= '</div>';
        
        return $output;
    }
    
    /**
     * Load plugin settings
     */
    private function load_settings() {
        $default_settings = array(
            'protection_enabled' => true,
            'token_expiration' => self::TOKEN_EXPIRATION,
            'post_types' => array('all'),
            'enable_logging' => false,
            'auto_clear_logs' => true,
            'log_retention_days' => 30,
            'ip_lock' => false,
            'disable_styling_in_tables' => false,
            'protect_svg_icons' => true,  // Default to true to prevent conflicts
            'excluded_pages' => '/login/', // Default to exclude login page
            'debug_mode' => false,
            'role_permissions' => array(),
            'rate_limit_enabled' => true, // Enable rate limiting by default
            'rate_limit' => 10,          // 10 requests per window (for regular users)
            'rate_window' => 60,         // 60 second window
            'rate_limit_admin' => 50,    // Higher limit for admins
            'rate_limit_editor' => 30,   // Higher limit for editors
            'rate_limit_author' => 20,   // Higher limit for authors
            // Watermarking settings
            'watermark_enabled' => false,
            'watermark_images' => true,
            'watermark_pdfs' => true,
            'watermark_text' => 'Downloaded by: %username% on %date%',
            'watermark_color' => 'rgba(0,0,0,0.3)',
            'watermark_position' => 'center',
            'watermark_font_size' => 20,
            // IP Whitelisting settings
            'ip_whitelist_enabled' => false,
            'ip_whitelist' => '',  // Comma-separated list of IP addresses
            'ip_whitelist_message' => 'Access denied: Your IP address is not authorized to access this file.',
            // File validation settings
            'file_validation_enabled' => true,
            'allowed_file_types' => 'jpg,jpeg,png,gif,pdf,doc,docx,xls,xlsx,ppt,pptx,txt,zip,mp3,mp4',
            'disallowed_extensions' => 'php,phtml,php3,php4,php5,phps,pht,phar,cgi,pl,py,asp,aspx,exe,bat,cmd,sh,dll,jsp,js,json',
            'scan_file_contents' => true,
            'file_content_signatures' => '<?php,<%,<script,<iframe,javascript:,eval(',
            // Remote storage settings
            'remote_storage_enabled' => false,
            'remote_storage_type' => 's3', // s3, google, azure, etc.
            'remote_storage_creds' => array(
                's3_access_key' => '',
                's3_secret_key' => '',
                's3_bucket' => '',
                's3_region' => 'us-east-1',
                's3_endpoint' => '', // For custom S3-compatible storage
                's3_path_prefix' => '', // Optional path prefix for all files
            ),
            'remote_storage_cache_enabled' => true,
            'remote_storage_cache_expiration' => 3600, // 1 hour
            'remote_storage_local_fallback' => true,
        );
        
        $this->settings = get_option('secure_file_session_options', $default_settings);
        $this->settings = wp_parse_args($this->settings, $default_settings);
    }
    
    /**
     * Check if protection is enabled
     */
    public function is_protection_enabled() {
        return isset($this->settings['protection_enabled']) ? (bool) $this->settings['protection_enabled'] : true;
    }
    
    /**
     * Get token expiration time in seconds
     */
    public function get_token_expiration() {
        return isset($this->settings['token_expiration']) ? (int) $this->settings['token_expiration'] : self::TOKEN_EXPIRATION;
    }
    
    /**
     * Check if logging is enabled
     */
    public function is_logging_enabled() {
        return isset($this->settings['enable_logging']) ? (bool) $this->settings['enable_logging'] : false;
    }
    
    /**
     * Check if IP lock is enabled
     */
    public function is_ip_lock_enabled() {
        return isset($this->settings['ip_lock']) ? (bool) $this->settings['ip_lock'] : false;
    }
    
    /**
     * Check if debug mode is enabled
     */
    public function is_debug_mode_enabled() {
        return isset($this->settings['debug_mode']) ? (bool) $this->settings['debug_mode'] : false;
    }
    
    /**
     * Initialize integrations with form builders
     */
    private function initialize_integrations() {
        // Include integrations class
        require_once SECURE_FILE_SESSION_PLUGIN_DIR . 'includes/class-secure-file-session-integrations.php';
        
        // Initialize integrations
        $this->integrations = new Secure_File_Session_Integrations($this);
    }
    
    /**
     * Initialize remote storage
     */
    private function initialize_remote_storage() {
        // Skip if remote storage is not enabled
        if (empty($this->settings['remote_storage_enabled'])) {
            return;
        }
        
        // Include remote storage class
        require_once SECURE_FILE_SESSION_PLUGIN_DIR . 'includes/class-secure-file-session-remote-storage.php';
        
        // Initialize remote storage
        $this->remote_storage = new Secure_File_Session_Remote_Storage($this->settings);
        
        // Schedule cache cleanup
        if (!wp_next_scheduled('sfs_cleanup_remote_cache')) {
            wp_schedule_event(time(), 'daily', 'sfs_cleanup_remote_cache');
        }
        
        // Register cleanup hook
        add_action('sfs_cleanup_remote_cache', array($this, 'cleanup_remote_cache'));
    }
    
    /**
     * Clean up remote storage cache
     */
    public function cleanup_remote_cache() {
        if ($this->remote_storage) {
            $this->remote_storage->cleanup_cache();
        }
    }
    
    /**
     * Check if remote storage is enabled and configured
     */
    public function is_remote_storage_enabled() {
        return $this->remote_storage && $this->remote_storage->is_enabled();
    }
    
    /**
     * Get remote storage instance
     */
    public function get_remote_storage() {
        return $this->remote_storage;
    }
    
    /**
     * Initialize admin functionality
     */
    public function initialize_admin() {
        // Include admin class
        require_once SECURE_FILE_SESSION_PLUGIN_DIR . 'includes/class-secure-file-session-admin.php';
        
        // Initialize admin
        $this->admin = new Secure_File_Session_Admin();
        $this->admin->init();
    }
    
    /**
     * Start a session if not already started
     */
    private function maybe_start_session() {
        if (!session_id() && !headers_sent()) {
            session_start();
        }
    }
    
    /**
     * Add rewrite rules for secure file access
     */
    public function add_rewrite_rules() {
        // We are using direct access approach, so no need for complex rewrite rules
        // Just make sure rules are flushed if the flag is set
        if (get_option('sfs_flush_rewrite_rules', false)) {
            flush_rewrite_rules();
            update_option('sfs_flush_rewrite_rules', false);
        }
    }
    
    /**
     * Register query vars for secure file access
     */
    public function register_query_vars($vars) {
        // Register these just in case, but we're not using them with direct access
        $vars[] = 'secure_file';
        $vars[] = 'file';
        $vars[] = 'token';
        return $vars;
    }
    
    /**
     * Register the secure file endpoint directly
     */
    public function register_secure_endpoint() {
        global $wp;
        $wp->add_query_var('secure_file');
        $wp->add_query_var('file');
        $wp->add_query_var('token');
    }
    
    /**
     * Try to capture secure file requests directly from the parse_request
     */
    public function parse_secure_file_request($wp) {
        // We're using direct access, so this function is not needed
        return;
    }
    
    /**
     * Handle secure file requests
     */
    public function handle_secure_file_request() {
        // We're using direct access, so this function is not needed
        return;
    }
    
    /**
     * Generate a secure token for file access
     */
    private function generate_token($file) {
        // Get token expiration time from settings
        $token_expiration = $this->get_token_expiration();
        
        // Create token data
        $token_data = array(
            'file' => $file,
            'user_id' => get_current_user_id(),
            'user_ip' => $_SERVER['REMOTE_ADDR'],
            'session_id' => session_id(),
            'expiration' => time() + $token_expiration,
            'generated' => time()
        );
        
        // Generate a unique token based on the file and current time
        $token = md5($file . get_current_user_id() . $_SERVER['REMOTE_ADDR'] . time() . wp_rand());
        
        // Store token data in transient with expiration
        set_transient('sfs_token_' . $token, $token_data, $token_expiration + 60); // Add a small buffer
        
        // Log token generation if logging is enabled
        if ($this->is_logging_enabled()) {
            $this->log_event('token_generated', array(
                'token' => $token,
                'file' => $file,
                'user_id' => get_current_user_id(),
                'expiration' => $token_expiration
            ));
        }
        
        return $token;
    }
    
    /**
     * Verify a token against the stored token data
     *
     * @param string $file The encoded file
     * @param string $token The token to verify
     * @return bool Whether the token is valid
     */
    private function verify_token($file, $token) {
        // Get token data from transient
        $token_data = get_transient('sfs_token_' . $token);
        
        // Verify token exists
        if (!$token_data) {
            $this->log_failed_verification($token, $file, 'Token not found or expired');
            return false;
        }
        
        // Verify file matches
        if ($token_data['file'] !== $file) {
            $this->log_failed_verification($token, $file, 'File mismatch');
            return false;
        }
        
        // Verify expiration
        if ($token_data['expiration'] < time()) {
            $this->log_failed_verification($token, $file, 'Token expired');
            return false;
        }
        
        // Verify IP address if IP lock is enabled
        if ($this->is_ip_lock_enabled() && $token_data['user_ip'] !== $_SERVER['REMOTE_ADDR']) {
            // Check if the IP has changed but is still in the same range (for dynamic IPs)
            $original_ip_parts = explode('.', $token_data['user_ip']);
            $current_ip_parts = explode('.', $_SERVER['REMOTE_ADDR']);
            
            // If the first three segments match, consider it the same network
            $same_network = (count($original_ip_parts) === 4 && count($current_ip_parts) === 4 &&
                            $original_ip_parts[0] === $current_ip_parts[0] &&
                            $original_ip_parts[1] === $current_ip_parts[1] &&
                            $original_ip_parts[2] === $current_ip_parts[2]);
            
            // If not in the same network, deny access
            if (!$same_network) {
                $this->log_failed_verification($token, $file, 'IP address mismatch');
                return false;
            }
        }
        
        // Renew token to extend access if token is more than halfway expired
        $token_age = time() - ($token_data['expiration'] - $this->get_token_expiration());
        $token_halfway = $this->get_token_expiration() / 2;
        
        if ($token_age > $token_halfway) {
            // Update expiration time
            $token_data['expiration'] = time() + $this->get_token_expiration();
            set_transient('sfs_token_' . $token, $token_data, $this->get_token_expiration() + 60);
            
            if ($this->is_logging_enabled()) {
                $this->log_event('token_renewed', array(
                    'token' => $token,
                    'file' => $file,
                    'new_expiration' => $token_data['expiration']
                ));
            }
        }
        
        return true;
    }
    
    /**
     * Log a token verification failure
     */
    private function log_failed_verification($token, $file, $reason) {
        if ($this->is_logging_enabled()) {
            $this->log_event('token_verification_failed', array(
                'token' => $token,
                'file' => $file,
                'reason' => $reason
            ));
        }
    }
    
    /**
     * Log file access attempts
     */
    private function log_file_access($file_path, $status, $reason = '') {
        if (!$this->is_logging_enabled()) {
            return;
        }
        
        $log_data = array(
            'file' => $file_path,
            'status' => $status,
            'user_ip' => $_SERVER['REMOTE_ADDR'],
            'timestamp' => current_time('mysql'),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
            'referer' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
            'request_uri' => isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '',
        );
        
        if (!empty($reason)) {
            $log_data['reason'] = $reason;
        }
        
        // Include debug info for excluded pages if debug mode is enabled
        if ($this->is_debug_mode_enabled()) {
            $log_data['is_excluded_page'] = $this->is_excluded_page() ? 'yes' : 'no';
            $log_data['excluded_pages'] = isset($this->settings['excluded_pages']) ? $this->settings['excluded_pages'] : '';
        }
        
        $this->log_event('file_access', $log_data);
    }
    
    /**
     * Log an event to the database
     */
    private function log_event($event_type, $event_data) {
        if (!$this->is_logging_enabled()) {
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
     * Get file path from encoded file parameter
     */
    private function get_file_path_from_encoded_file($encoded_file) {
        $relative_path = base64_decode($encoded_file);
        
        // Security: Make sure the path doesn't try to access files outside the uploads directory
        $uploads_path = $this->upload_dir['basedir'];
        $file_path = path_join($uploads_path, $relative_path);
        
        // Validate the path is within uploads directory
        $real_uploads_path = realpath($uploads_path);
        $real_file_path = realpath($file_path);
        
        if ($real_file_path === false || strpos($real_file_path, $real_uploads_path) !== 0) {
            $this->deny_access('Invalid file path');
        }
        
        return $file_path;
    }
    
    /**
     * Replace file URLs in content with secure URLs
     * 
     * @param string $content The content to process
     * @return string The processed content with secure URLs
     */
    public function replace_file_urls($content) {
        // Skip if empty or not string
        if (empty($content) || !is_string($content)) {
            return $content;
        }
        
        // Skip if protection is disabled
        if (empty($this->settings['protection_enabled'])) {
            return $content;
        }
        
        // Skip if this is an excluded page
        if ($this->is_excluded_page()) {
            return $content;
        }
        
        // Get excluded file pattern
        $excluded_pattern = $this->get_excluded_files_pattern();
        
        // Regular expression to find URLs in various HTML attributes
        // Include more attributes that might contain URLs
        $pattern = '/(src|href|data-src|data-bg|data-background|data-image|data-srcset|data-lazysrc|data-lazy-src|data-original|data-source|poster)\s*=\s*(["\'])(.*?)\2/i';
        
        // Replace callback function
        $replaced_content = preg_replace_callback($pattern, function($matches) use ($excluded_pattern) {
            $attr = $matches[1];
            $quote = $matches[2];
            $url = $matches[3];
            
            // Skip if empty URL
            if (empty($url)) {
                return $attr . '=' . $quote . $url . $quote;
            }
            
            // Skip if URL doesn't start with upload URL or is a data URL
            if (strpos($url, $this->upload_url) !== 0 || strpos($url, 'data:') === 0) {
                return $attr . '=' . $quote . $url . $quote;
            }
            
            // Get the file path from the URL
            $file_path = str_replace($this->upload_url, '', $url);
            $file_path = ltrim($file_path, '/');
            
            // Skip SVG and ICO files by default unless specifically configured
            $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
            if (!empty($this->settings['protect_svg_icons'])) {
                // Protection enabled for all file types
            } elseif (in_array($extension, ['svg', 'ico'])) {
                return $attr . '=' . $quote . $url . $quote;
            }
            
            // Skip excluded files
            if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
                return $attr . '=' . $quote . $url . $quote;
            }
            
            // Check if the file has explicit metadata for security status
            $attachment_id = $this->get_attachment_id_from_url($url);
            if ($attachment_id) {
                $is_exempted = get_post_meta($attachment_id, '_sfs_exempted', true);
                if ($is_exempted) {
                    return $attr . '=' . $quote . $url . $quote; // Return original URL if explicitly exempted
                }
            }
            
            // Get the secure URL
            $secure_url = $this->get_secure_url($file_path);
            
            // Return the modified attribute with secure URL
            return $attr . '=' . $quote . $secure_url . $quote;
        }, $content);
        
        // Also check for background-image and other CSS properties in style attributes
        $bg_pattern = '/style\s*=\s*(["\'])(.*?background(-image)?\s*:\s*url\s*\([\'"]?(.*?)[\'"]?\).*?)\1/i';
        
        $replaced_content = preg_replace_callback($bg_pattern, function($matches) use ($excluded_pattern) {
            $quote = $matches[1];
            $style = $matches[2];
            $url = $matches[4];
            
            // Skip if empty URL or not from uploads dir
            if (empty($url) || strpos($url, $this->upload_url) !== 0) {
                return 'style=' . $quote . $style . $quote;
            }
            
            // Get the file path from the URL
            $file_path = str_replace($this->upload_url, '', $url);
            $file_path = ltrim($file_path, '/');
            
            // Skip SVG and ICO files by default
            $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
            if (!empty($this->settings['protect_svg_icons'])) {
                // Protection enabled for all file types
            } elseif (in_array($extension, ['svg', 'ico'])) {
                return 'style=' . $quote . $style . $quote;
            }
            
            // Skip excluded files
            if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
                return 'style=' . $quote . $style . $quote;
            }
            
            // Get the secure URL
            $secure_url = $this->get_secure_url($file_path);
            
            // Replace the URL in the style attribute
            $new_style = str_replace($url, $secure_url, $style);
            
            return 'style=' . $quote . $new_style . $quote;
        }, $replaced_content);
        
        // Also handle <source> tags (for audio/video and picture elements)
        $source_pattern = '/<source[^>]*\s+srcset\s*=\s*(["\'])(.*?)\1[^>]*>/i';
        
        $replaced_content = preg_replace_callback($source_pattern, function($matches) use ($excluded_pattern) {
            $tag = $matches[0];
            $quote = $matches[1];
            $srcset = $matches[2];
            
            // Skip if empty srcset
            if (empty($srcset)) {
                return $tag;
            }
            
            // Process each URL in the srcset
            $urls = explode(',', $srcset);
            $new_urls = array();
            
            foreach ($urls as $url_item) {
                $url_parts = preg_split('/\s+/', trim($url_item), 2);
                $url = $url_parts[0];
                $descriptor = isset($url_parts[1]) ? ' ' . $url_parts[1] : '';
                
                // Skip if not from uploads dir
                if (strpos($url, $this->upload_url) !== 0) {
                    $new_urls[] = $url . $descriptor;
                    continue;
                }
                
                // Get the file path from the URL
                $file_path = str_replace($this->upload_url, '', $url);
                $file_path = ltrim($file_path, '/');
                
                // Skip SVG and ICO files by default
                $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                if (!empty($this->settings['protect_svg_icons'])) {
                    // Protection enabled for all file types
                } elseif (in_array($extension, ['svg', 'ico'])) {
                    $new_urls[] = $url . $descriptor;
                    continue;
                }
                
                // Skip excluded files
                if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
                    $new_urls[] = $url . $descriptor;
                    continue;
                }
                
                // Get the secure URL
                $secure_url = $this->get_secure_url($file_path);
                
                $new_urls[] = $secure_url . $descriptor;
            }
            
            // Replace the srcset in the tag
            $new_srcset = implode(', ', $new_urls);
            $new_tag = str_replace('srcset=' . $quote . $srcset . $quote, 'srcset=' . $quote . $new_srcset . $quote, $tag);
            
            return $new_tag;
        }, $replaced_content);
        
        return $replaced_content;
    }
    
    /**
     * Check if current page is in the excluded list
     */
    public function is_excluded_page() {
        // Get excluded pages from settings
        $excluded_pages = isset($this->settings['excluded_pages']) ? $this->settings['excluded_pages'] : '';
        
        if (empty($excluded_pages)) {
            return false;
        }
        
        // Get current URL path
        $current_path = $_SERVER['REQUEST_URI'];
        
        // Split excluded pages by newline
        $excluded_paths = explode("\n", $excluded_pages);
        
        foreach ($excluded_paths as $path) {
            $path = trim($path);
            if (empty($path)) {
                continue;
            }
            
            // Check for wildcard matches
            if (substr($path, -1) === '*') {
                $path_prefix = rtrim(substr($path, 0, -1), '/');
                if (strpos($current_path, $path_prefix) === 0) {
                    return true;
                }
            } 
            // Exact path match
            elseif ($path === $current_path) {
                return true;
            }
            // Path segment match (e.g. /login/ matches /login/ or /wp-login/)
            elseif (strpos($current_path, $path) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Get file size for a secure URL
     */
    public function get_file_size($file_path) {
        // Get actual file path from the uploads directory
        if (!is_array($this->upload_dir)) {
            // Handle the case when upload_dir is not an array
            $uploads_info = wp_upload_dir();
            $uploads_path = $uploads_info['basedir'];
        } else {
            $uploads_path = $this->upload_dir['basedir'];
        }
        
        $full_path = path_join($uploads_path, $file_path);
        
        if (file_exists($full_path)) {
            $size = filesize($full_path);
            return $this->format_file_size($size);
        }
        
        return '(File)';
    }
    
    /**
     * Format file size for display
     */
    private function format_file_size($bytes) {
        if ($bytes === 0) {
            return '0 Bytes';
        }
        
        $k = 1024;
        $sizes = array('Bytes', 'KB', 'MB', 'GB');
        $i = floor(log($bytes) / log($k));
        
        return sprintf("%.1f", $bytes / pow($k, $i)) . ' ' . $sizes[$i];
    }
    
    /**
     * Create a secure URL for a file
     */
    public function get_secure_url($file_path) {
        // Ensure we're working with a valid file path
        $file_path = trim($file_path, '/');
        
        // If we're dealing with a URL rather than a path, convert it
        if (strpos($file_path, 'http') === 0) {
            $file_path = str_replace($this->upload_url, '', $file_path);
            $file_path = trim($file_path, '/');
            
            // Log this issue for debugging
            error_log('SecureFileSession: Converting URL to relative path: ' . $file_path);
        }
        
        // Check for SVG and ICO files - these are exempted from security by default
        $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        if (!empty($this->settings['protect_svg_icons'])) {
            // Protection is enabled for SVG/ICO, they should be secured
        } elseif (in_array($extension, ['svg', 'ico'])) {
            return $this->upload_url . '/' . $file_path; // Return original URL
        }
        
        // Get file size for data attributes (useful for displaying file size in links)
        $file_size = $this->get_file_size($file_path);
        
        // Encode file path
        $encoded_file = base64_encode($file_path);
        
        // Generate token with expiration based on settings
        $token = $this->generate_token($encoded_file);
        
        // Use direct access method (via plugin root file)
        $plugin_url = plugins_url('secure-file-session.php', dirname(__FILE__));
        
        // Make sure it's a full URL
        if (strpos($plugin_url, 'http') !== 0) {
            $plugin_url = site_url($plugin_url);
        }
        
        // Create the secure URL with all necessary parameters
        $secure_url = $plugin_url . 
                      '?sfs_file=' . urlencode($encoded_file) . 
                      '&sfs_token=' . urlencode($token) . 
                      '&sfs_size=' . urlencode($file_size);
        
        return $secure_url;
    }
    
    /**
     * Secure attachment URL from wp_get_attachment_url
     * 
     * @param string $url The attachment URL
     * @return string The secured URL if it's from uploads directory
     */
    public function secure_attachment_url($url) {
        // Skip if excluded page
        if ($this->is_excluded_page()) {
            return $url;
        }
        
        // Skip if protection is disabled
        if (empty($this->settings['protection_enabled'])) {
            return $url;
        }
        
        // Skip if URL is empty or not a string
        if (empty($url) || !is_string($url)) {
            return $url;
        }
        
        // Skip if URL doesn't start with upload URL
        if (strpos($url, $this->upload_url) !== 0) {
            return $url;
        }
        
        // Get the file path from the URL
        $file_path = str_replace($this->upload_url, '', $url);
        $file_path = ltrim($file_path, '/');
        
        // Get file extension
        $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        
        // Skip SVG and ICO files unless protection is enabled for them
        if (!empty($this->settings['protect_svg_icons'])) {
            // Protection enabled for all file types
        } elseif (in_array($extension, ['svg', 'ico'])) {
            return $url;
        }
        
        // Check excluded pattern
        $excluded_pattern = $this->get_excluded_files_pattern();
        if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
            return $url;
        }
        
        // Get attachment ID
        $attachment_id = attachment_url_to_postid($url);
        
        // Check if the file is exempted
        if ($attachment_id) {
            $is_exempted = get_post_meta($attachment_id, '_sfs_exempted', true);
            if ($is_exempted) {
                return $url;
            }
        }
        
        // ALWAYS return secure URL for non-exempted files
        return $this->get_secure_url($file_path);
    }
    
    /**
     * Exclude theme files from being secured
     */
    public function exclude_theme_files($excluded_files) {
        // Exclude anything within theme or plugin directories (using regex ^)
        $excluded_files[] = '^wp-content/themes/'; 
        $excluded_files[] = '^wp-content/plugins/'; // Add plugins explicitly

        // Exclude common UI image/icon file extensions (match end of string $)
        // Use single backslash for literal dot, $ for end of string. preg_quote will handle escaping.
        // $excluded_files[] = '\.png$'; // REMOVE Image types - should be secured if in uploads
        // $excluded_files[] = '\.jpg$';
        // $excluded_files[] = '\.jpeg$';
        // $excluded_files[] = '\.gif$';
        // $excluded_files[] = '\.webp$';
        $excluded_files[] = '\.svg$'; // KEEP SVG
        $excluded_files[] = '\.ico$'; // KEEP ICO
        
        // Remove less reliable generic word matches 
        // $excluded_files[] = 'logo'; 
        // $excluded_files[] = 'header';
        // $excluded_files[] = 'footer';
        // $excluded_files[] = 'background';
        // $excluded_files[] = 'banner';
        
        return $excluded_files;
    }
    
    /**
     * Get regex pattern for excluded files
     */
    public function get_excluded_files_pattern() {
        $excluded_files = apply_filters('secure_file_session_excluded_files', array());
        
        if (empty($excluded_files)) {
            return false;
        }
        
        // Ensure the regex delimiter '/' is escaped in the pattern items
        return '/(' . implode('|', array_map(function($s) { return preg_quote($s, '/'); }, $excluded_files)) . ')/i';
    }
    
    /**
     * Serve a file to the browser
     */
    private function serve_file($file_path) {
        // Get file information
        $file_name = basename($file_path);
        $file_size = filesize($file_path);
        $file_mime = $this->get_mime_type($file_path);
        
        // Log successful file access
        $this->log_file_access($file_path, 'success');
        
        // Clean any previous output
        if (ob_get_level()) {
            ob_end_clean();
        }
        
        // Set headers for file download
        nocache_headers();
        header('Content-Type: ' . $file_mime);
        header('Content-Disposition: attachment; filename="' . $file_name . '"');
        header('Content-Length: ' . $file_size);
        header('Connection: close');
        
        // Output file contents
        readfile($file_path);
        exit;
    }
    
    /**
     * Get MIME type for a file
     */
    private function get_mime_type($file) {
        $mime_types = array(
            'pdf' => 'application/pdf',
            'jpg' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'png' => 'image/png',
            'gif' => 'image/gif',
            'svg' => 'image/svg+xml',
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
        );
        
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        
        if (array_key_exists($ext, $mime_types)) {
            return $mime_types[$ext];
        }
        
        // Default to octet-stream
        return 'application/octet-stream';
    }
    
    /**
     * Replace links text with original filenames
     * 
     * This function is added to the init hook to run after DOM is loaded
     */
    public function replace_link_text_with_filename() {
        // Add styles for secure file links
        add_action('wp_head', function() {
            // Get settings
            $settings = $this->settings;
            $disable_styling_in_tables = !empty($settings['disable_styling_in_tables']);
            $protect_svg_icons = !empty($settings['protect_svg_icons']);
            ?>
            <style type="text/css">
            /* Style for secure file links - with more specific selectors to avoid conflicts */
            a[href*="secure-file-session.php"] {
                display: inline-flex;
                align-items: center;
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 6px 12px;
                margin: 4px 2px;
                color: #495057;
                text-decoration: none;
                font-size: 14px;
                font-weight: normal;
                transition: all 0.2s ease;
            }
            
            a[href*="secure-file-session.php"]:hover {
                background-color: #e9ecef;
                color: #212529;
                text-decoration: none;
            }
            
            <?php if ($protect_svg_icons) : ?>
            /* Prevent styles from affecting SVG icons */
            a:not([href*="secure-file-session.php"]) svg,
            a:not([href*="secure-file-session.php"]) svg *,
            svg:not(a[href*="secure-file-session.php"] svg),
            svg:not(a[href*="secure-file-session.php"] svg) * {
                fill: inherit;
                color: inherit;
                background-color: inherit;
                border: inherit;
                box-shadow: inherit;
                margin: initial;
                padding: initial;
            }
            <?php endif; ?>
            
            /* Disable styling for links in tables if the option is enabled */
            <?php if ($disable_styling_in_tables) : ?>
            table a[href*="secure-file-session.php"],
            .jet-dynamic-table a[href*="secure-file-session.php"],
            .jet-listing-dynamic-table a[href*="secure-file-session.php"] {
                display: inline;
                background: none;
                border: none;
                padding: 0;
                margin: 0;
                color: inherit;
                font-size: inherit;
                font-weight: inherit;
            }
            
            table a[href*="secure-file-session.php"]:hover,
            .jet-dynamic-table a[href*="secure-file-session.php"]:hover,
            .jet-listing-dynamic-table a[href*="secure-file-session.php"]:hover {
                background: none;
                color: inherit;
                text-decoration: underline;
            }
            
            table a[href*="secure-file-session.php"] .sfs-ext-badge,
            table a[href*="secure-file-session.php"] .sfs-file-size,
            .jet-dynamic-table a[href*="secure-file-session.php"] .sfs-ext-badge,
            .jet-dynamic-table a[href*="secure-file-session.php"] .sfs-file-size,
            .jet-listing-dynamic-table a[href*="secure-file-session.php"] .sfs-ext-badge,
            .jet-listing-dynamic-table a[href*="secure-file-session.php"] .sfs-file-size {
                display: none !important;
            }
            <?php endif; ?>
            
            /* File extension badge styles - specifically scoped to plugin elements */
            a[href*="secure-file-session.php"] .sfs-ext-badge {
                display: inline-block;
                min-width: 28px;
                height: 28px;
                line-height: 28px;
                text-align: center;
                background-color: #6c757d;
                color: white;
                border-radius: 3px;
                margin-right: 8px;
                font-size: 11px;
                font-weight: bold;
                text-transform: uppercase;
                padding: 0 4px;
            }
            
            /* Colors for different file types */
            a[href*="secure-file-session.php"] .sfs-ext-pdf { background-color: #dc3545; }
            a[href*="secure-file-session.php"] .sfs-ext-doc, 
            a[href*="secure-file-session.php"] .sfs-ext-docx { background-color: #0d6efd; }
            a[href*="secure-file-session.php"] .sfs-ext-xls, 
            a[href*="secure-file-session.php"] .sfs-ext-xlsx { background-color: #198754; }
            a[href*="secure-file-session.php"] .sfs-ext-ppt, 
            a[href*="secure-file-session.php"] .sfs-ext-pptx { background-color: #fd7e14; }
            a[href*="secure-file-session.php"] .sfs-ext-jpg, 
            a[href*="secure-file-session.php"] .sfs-ext-jpeg, 
            a[href*="secure-file-session.php"] .sfs-ext-png, 
            a[href*="secure-file-session.php"] .sfs-ext-gif, 
            a[href*="secure-file-session.php"] .sfs-ext-svg { background-color: #6f42c1; }
            a[href*="secure-file-session.php"] .sfs-ext-zip, 
            a[href*="secure-file-session.php"] .sfs-ext-rar { background-color: #6c757d; }
            
            /* File details container */
            a[href*="secure-file-session.php"] .sfs-file-details {
                display: flex;
                flex-direction: column;
            }
            
            /* File size style */
            a[href*="secure-file-session.php"] .sfs-file-size {
                font-size: 10px;
                color: #6c757d;
                margin-top: 2px;
                font-style: italic;
            }
            </style>
            <?php
        });

        // Add script to replace link text with original filename
        add_action('wp_footer', function() {
            // Get settings
            $settings = $this->settings;
            $disable_styling_in_tables = !empty($settings['disable_styling_in_tables']);
            ?>
            <script type="text/javascript">
            document.addEventListener('DOMContentLoaded', function() {
                // Helper function to format file size
                function formatFileSize(bytes) {
                    if (bytes === 0) return '0 Bytes';
                    const k = 1024;
                    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                    const i = Math.floor(Math.log(bytes) / Math.log(k));
                    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
                }
                
                // Function to get file size
                async function getFileSize(url) {
                    try {
                        const response = await fetch(url, { 
                            method: 'HEAD',
                            cache: 'no-store',
                            headers: {
                                'Pragma': 'no-cache',
                                'Cache-Control': 'no-cache'
                            }
                        });
                        if (response.ok) {
                            const contentLength = response.headers.get('Content-Length');
                            if (contentLength) {
                                return formatFileSize(parseInt(contentLength, 10));
                            } else {
                                // Try to extract size from URL for debugging
                                try {
                                    // If Content-Length header isn't available, try a different approach
                                    // This is a fallback method that just shows a placeholder
                                    return '(File)';
                                } catch(e) {
                                    return '(File)';
                                }
                            }
                        } else {
                            return '(File)';
                        }
                    } catch (e) {
                        console.log('Error fetching file size', e);
                        return '(File)';
                    }
                }
                
                // Find all links that contain secure file URLs
                const secureLinks = document.querySelectorAll('a[href*="secure-file-session.php"]');
                
                secureLinks.forEach(function(link) {
                    // Force download attribute on all secure file links
                    link.setAttribute('download', '');
                    
                    // Skip styling if this is a link in a table and the option is enabled
                    const disableStylingInTables = <?php echo $disable_styling_in_tables ? 'true' : 'false'; ?>;
                    const isInTable = link.closest('table') !== null || 
                                     link.closest('.jet-dynamic-table') !== null ||
                                     link.closest('.jet-listing-dynamic-table') !== null;
                    
                    // Always replace the text with filename, even in tables
                    // Check if link text is the same as the href (indicating it's displaying the whole URL)
                    if (link.textContent.includes('secure-file-session.php') || 
                        link.textContent.includes('sfs_file=') ||
                        link.textContent.includes('sfs_token=')) {
                        
                        // Extract the encoded filename from the URL
                        let fileParam = '';
                        let fileSize = '';
                        const urlParams = new URLSearchParams(link.href.split('?')[1]);
                        if (urlParams.has('sfs_file')) {
                            fileParam = urlParams.get('sfs_file');
                            
                            // Check if file size is provided in URL
                            if (urlParams.has('sfs_size')) {
                                fileSize = urlParams.get('sfs_size');
                            }
                            
                            try {
                                // Decode the base64 filename
                                const decodedPath = atob(decodeURIComponent(fileParam));
                                
                                // Extract the actual filename from the path
                                const filename = decodedPath.split('/').pop();
                                
                                // If in a table and styling is disabled, just set the text and return
                                if (disableStylingInTables && isInTable) {
                                    link.textContent = filename;
                                    return;
                                }
                                
                                // Get file extension
                                const fileExt = filename.split('.').pop().toLowerCase();
                                
                                // Create file extension badge
                                const extBadge = document.createElement('span');
                                extBadge.className = 'sfs-ext-badge sfs-ext-' + fileExt;
                                extBadge.textContent = fileExt;
                                
                                // Create file details container
                                const fileDetails = document.createElement('div');
                                fileDetails.className = 'sfs-file-details';
                                
                                // Create filename element
                                const filenameElement = document.createElement('span');
                                filenameElement.textContent = filename;
                                
                                // Create file size element
                                const fileSizeElement = document.createElement('span');
                                fileSizeElement.className = 'sfs-file-size';
                                
                                // Use server-provided size if available, otherwise fetch dynamically
                                if (fileSize) {
                                    fileSizeElement.textContent = decodeURIComponent(fileSize);
                                } else {
                                    fileSizeElement.textContent = 'Fetching size...';
                                    
                                    // Fetch and update file size asynchronously
                                    getFileSize(link.href).then(size => {
                                        if (size) {
                                            fileSizeElement.textContent = size;
                                        } else {
                                            fileSizeElement.textContent = '(File)';
                                        }
                                    });
                                }
                                
                                // Add filename and file size to details container
                                fileDetails.appendChild(filenameElement);
                                fileDetails.appendChild(fileSizeElement);
                                
                                // Clear link content
                                link.textContent = '';
                                
                                // Add badge and file details
                                link.appendChild(extBadge);
                                link.appendChild(fileDetails);
                            } catch(e) {
                                // If decoding fails, keep the original text
                                console.log('Error decoding filename', e);
                            }
                        }
                    }
                });
            });
            </script>
            <?php
        }, 999);
    }
    
    /**
     * Check if the current user can access a specific file type
     * based on role permissions in settings
     *
     * @param string $file_path Path to the file
     * @return bool Whether the user can access the file
     */
    public function user_can_access_file_type($file_path) {
        // If user is not logged in, deny access
        if (!is_user_logged_in()) {
            return false;
        }
        
        // Admins can access everything
        if (current_user_can('manage_options')) {
            return true;
        }
        
        // Get user's roles
        $user = wp_get_current_user();
        $user_roles = (array) $user->roles;
        
        // Get file extension and determine permission type
        $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        $permission_type = $this->get_permission_type_for_extension($extension);
        
        // If no specific permission type, allow access (this can be customized)
        if (empty($permission_type)) {
            return true;
        }
        
        // Get role permissions from settings
        $role_permissions = isset($this->settings['role_permissions']) ? $this->settings['role_permissions'] : [];
        
        // If no permissions are set for this type, allow access
        if (empty($role_permissions[$permission_type])) {
            return true;
        }
        
        // Check if any of the user's roles are allowed
        foreach ($user_roles as $role) {
            if (in_array($role, $role_permissions[$permission_type])) {
                return true;
            }
        }
        
        // Log access denial if logging is enabled
        if ($this->is_logging_enabled()) {
            $this->log_event('role_permission_denied', array(
                'file_path' => $file_path,
                'user_id' => get_current_user_id(),
                'user_roles' => implode(', ', $user_roles),
                'permission_type' => $permission_type,
                'allowed_roles' => implode(', ', $role_permissions[$permission_type])
            ));
        }
        
        return false;
    }
    
    /**
     * Determine permission type based on file extension
     *
     * @param string $extension File extension
     * @return string|null Permission type key or null if not found
     */
    private function get_permission_type_for_extension($extension) {
        // Extension to permission type mapping
        $type_mapping = array(
            'pdf' => 'pdf',
            'doc' => 'doc', 'docx' => 'doc',
            'xls' => 'xls', 'xlsx' => 'xls',
            'ppt' => 'ppt', 'pptx' => 'ppt',
            'zip' => 'zip', 'rar' => 'zip',
            'jpg' => 'image', 'jpeg' => 'image', 'png' => 'image', 'gif' => 'image', 'webp' => 'image',
            'svg' => 'svg',
            'mp3' => 'audio', 'wav' => 'audio',
            'mp4' => 'video', 'mov' => 'video', 'avi' => 'video'
        );
        
        return isset($type_mapping[$extension]) ? $type_mapping[$extension] : null;
    }
    
    /**
     * Clean up a watermarked file
     */
    public function cleanup_watermarked_file($file_path) {
        if (file_exists($file_path)) {
            @unlink($file_path);
        }
    }
    
    /**
     * Get watermarking instance
     */
    public function get_watermarking() {
        // Load watermarking class if not already loaded
        if (!class_exists('Secure_File_Session_Watermark')) {
            require_once SECURE_FILE_SESSION_PLUGIN_DIR . 'includes/class-secure-file-session-watermark.php';
        }
        
        // Create and return watermarking instance
        return new Secure_File_Session_Watermark($this->settings);
    }
    
    /**
     * Add IP whitelist checkbox to attachment edit screen
     */
    public function add_ip_whitelist_field($fields, $post) {
        // Only show if IP whitelisting is enabled in settings
        if (empty($this->settings['ip_whitelist_enabled'])) {
            return $fields;
        }
        
        // Get current value
        $requires_whitelist = get_post_meta($post->ID, '_sfs_requires_whitelist', true);
        
        // Add custom field
        $fields['sfs_requires_whitelist'] = array(
            'label' => __('IP Whitelist Protection', 'secure-file-session'),
            'input' => 'html',
            'html' => '<label><input type="checkbox" name="attachments[' . $post->ID . '][sfs_requires_whitelist]" value="1" ' . checked($requires_whitelist, 1, false) . ' /> ' . 
                      __('Require IP whitelist for this file', 'secure-file-session') . '</label>',
            'helps' => __('If checked, this file will only be accessible from whitelisted IP addresses.', 'secure-file-session')
        );
        
        return $fields;
    }
    
    /**
     * Save IP whitelist field
     */
    public function save_ip_whitelist_field($post, $attachment) {
        if (isset($attachment['sfs_requires_whitelist'])) {
            update_post_meta($post['ID'], '_sfs_requires_whitelist', 1);
        } else {
            delete_post_meta($post['ID'], '_sfs_requires_whitelist');
        }
        
        return $post;
    }
    
    /**
     * Validate file upload
     * Performs security checks on files being uploaded
     * 
     * @param array $file The file being uploaded
     * @return array The file array, potentially with an error message
     */
    public function validate_file_upload($file) {
        // Skip validation if the feature is disabled
        if (empty($this->settings['file_validation_enabled'])) {
            return $file;
        }
        
        // Get file extension
        $filename = $file['name'];
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        
        // Check against disallowed extensions list
        $disallowed = !empty($this->settings['disallowed_extensions']) ? 
            array_map('trim', explode(',', strtolower($this->settings['disallowed_extensions']))) : 
            array();
            
        if (in_array($ext, $disallowed)) {
            $file['error'] = sprintf(__('File type not allowed. The extension "%s" is not permitted for security reasons.', 'secure-file-session'), $ext);
            
            // Log the attempt if logging is enabled
            if ($this->is_logging_enabled()) {
                $this->log_event('file_upload_blocked', array(
                    'filename' => $filename,
                    'extension' => $ext,
                    'reason' => 'disallowed_extension',
                    'user_id' => get_current_user_id()
                ));
            }
            
            return $file;
        }
        
        // Check against allowed extensions list
        $allowed = !empty($this->settings['allowed_file_types']) ? 
            array_map('trim', explode(',', strtolower($this->settings['allowed_file_types']))) : 
            array();
            
        if (!empty($allowed) && !in_array($ext, $allowed)) {
            $file['error'] = sprintf(__('File type not allowed. The extension "%s" is not in the list of permitted file types.', 'secure-file-session'), $ext);
            
            // Log the attempt if logging is enabled
            if ($this->is_logging_enabled()) {
                $this->log_event('file_upload_blocked', array(
                    'filename' => $filename,
                    'extension' => $ext,
                    'reason' => 'not_in_allowed_list',
                    'user_id' => get_current_user_id()
                ));
            }
            
            return $file;
        }
        
        // Check file content for malicious code if enabled
        if (!empty($this->settings['scan_file_contents'])) {
            $scan_result = $this->scan_file_contents($file['tmp_name']);
            if ($scan_result !== true) {
                $file['error'] = sprintf(__('File content rejected. Potential security threat detected: %s', 'secure-file-session'), $scan_result);
                
                // Log the attempt if logging is enabled
                if ($this->is_logging_enabled()) {
                    $this->log_event('file_upload_blocked', array(
                        'filename' => $filename,
                        'extension' => $ext,
                        'reason' => 'malicious_content',
                        'signature' => $scan_result,
                        'user_id' => get_current_user_id()
                    ));
                }
                
                return $file;
            }
        }
        
        // Perform double extension check (e.g., file.php.jpg)
        $filename_parts = explode('.', $filename);
        if (count($filename_parts) > 2) {
            // Check if any part of the filename matches disallowed extensions
            foreach ($filename_parts as $part) {
                $part = strtolower(trim($part));
                if (in_array($part, $disallowed)) {
                    $file['error'] = sprintf(__('File name contains a disallowed extension segment: "%s"', 'secure-file-session'), $part);
                    
                    // Log the attempt if logging is enabled
                    if ($this->is_logging_enabled()) {
                        $this->log_event('file_upload_blocked', array(
                            'filename' => $filename,
                            'extension' => $ext,
                            'reason' => 'multi_extension',
                            'suspicious_part' => $part,
                            'user_id' => get_current_user_id()
                        ));
                    }
                    
                    return $file;
                }
            }
        }
        
        // No issues found, file is validated
        return $file;
    }
    
    /**
     * Filter MIME types that are allowed for upload
     * 
     * @param array $mimes The list of allowed MIME types
     * @return array The filtered list of MIME types
     */
    public function filter_upload_mimes($mimes) {
        // Skip filtering if the feature is disabled
        if (empty($this->settings['file_validation_enabled'])) {
            return $mimes;
        }
        
        // Get allowed extensions
        $allowed = !empty($this->settings['allowed_file_types']) ? 
            array_map('trim', explode(',', strtolower($this->settings['allowed_file_types']))) : 
            array();
            
        // If allowed list is empty, return all mimes
        if (empty($allowed)) {
            return $mimes;
        }
        
        // Filter the MIME types based on allowed extensions
        $filtered_mimes = array();
        foreach ($mimes as $ext => $mime) {
            // Handle multi-extension keys like 'jpg|jpeg|jpe'
            $extensions = explode('|', $ext);
            foreach ($extensions as $extension) {
                if (in_array(strtolower($extension), $allowed)) {
                    $filtered_mimes[$ext] = $mime;
                    break;
                }
            }
        }
        
        return $filtered_mimes;
    }
    
    /**
     * Scan file contents for malicious signatures
     * 
     * @param string $file_path Path to the temporary uploaded file
     * @return bool|string True if safe, or string containing the matched signature
     */
    private function scan_file_contents($file_path) {
        // Get malicious signatures from settings
        $signatures = !empty($this->settings['file_content_signatures']) ? 
            array_map('trim', explode(',', $this->settings['file_content_signatures'])) : 
            array();
            
        if (empty($signatures)) {
            return true; // No signatures to check
        }
        
        // Don't try to scan very large files
        $filesize = filesize($file_path);
        if ($filesize > 10 * 1024 * 1024) { // 10MB max
            return true; // Skip large files
        }
        
        // Get file content
        $content = @file_get_contents($file_path);
        if ($content === false) {
            return true; // Can't read file, assume it's safe
        }
        
        // Check content against each signature
        foreach ($signatures as $signature) {
            if (empty($signature)) {
                continue;
            }
            
            if (stripos($content, $signature) !== false) {
                return $signature; // Return the found signature
            }
        }
        
        return true; // No malicious content found
    }
    
    /**
     * Get attachment ID from URL
     * 
     * @param string $url The attachment URL
     * @return int|false The attachment ID or false if not found
     */
    public function get_attachment_id_from_url($url) {
        // If the URL is empty, return false
        if (empty($url)) {
            return false;
        }
        
        // First, try to use the built-in WordPress function
        $attachment_id = attachment_url_to_postid($url);
        if ($attachment_id) {
            return $attachment_id;
        }
        
        // If the built-in function fails, try a custom approach
        global $wpdb;
        
        // Clean the URL
        $url = preg_replace('/\?.*/', '', $url); // Remove query string
        $url = preg_replace('/-\d+x\d+(?=\.(jpg|jpeg|png|gif)$)/i', '', $url); // Remove resolution suffix
        
        // Get uploads directory info
        $upload_dir = wp_upload_dir();
        $url_relative = str_replace($upload_dir['baseurl'] . '/', '', $url);
        
        // Try to get the attachment ID from the database
        $attachment = $wpdb->get_col($wpdb->prepare("SELECT post_id FROM $wpdb->postmeta WHERE meta_key = '_wp_attached_file' AND meta_value = %s", $url_relative));
        
        if (!empty($attachment[0])) {
            return (int) $attachment[0];
        }
        
        // If still not found, try with a more fuzzy match using LIKE
        $url_relative_pattern = '%' . $wpdb->esc_like($url_relative) . '%';
        $attachment = $wpdb->get_col($wpdb->prepare("SELECT post_id FROM $wpdb->postmeta WHERE meta_key = '_wp_attached_file' AND meta_value LIKE %s", $url_relative_pattern));
        
        if (!empty($attachment[0])) {
            return (int) $attachment[0];
        }
        
        return false;
    }
    
    /**
     * Check if an attachment should be secured based on metadata
     * 
     * @param int $attachment_id The attachment ID
     * @return bool Whether the attachment should be secured
     */
    public function should_secure_attachment($attachment_id) {
        if (!$attachment_id) {
            return false;
        }
        
        // Check if explicitly exempted
        $is_exempted = get_post_meta($attachment_id, '_sfs_exempted', true);
        if ($is_exempted) {
            return false; // Skip if explicitly exempted
        }
        
        // Check if explicitly secured
        $is_secured = get_post_meta($attachment_id, '_sfs_secured', true);
        if ($is_secured) {
            return true; // Secure if explicitly marked
        }
        
        // Check file extension for automatic exemption
        $file = get_attached_file($attachment_id);
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        
        if (in_array($ext, ['svg', 'ico'])) {
            return false; // Skip SVG and ICO files by default
        }
        
        // Check excluded pattern
        $file_url = wp_get_attachment_url($attachment_id);
        $file_path = str_replace($this->upload_url, '', $file_url);
        
        $excluded_pattern = $this->get_excluded_files_pattern();
        if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
            return false;
        }
        
        // Default to securing
        return true;
    }
    
    /**
     * Process a new attachment when uploaded
     * Automatically secure all new uploads if enabled in settings
     *
     * @param int $attachment_id The attachment ID
     */
    public function process_new_attachment($attachment_id) {
        // Skip if auto-securing uploads is disabled
        if (empty($this->settings['auto_secure_uploads'])) {
            return;
        }
        
        // Check if it's a file type that should be secured
        $file_path = get_attached_file($attachment_id);
        if (!$file_path) {
            return; // File path not found
        }
        
        $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        
        // Skip SVG and ICO files by default unless explicitly configured to secure them
        if (!empty($this->settings['protect_svg_icons'])) {
            // Protection is enabled for SVG/ICO in settings
        } elseif (in_array($extension, ['svg', 'ico'])) {
            // Mark as exempted by default
            update_post_meta($attachment_id, '_sfs_exempted', 1);
            return;
        }
        
        // Check if file extension is in the allowed list
        $allowed_types = isset($this->settings['allowed_file_types']) ? 
            explode(',', $this->settings['allowed_file_types']) : 
            array('jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'zip', 'mp3', 'mp4');
        
        // Secure this attachment by marking it in the database
        if (in_array($extension, $allowed_types)) {
            update_post_meta($attachment_id, '_sfs_secured', 1);
            
            // Log this action if logging is enabled
            if ($this->is_logging_enabled()) {
                $this->log_event('attachment_secured', array(
                    'attachment_id' => $attachment_id,
                    'file_path' => $file_path,
                    'user_id' => get_current_user_id()
                ));
            }
        }
        
        // Allow developers to perform additional actions when a file is secured
        do_action('secure_file_session_attachment_secured', $attachment_id, $file_path);
    }
    
    /**
     * Add download attribute to links
     */
    public function add_download_attribute_to_links() {
        // Add download attribute to all secure file links
        if (!is_admin()) {
            ?>
            <script type="text/javascript">
            document.addEventListener('DOMContentLoaded', function() {
                var secureLinks = document.querySelectorAll('a[href*="secure-file"]');
                secureLinks.forEach(function(link) {
                    link.setAttribute('download', '');
                });
            });
            </script>
            <?php
        }
    }
    
    /**
     * Secure image src array from wp_get_attachment_image_src
     * 
     * @param array|false $image Array of image data, or false if no image is available
     * @return array|false Modified image data with secure URL
     */
    public function secure_image_src($image) {
        if (!$image || !is_array($image) || empty($image[0])) {
            return $image;
        }
        
        // Skip if excluded page
        if ($this->is_excluded_page()) {
            return $image;
        }
        
        // Check if URL is from uploads directory
        if (strpos($image[0], $this->upload_url) === 0) {
            // Get the file path from the URL
            $file_path = str_replace($this->upload_url, '', $image[0]);
            $file_path = ltrim($file_path, '/');
            
            // Get file extension
            $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
            
            // Skip SVG and ICO files unless protection is enabled for them
            if (!empty($this->settings['protect_svg_icons'])) {
                // Protection enabled for all file types
            } elseif (in_array($extension, ['svg', 'ico'])) {
                return $image; // Return original
            }
            
            // Check excluded pattern
            $excluded_pattern = $this->get_excluded_files_pattern();
            if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
                return $image; // Return original if excluded
            }
            
            // Secure the URL
            $secure_url = $this->get_secure_url($file_path);
            
            // Replace URL in the image array
            $image[0] = $secure_url;
        }
        
        return $image;
    }
    
    /**
     * Secure image attributes for wp_get_attachment_image
     * 
     * @param array $attr Array of attribute values for the image markup
     * @return array Modified attributes with secure URLs
     */
    public function secure_image_attributes($attr) {
        if (empty($attr) || !is_array($attr)) {
            return $attr;
        }
        
        // Skip if excluded page
        if ($this->is_excluded_page()) {
            return $attr;
        }
        
        // Process src attribute
        if (!empty($attr['src']) && strpos($attr['src'], $this->upload_url) === 0) {
            $file_path = str_replace($this->upload_url, '', $attr['src']);
            $file_path = ltrim($file_path, '/');
            
            // Get file extension
            $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
            
            // Skip SVG and ICO files unless protection is enabled for them
            if (!empty($this->settings['protect_svg_icons'])) {
                // Protection enabled for all file types
            } elseif (in_array($extension, ['svg', 'ico'])) {
                return $attr; // Return original
            }
            
            // Check excluded pattern
            $excluded_pattern = $this->get_excluded_files_pattern();
            if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
                return $attr; // Return original if excluded
            }
            
            // Secure the URL
            $attr['src'] = $this->get_secure_url($file_path);
        }
        
        // Process srcset attribute
        if (!empty($attr['srcset'])) {
            $srcset_urls = explode(', ', $attr['srcset']);
            $new_srcset = array();
            
            foreach ($srcset_urls as $srcset_url) {
                $parts = preg_split('/\s+/', trim($srcset_url));
                $url = $parts[0];
                
                if (strpos($url, $this->upload_url) === 0) {
                    $file_path = str_replace($this->upload_url, '', $url);
                    $file_path = ltrim($file_path, '/');
                    
                    // Get file extension
                    $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                    
                    // Skip SVG and ICO files unless protection is enabled for them
                    if (!empty($this->settings['protect_svg_icons'])) {
                        // Protection enabled for all file types
                    } elseif (in_array($extension, ['svg', 'ico'])) {
                        $new_srcset[] = $srcset_url;
                        continue;
                    }
                    
                    // Check excluded pattern
                    $excluded_pattern = $this->get_excluded_files_pattern();
                    if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
                        $new_srcset[] = $srcset_url;
                        continue;
                    }
                    
                    // Secure the URL
                    $secure_url = $this->get_secure_url($file_path);
                    
                    // Replace in srcset
                    $parts[0] = $secure_url;
                    $new_srcset[] = implode(' ', $parts);
                } else {
                    $new_srcset[] = $srcset_url;
                }
            }
            
            $attr['srcset'] = implode(', ', $new_srcset);
        }
        
        return $attr;
    }
    
    /**
     * Secure image srcset array
     * 
     * @param array $sources Array of image source data
     * @return array Modified sources with secure URLs
     */
    public function secure_image_srcset($sources) {
        if (empty($sources) || !is_array($sources)) {
            return $sources;
        }
        
        // Skip if excluded page
        if ($this->is_excluded_page()) {
            return $sources;
        }
        
        foreach ($sources as $size => $source) {
            if (!empty($source['url']) && strpos($source['url'], $this->upload_url) === 0) {
                $file_path = str_replace($this->upload_url, '', $source['url']);
                $file_path = ltrim($file_path, '/');
                
                // Get file extension
                $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                
                // Skip SVG and ICO files unless protection is enabled for them
                if (!empty($this->settings['protect_svg_icons'])) {
                    // Protection enabled for all file types
                } elseif (in_array($extension, ['svg', 'ico'])) {
                    continue; // Keep original
                }
                
                // Check excluded pattern
                $excluded_pattern = $this->get_excluded_files_pattern();
                if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
                    continue; // Keep original if excluded
                }
                
                // Secure the URL
                $sources[$size]['url'] = $this->get_secure_url($file_path);
            }
        }
        
        return $sources;
    }
    
    /**
     * Protect uploads directory by blocking direct access
     */
    public function protect_uploads_directory() {
        // Check if we're trying to access a file in the uploads directory directly
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        
        if (empty($request_uri)) {
            return;
        }
        
        // Extract uploads path from URL
        $upload_dir = wp_upload_dir();
        $upload_url_path = wp_parse_url($upload_dir['baseurl'], PHP_URL_PATH);
        
        // Check if the request is for a file in the uploads directory
        if (strpos($request_uri, $upload_url_path) === 0) {
            // Get the file extension
            $extension = strtolower(pathinfo($request_uri, PATHINFO_EXTENSION));
            
            // Allow direct access to some file types if configured
            $allowed_direct_extensions = ['css', 'js', 'svg', 'ico'];
            
            // If we're protecting SVG icons, remove SVG from allowed direct extensions
            if (!empty($this->settings['protect_svg_icons'])) {
                $allowed_direct_extensions = array_diff($allowed_direct_extensions, ['svg']);
            }
            
            // Skip protection for allowed extensions
            if (in_array($extension, $allowed_direct_extensions)) {
                return;
            }
            
            // Check excluded pattern
            $excluded_pattern = $this->get_excluded_files_pattern();
            if ($excluded_pattern && preg_match($excluded_pattern, $request_uri)) {
                return; // Allow access if excluded
            }
            
            // Block direct access
            if (!is_user_logged_in() || !current_user_can('manage_options')) {
                // Log the direct access attempt if logging is enabled
                if ($this->is_logging_enabled()) {
                    $this->log_event('direct_access_blocked', array(
                        'request_uri' => $request_uri,
                        'user_ip' => $_SERVER['REMOTE_ADDR'],
                        'user_id' => get_current_user_id()
                    ));
                }
                
                // Redirect to login or show access denied
                if (!is_user_logged_in()) {
                    wp_redirect(wp_login_url(home_url($request_uri)));
                } else {
                    status_header(403);
                    wp_die(__('Access denied. Please use secure links to access protected files.', 'secure-file-session'), __('Access Denied', 'secure-file-session'), array('response' => 403));
                }
                exit;
            }
        }
    }
    
    /**
     * Secure file URLs in REST API attachment responses
     * 
     * @param WP_REST_Response $response The response object
     * @param WP_Post $post The attachment post
     * @param WP_REST_Request $request The request object
     * @return WP_REST_Response Modified response
     */
    public function secure_rest_attachment($response, $post, $request) {
        // Skip if excluded page
        if ($this->is_excluded_page()) {
            return $response;
        }
        
        // Get response data
        $data = $response->get_data();
        
        // Secure source URL
        if (!empty($data['source_url']) && strpos($data['source_url'], $this->upload_url) === 0) {
            $file_path = str_replace($this->upload_url, '', $data['source_url']);
            $file_path = ltrim($file_path, '/');
            
            // Get file extension
            $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
            
            // Skip SVG and ICO files unless protection is enabled for them
            if (!empty($this->settings['protect_svg_icons'])) {
                // Protection enabled for all file types
            } elseif (in_array($extension, ['svg', 'ico'])) {
                return $response; // Return original response
            }
            
            // Check excluded pattern
            $excluded_pattern = $this->get_excluded_files_pattern();
            if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
                return $response; // Return original if excluded
            }
            
            // Check if the file is exempted
            $is_exempted = get_post_meta($post->ID, '_sfs_exempted', true);
            if ($is_exempted) {
                return $response; // Return original if exempted
            }
            
            // Secure the URL
            $data['source_url'] = $this->get_secure_url($file_path);
            
            // Also secure media_details URLs if present
            if (!empty($data['media_details']) && !empty($data['media_details']['sizes'])) {
                foreach ($data['media_details']['sizes'] as $size => $size_data) {
                    if (!empty($size_data['source_url'])) {
                        $size_file_path = str_replace($this->upload_url, '', $size_data['source_url']);
                        $size_file_path = ltrim($size_file_path, '/');
                        $data['media_details']['sizes'][$size]['source_url'] = $this->get_secure_url($size_file_path);
                    }
                }
            }
            
            // Update response data
            $response->set_data($data);
        }
        
        return $response;
    }
    
    /**
     * Secure file URLs in REST API post/page responses
     * 
     * @param WP_REST_Response $response The response object
     * @param WP_Post $post The post
     * @param WP_REST_Request $request The request object
     * @return WP_REST_Response Modified response
     */
    public function secure_rest_post($response, $post, $request) {
        // Skip if excluded page
        if ($this->is_excluded_page()) {
            return $response;
        }
        
        // Get response data
        $data = $response->get_data();
        
        // Secure content
        if (!empty($data['content']) && !empty($data['content']['rendered'])) {
            $data['content']['rendered'] = $this->replace_file_urls($data['content']['rendered']);
        }
        
        // Secure excerpt
        if (!empty($data['excerpt']) && !empty($data['excerpt']['rendered'])) {
            $data['excerpt']['rendered'] = $this->replace_file_urls($data['excerpt']['rendered']);
        }
        
        // Secure featured media URL
        if (!empty($data['featured_media']) && !empty($data['_links']['wp:featuredmedia'][0]['href'])) {
            // We can't directly modify the featured media URL here,
            // but the attachment response will be secured by secure_rest_attachment
        }
        
        // Recursively secure any nested properties that might contain HTML
        $data = $this->secure_rest_data_recursive($data);
        
        // Update response data
        $response->set_data($data);
        
        return $response;
    }
    
    /**
     * Recursively process REST API data to secure URLs in any HTML content
     * 
     * @param mixed $data The data to process
     * @return mixed The processed data
     */
    private function secure_rest_data_recursive($data) {
        if (is_array($data)) {
            foreach ($data as $key => $value) {
                if (is_array($value) || is_object($value)) {
                    $data[$key] = $this->secure_rest_data_recursive($value);
                } elseif (is_string($value) && strpos($value, '<') !== false && strpos($value, '>') !== false) {
                    // This looks like HTML, try to secure URLs in it
                    $data[$key] = $this->replace_file_urls($value);
                } elseif (is_string($value) && strpos($value, $this->upload_url) === 0) {
                    // This is a direct URL to an uploads file
                    $file_path = str_replace($this->upload_url, '', $value);
                    $file_path = ltrim($file_path, '/');
                    
                    // Get file extension
                    $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                    
                    // Skip SVG and ICO files unless protection is enabled for them
                    if (!empty($this->settings['protect_svg_icons'])) {
                        // Protection enabled for all file types
                    } elseif (in_array($extension, ['svg', 'ico'])) {
                        continue; // Keep original URL
                    }
                    
                    // Check excluded pattern
                    $excluded_pattern = $this->get_excluded_files_pattern();
                    if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
                        continue; // Keep original if excluded
                    }
                    
                    // Secure the URL
                    $data[$key] = $this->get_secure_url($file_path);
                }
            }
        } elseif (is_object($data)) {
            foreach (get_object_vars($data) as $key => $value) {
                if (is_array($value) || is_object($value)) {
                    $data->$key = $this->secure_rest_data_recursive($value);
                } elseif (is_string($value) && strpos($value, '<') !== false && strpos($value, '>') !== false) {
                    // This looks like HTML, try to secure URLs in it
                    $data->$key = $this->replace_file_urls($value);
                } elseif (is_string($value) && strpos($value, $this->upload_url) === 0) {
                    // This is a direct URL to an uploads file
                    $file_path = str_replace($this->upload_url, '', $value);
                    $file_path = ltrim($file_path, '/');
                    
                    // Get file extension
                    $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                    
                    // Skip SVG and ICO files unless protection is enabled for them
                    if (!empty($this->settings['protect_svg_icons'])) {
                        // Protection enabled for all file types
                    } elseif (in_array($extension, ['svg', 'ico'])) {
                        continue; // Keep original URL
                    }
                    
                    // Check excluded pattern
                    $excluded_pattern = $this->get_excluded_files_pattern();
                    if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
                        continue; // Keep original if excluded
                    }
                    
                    // Secure the URL
                    $data->$key = $this->get_secure_url($file_path);
                }
            }
        }
        
        return $data;
    }
} 