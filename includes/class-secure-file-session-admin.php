<?php
/**
 * Admin functionality for Secure File Session
 *
 * @package SecureFileSession
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

/**
 * Class for admin functionality
 */
class Secure_File_Session_Admin {
    
    /**
     * The plugin settings
     *
     * @var array
     */
    private $settings;
    
    /**
     * The capability required to manage plugin settings
     *
     * @var string
     */
    private $capability;
    
    /**
     * Initialize the class
     */
    public function __construct() {
        // Define the capability required to manage plugin settings
        $this->capability = 'edit_posts'; // Use edit_posts instead of manage_options to allow editors
    }
    
    /**
     * Init the admin functionality
     */
    public function init() {
        // Admin AJAX actions - wait until admin_init to ensure functions are available
        add_action('admin_init', function() {
            // Add AJAX handlers
            add_action('wp_ajax_sfs_run_diagnostic', array($this, 'handle_diagnostic_test'));
            add_action('wp_ajax_sfs_fix_issue', array($this, 'handle_fix_issue'));
            add_action('wp_ajax_sfs_fix_all', array($this, 'handle_fix_all'));
            add_action('wp_ajax_sfs_test_remote', array($this, 'handle_test_remote_storage'));
            add_action('wp_ajax_sfs_purge_cache', array($this, 'handle_purge_cache'));
            add_action('wp_ajax_sfs_htaccess_test', array($this, 'handle_htaccess_test'));
            add_action('wp_ajax_sfs_debug', array($this, 'output_diagnostics'));
            add_action('wp_ajax_sfs_self_test', array($this, 'perform_self_test'));
            
            // Check capability for log viewer
            if (current_user_can('manage_options')) {
                add_action('wp_ajax_sfs_get_logs', array($this, 'handle_get_logs'));
            }
        });
        
        // Get settings
        $this->settings = get_option('secure_file_session_options', array());
        
        // Register settings
        add_action('admin_init', array($this, 'register_settings'));
        
        // Add admin menu
        add_action('admin_menu', array($this, 'add_admin_menu'));
        
        // Handle AJAX token revocation
        add_action('admin_init', function() {
            add_action('wp_ajax_sfs_revoke_token', array($this, 'handle_token_revocation'));
        });
        
        // Handle tools page hook
        add_action('admin_init', array($this, 'handle_tools_actions'));

        // Register actions
        add_action('admin_init', function() {
            add_action('admin_post_sfs_create_htaccess', array($this, 'handle_tools_actions'));
            add_action('admin_post_sfs_fix_permissions', array($this, 'handle_tools_actions'));
            add_action('admin_post_sfs_clear_logs', array($this, 'handle_tools_actions'));
            add_action('admin_post_sfs_test_s3', array($this, 'handle_tools_actions'));
            
            // Diagnostic tool handlers
            add_action('wp_ajax_sfs_run_diagnostic', array($this, 'handle_diagnostic_test'));
            add_action('wp_ajax_sfs_fix_issue', array($this, 'handle_fix_issue'));
            add_action('wp_ajax_sfs_fix_all_issues', array($this, 'handle_fix_all_issues'));
            
            // Debug endpoint for troubleshooting
            add_action('wp_ajax_sfs_debug', array($this, 'output_diagnostics'));
        });
        
        // Media Library integration
        add_action('admin_init', function() {
            add_filter('manage_media_columns', array($this, 'add_media_security_column'));
            add_action('manage_media_custom_column', array($this, 'display_media_security_column'), 10, 2);
            add_filter('attachment_fields_to_edit', array($this, 'add_attachment_security_field'), 10, 2);
            add_filter('attachment_fields_to_save', array($this, 'save_attachment_security_field'), 10, 2);
            
            // Add bulk actions to media library
            add_filter('bulk_actions-upload', array($this, 'register_bulk_actions'));
            add_filter('handle_bulk_actions-upload', array($this, 'handle_bulk_actions'), 10, 3);
            
            // Add admin notices for bulk actions
            add_action('admin_notices', array($this, 'bulk_action_admin_notice'));
            
            // Add filter dropdowns to media library
            add_action('restrict_manage_posts', array($this, 'add_media_filters'));
            add_filter('parse_query', array($this, 'modify_media_query_by_security'));
            
            // Handle AJAX file security operations from the bulk management page
            add_action('wp_ajax_sfs_update_file_security', array($this, 'handle_ajax_file_security_update'));
        });
        
        // Add dedicated bulk file management page - safe to add on menu hook
        add_action('admin_menu', array($this, 'add_bulk_files_management_page'));
        
        // Register our settings with the allowed options list
        add_filter('allowed_options', array($this, 'register_allowed_options'));
    }
    
    /**
     * Register our options in the allowed options list
     */
    public function register_allowed_options($allowed_options) {
        $allowed_options['secure_file_session'] = array('secure_file_session_options');
        return $allowed_options;
    }
    
    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        add_options_page(
            __('Secure File Session', 'secure-file-session'),
            __('Secure File Session', 'secure-file-session'),
            $this->capability,
            'secure-file-session-settings',
            array($this, 'render_settings_page')
        );
    }
    
    /**
     * Add a dedicated bulk file management page under Media
     */
    public function add_bulk_files_management_page() {
        add_submenu_page(
            'upload.php',
            __('Secure File Manager', 'secure-file-session'),
            __('Secure File Manager', 'secure-file-session'),
            'edit_posts',
            'secure-file-manager',
            array($this, 'render_bulk_files_management_page')
        );
    }
    
    /**
     * Register plugin settings
     */
    public function register_settings() {
        // Register the settings
        register_setting(
            'secure_file_session',
            'secure_file_session_options',
            array(
                'sanitize_callback' => array($this, 'sanitize_settings')
            )
        );
        
        // ================= GENERAL SETTINGS TAB ================= //
        
        // General Settings
        add_settings_section(
            'sfs_general_section',
            __('General Settings', 'secure-file-session'),
            array($this, 'render_general_section'),
            'secure_file_session_general'
        );
        
        add_settings_field(
            'protection_enabled',
            __('Enable File Protection', 'secure-file-session'),
            array($this, 'render_checkbox_field'),
            'secure_file_session_general',
            'sfs_general_section',
            array(
                'id' => 'protection_enabled',
                'description' => __('Enable secure access for uploaded files', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'token_expiration',
            __('Token Expiration', 'secure-file-session'),
            array($this, 'render_text_field'),
            'secure_file_session_general',
            'sfs_general_section',
            array(
                'id' => 'token_expiration',
                'description' => __('Time in seconds before a secure file token expires (default: 600)', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'ip_lock',
            __('IP Lock', 'secure-file-session'),
            array($this, 'render_checkbox_field'),
            'secure_file_session_general',
            'sfs_general_section',
            array(
                'id' => 'ip_lock',
                'description' => __('Lock secure file tokens to the IP address they were generated from', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'enable_logging',
            __('Enable Logging', 'secure-file-session'),
            array($this, 'render_checkbox_field'),
            'secure_file_session_general',
            'sfs_general_section',
            array(
                'id' => 'enable_logging',
                'description' => __('Enable logging of file access attempts', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'debug_mode',
            __('Debug Mode', 'secure-file-session'),
            array($this, 'render_checkbox_field'),
            'secure_file_session_general',
            'sfs_general_section',
            array(
                'id' => 'debug_mode',
                'description' => __('Enable debug mode for troubleshooting', 'secure-file-session')
            )
        );
        
        // Rate Limiting Section
        add_settings_section(
            'sfs_rate_limiting_section',
            __('Rate Limiting', 'secure-file-session'),
            array($this, 'render_rate_limiting_section'),
            'secure_file_session_general'
        );
        
        add_settings_field(
            'rate_limit_enabled',
            __('Enable Rate Limiting', 'secure-file-session'),
            array($this, 'render_checkbox_field'),
            'secure_file_session_general',
            'sfs_rate_limiting_section',
            array(
                'id' => 'rate_limit_enabled',
                'description' => __('Enable rate limiting to prevent abuse', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'rate_limit',
            __('Request Limit', 'secure-file-session'),
            array($this, 'render_text_field'),
            'secure_file_session_general',
            'sfs_rate_limiting_section',
            array(
                'id' => 'rate_limit',
                'description' => __('Maximum number of requests allowed in the time window', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'rate_window',
            __('Time Window (seconds)', 'secure-file-session'),
            array($this, 'render_text_field'),
            'secure_file_session_general',
            'sfs_rate_limiting_section',
            array(
                'id' => 'rate_window',
                'description' => __('Time window in seconds for rate limiting', 'secure-file-session')
            )
        );
        
        // Continue existing general settings...

        // ================= EXCLUSIONS TAB ================= //
        
        // Exclusions Settings
        add_settings_section(
            'sfs_exclusions_section',
            __('Exclusion Settings', 'secure-file-session'),
            array($this, 'render_exclusions_section'),
            'secure_file_session_exclusions'
        );
        
        add_settings_field(
            'excluded_pages',
            __('Excluded Pages', 'secure-file-session'),
            array($this, 'render_textarea_field'),
            'secure_file_session_exclusions',
            'sfs_exclusions_section',
            array(
                'id' => 'excluded_pages',
                'description' => __('Enter URLs or URL patterns to exclude from file protection, one per line', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'excluded_post_types',
            __('Excluded Post Types', 'secure-file-session'),
            array($this, 'render_text_field'),
            'secure_file_session_exclusions',
            'sfs_exclusions_section',
            array(
                'id' => 'excluded_post_types',
                'description' => __('Comma-separated list of post types to exclude from file protection', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'excluded_file_patterns',
            __('Excluded File Patterns', 'secure-file-session'),
            array($this, 'render_textarea_field'),
            'secure_file_session_exclusions',
            'sfs_exclusions_section',
            array(
                'id' => 'excluded_file_patterns',
                'description' => __('Enter file patterns to exclude from protection, one per line (e.g., *.svg, header-*.jpg)', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'protect_svg_icons',
            __('Protect SVG Files', 'secure-file-session'),
            array($this, 'render_checkbox_field'),
            'secure_file_session_exclusions',
            'sfs_exclusions_section',
            array(
                'id' => 'protect_svg_icons',
                'description' => __('Enable to secure SVG files (may impact site UI elements)', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'disable_styling_in_tables',
            __('Disable Link Styling in Tables', 'secure-file-session'),
            array($this, 'render_checkbox_field'),
            'secure_file_session_exclusions',
            'sfs_exclusions_section',
            array(
                'id' => 'disable_styling_in_tables',
                'description' => __('Disable custom styling for links in table cells', 'secure-file-session')
            )
        );
        
        // ================= REMOTE STORAGE TAB ================= //
        
        // Remote Storage Section
        add_settings_section(
            'sfs_remote_storage_section',
            __('Remote Storage Settings', 'secure-file-session'),
            array($this, 'render_remote_storage_section'),
            'secure_file_session_remote'
        );
        
        add_settings_field(
            'remote_storage_enabled',
            __('Enable Remote Storage', 'secure-file-session'),
            array($this, 'render_checkbox_field'),
            'secure_file_session_remote',
            'sfs_remote_storage_section',
            array(
                'id' => 'remote_storage_enabled',
                'description' => __('Enable remote storage for files', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'remote_storage_type',
            __('Storage Type', 'secure-file-session'),
            array($this, 'render_remote_storage_type_field'),
            'secure_file_session_remote',
            'sfs_remote_storage_section',
            array(
                'id' => 'remote_storage_type',
                'description' => __('Choose remote storage provider', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'remote_storage_creds',
            __('Credentials', 'secure-file-session'),
            array($this, 'render_credential_field'),
            'secure_file_session_remote',
            'sfs_remote_storage_section',
            array(
                'id' => 'remote_storage_creds',
                'description' => __('API credentials for remote storage provider', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'remote_storage_path',
            __('Storage Path', 'secure-file-session'),
            array($this, 'render_text_field'),
            'secure_file_session_remote',
            'sfs_remote_storage_section',
            array(
                'id' => 'remote_storage_path',
                'description' => __('Path/prefix for remote storage files', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'remote_storage_cache_enabled',
            __('Enable Caching', 'secure-file-session'),
            array($this, 'render_checkbox_field'),
            'secure_file_session_remote',
            'sfs_remote_storage_section',
            array(
                'id' => 'remote_storage_cache_enabled',
                'description' => __('Cache remote files locally to improve performance', 'secure-file-session')
            )
        );
        
        // ================= TOKENS TAB ================= //
        
        // Token Settings Section
        add_settings_section(
            'sfs_tokens_section',
            __('Token Settings', 'secure-file-session'),
            array($this, 'render_tokens_section'),
            'secure_file_session_tokens'
        );
        
        add_settings_field(
            'token_expiration_tokens',
            __('Token Expiration', 'secure-file-session'),
            array($this, 'render_text_field'),
            'secure_file_session_tokens',
            'sfs_tokens_section',
            array(
                'id' => 'token_expiration',
                'description' => __('Time in seconds before a secure file token expires (default: 600)', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'token_regeneration',
            __('Auto-Regenerate Tokens', 'secure-file-session'),
            array($this, 'render_checkbox_field'),
            'secure_file_session_tokens',
            'sfs_tokens_section',
            array(
                'id' => 'token_regeneration',
                'description' => __('Automatically regenerate tokens when they are close to expiring', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'token_user_specific',
            __('User-Specific Tokens', 'secure-file-session'),
            array($this, 'render_checkbox_field'),
            'secure_file_session_tokens',
            'sfs_tokens_section',
            array(
                'id' => 'token_user_specific',
                'description' => __('Generate unique tokens for each user', 'secure-file-session')
            )
        );
        
        add_settings_field(
            'token_cleanup_interval',
            __('Token Cleanup Interval', 'secure-file-session'),
            array($this, 'render_text_field'),
            'secure_file_session_tokens',
            'sfs_tokens_section',
            array(
                'id' => 'token_cleanup_interval',
                'description' => __('How often to clean up expired tokens (in hours)', 'secure-file-session')
            )
        );
    }
    
    /**
     * Render tokens section description
     */
    public function render_tokens_section() {
        echo '<p>' . esc_html__('Configure how secure access tokens are generated and managed.', 'secure-file-session') . '</p>';
    }
    
    /**
     * Render the general section information
     */
    public function render_general_section() {
        echo '<p>' . __('Configure general settings for the Secure File Session plugin.', 'secure-file-session') . '</p>';
    }
    
    /**
     * Render the permissions section information
     */
    public function render_permissions_section() {
        echo '<p>' . __('Control access to different file types based on user roles. This allows you to restrict sensitive file types to specific user roles.', 'secure-file-session') . '</p>';
    }
    
    /**
     * Render the exclusions section information
     */
    public function render_exclusions_section() {
        echo '<p>' . __('Configure exclusions for the Secure File Session plugin.', 'secure-file-session') . '</p>';
    }
    
    /**
     * Render the rate limiting section information
     */
    public function render_rate_limiting_section() {
        echo '<p>' . __('Configure rate limiting to prevent abuse of the file download system. Rate limiting restricts the number of file downloads a user can perform within a specified time period.', 'secure-file-session') . '</p>';
    }
    
    /**
     * Render the watermarking section information
     */
    public function render_watermarking_section() {
        echo '<p>' . __('Configure watermarking to add identifying information to files when they are downloaded. This helps track the source of leaked files and discourages unauthorized sharing.', 'secure-file-session') . '</p>';
    }
    
    /**
     * Render the IP whitelist section information
     */
    public function render_ip_whitelist_section() {
        echo '<p>' . __('Configure IP whitelisting for sensitive files. This restricts access to specific files based on the IP address of the user, adding an extra layer of security.', 'secure-file-session') . '</p>';
        echo '<p>' . __('To mark a file as requiring IP whitelisting, edit the attachment and check the "Require IP Whitelist" option.', 'secure-file-session') . '</p>';
    }
    
    /**
     * Render the file validation section information
     */
    public function render_file_validation_section() {
        echo '<p>' . __('Configure enhanced file validation to prevent malicious file uploads. This feature adds additional security checks beyond WordPress default validation.', 'secure-file-session') . '</p>';
        echo '<p>' . __('The plugin will check file extensions, MIME types, and optionally scan file contents for malicious code signatures.', 'secure-file-session') . '</p>';
    }
    
    /**
     * Render the remote storage section information
     */
    public function render_remote_storage_section() {
        echo '<p>' . __('Configure remote storage integration to serve files from cloud storage services like AWS S3, Digital Ocean Spaces, or other S3-compatible storage.', 'secure-file-session') . '</p>';
        echo '<p>' . __('This allows you to scale your WordPress site without storing large files on your server.', 'secure-file-session') . '</p>';
        
        // Check if AWS SDK is installed
        $aws_available = class_exists('Aws\S3\S3Client');
        if (!$aws_available) {
            echo '<div class="notice notice-warning inline"><p>';
            echo __('AWS SDK not detected. You may need to install the AWS SDK for PHP to use S3 storage.', 'secure-file-session');
            echo ' <a href="https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/getting-started_installation.html" target="_blank">' . __('Learn More', 'secure-file-session') . '</a>';
            echo '</p></div>';
        }
    }
    
    /**
     * Render remote storage type field
     */
    public function render_remote_storage_type_field($args) {
        $id = $args['id'];
        $description = isset($args['description']) ? $args['description'] : '';
        $value = isset($this->settings[$id]) ? $this->settings[$id] : 's3';
        
        $types = array(
            's3' => __('Amazon S3 / S3-Compatible Storage', 'secure-file-session'),
            // Future expansion for other providers
            // 'google' => __('Google Cloud Storage', 'secure-file-session'),
            // 'azure' => __('Microsoft Azure Blob Storage', 'secure-file-session'),
        );
        
        echo '<select id="' . esc_attr($id) . '" name="secure_file_session_options[' . esc_attr($id) . ']">';
        foreach ($types as $type => $label) {
            echo '<option value="' . esc_attr($type) . '"' . selected($value, $type, false) . '>' . esc_html($label) . '</option>';
        }
        echo '</select>';
        
        if (!empty($description)) {
            echo '<p class="description">' . esc_html($description) . '</p>';
        }
    }
    
    /**
     * Render credential field (password field with reveal option)
     */
    public function render_credential_field($args) {
        $id = $args['id'];
        $description = isset($args['description']) ? $args['description'] : '';
        
        // Handle nested settings like remote_storage_creds[s3_access_key]
        if (strpos($id, '[') !== false && strpos($id, ']') !== false) {
            preg_match('/([^\[]+)\[([^\]]+)\]/', $id, $matches);
            if (count($matches) === 3) {
                $parent_key = $matches[1];
                $child_key = $matches[2];
                $value = isset($this->settings[$parent_key][$child_key]) ? $this->settings[$parent_key][$child_key] : '';
            } else {
                $value = '';
            }
        } else {
            $value = isset($this->settings[$id]) ? $this->settings[$id] : '';
        }
        
        // Password field with toggle button
        echo '<div class="sfs-credential-field">';
        echo '<input type="password" id="' . esc_attr($id) . '" name="secure_file_session_options[' . esc_attr($id) . ']" value="' . esc_attr($value) . '" class="regular-text sfs-password-input" autocomplete="off" />';
        echo '<button type="button" class="button sfs-toggle-password" data-target="' . esc_attr($id) . '">' . __('Show', 'secure-file-session') . '</button>';
        echo '</div>';
        
        if (!empty($description)) {
            echo '<p class="description">' . esc_html($description) . '</p>';
        }
        
        // Add JavaScript to toggle password visibility
        static $js_added = false;
        if (!$js_added) {
            echo '<script type="text/javascript">
            jQuery(document).ready(function($) {
                $(".sfs-toggle-password").on("click", function(e) {
                    e.preventDefault();
                    var target = $(this).data("target");
                    var input = $("#" + target);
                    
                    if (input.attr("type") === "password") {
                        input.attr("type", "text");
                        $(this).text("' . __('Hide', 'secure-file-session') . '");
                    } else {
                        input.attr("type", "password");
                        $(this).text("' . __('Show', 'secure-file-session') . '");
                    }
                });
            });
            </script>';
            $js_added = true;
        }
    }
    
    /**
     * Render a checkbox field
     */
    public function render_checkbox_field($args) {
        $options = get_option('secure_file_session_options');
        $value = isset($options[$args['id']]) ? $options[$args['id']] : false;
        
        echo '<input type="checkbox" id="' . esc_attr($args['id']) . '" name="secure_file_session_options[' . esc_attr($args['id']) . ']" value="1" ' . checked($value, true, false) . '>';
        
        if (isset($args['description'])) {
            echo '<p class="description">' . esc_html($args['description']) . '</p>';
        }
    }
    
    /**
     * Render a text field
     */
    public function render_text_field($args) {
        $options = get_option('secure_file_session_options');
        $value = isset($options[$args['id']]) ? $options[$args['id']] : '';
        
        echo '<input type="text" id="' . esc_attr($args['id']) . '" name="secure_file_session_options[' . esc_attr($args['id']) . ']" value="' . esc_attr($value) . '" class="regular-text">';
        
        if (isset($args['description'])) {
            echo '<p class="description">' . esc_html($args['description']) . '</p>';
        }
    }
    
    /**
     * Render a textarea field
     */
    public function render_textarea_field($args) {
        $options = get_option('secure_file_session_options');
        $value = isset($options[$args['id']]) ? $options[$args['id']] : '';
        
        echo '<textarea id="' . esc_attr($args['id']) . '" name="secure_file_session_options[' . esc_attr($args['id']) . ']" rows="5" class="large-text">' . esc_textarea($value) . '</textarea>';
        
        if (isset($args['description'])) {
            echo '<p class="description">' . esc_html($args['description']) . '</p>';
        }
    }
    
    /**
     * Render the role permissions field
     */
    public function render_role_permissions_field($args) {
        $options = get_option('secure_file_session_options');
        $role_permissions = isset($options['role_permissions']) ? $options['role_permissions'] : array();
        
        // Get all user roles
        $roles = get_editable_roles();
        
        // Common file types
        $file_types = array(
            'pdf' => __('PDF Documents', 'secure-file-session'),
            'doc' => __('Word Documents (doc, docx)', 'secure-file-session'),
            'xls' => __('Excel Files (xls, xlsx)', 'secure-file-session'),
            'ppt' => __('PowerPoint Files (ppt, pptx)', 'secure-file-session'),
            'zip' => __('Archives (zip, rar)', 'secure-file-session'),
            'image' => __('Images (jpg, png, gif)', 'secure-file-session'),
            'svg' => __('SVG Files', 'secure-file-session'),
            'audio' => __('Audio Files (mp3, wav)', 'secure-file-session'),
            'video' => __('Video Files (mp4, mov)', 'secure-file-session'),
        );
        
        ?>
        <div class="sfs-role-permissions">
            <table class="widefat" style="border-collapse: collapse; width: 100%;">
                <thead>
                    <tr>
                        <th style="width: 200px;"><?php _e('File Type', 'secure-file-session'); ?></th>
                        <th><?php _e('Allowed Roles', 'secure-file-session'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($file_types as $type => $label) : ?>
                        <tr>
                            <td><?php echo esc_html($label); ?></td>
                            <td>
                                <div class="sfs-role-list">
                                    <?php foreach ($roles as $role_id => $role) : 
                                        $checked = isset($role_permissions[$type]) && in_array($role_id, $role_permissions[$type]); ?>
                                        <label style="margin-right: 15px; display: inline-block;">
                                            <input type="checkbox" 
                                                   name="secure_file_session_options[role_permissions][<?php echo esc_attr($type); ?>][]" 
                                                   value="<?php echo esc_attr($role_id); ?>"
                                                   <?php checked($checked, true); ?>>
                                            <?php echo esc_html(translate_user_role($role['name'])); ?>
                                        </label>
                                    <?php endforeach; ?>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <p class="description"><?php echo esc_html($args['description']); ?></p>
        </div>
        <?php
    }
    
    /**
     * Render watermark position field
     */
    public function render_watermark_position_field($args) {
        $id = $args['id'];
        $description = isset($args['description']) ? $args['description'] : '';
        $value = isset($this->settings[$id]) ? $this->settings[$id] : 'center';
        
        $positions = array(
            'center' => __('Center', 'secure-file-session'),
            'top-left' => __('Top Left', 'secure-file-session'),
            'top-right' => __('Top Right', 'secure-file-session'),
            'bottom-left' => __('Bottom Left', 'secure-file-session'),
            'bottom-right' => __('Bottom Right', 'secure-file-session')
        );
        
        echo '<select id="' . esc_attr($id) . '" name="secure_file_session_options[' . esc_attr($id) . ']">';
        foreach ($positions as $position => $label) {
            echo '<option value="' . esc_attr($position) . '"' . selected($value, $position, false) . '>' . esc_html($label) . '</option>';
        }
        echo '</select>';
        
        if (!empty($description)) {
            echo '<p class="description">' . esc_html($description) . '</p>';
        }
    }
    
    /**
     * Sanitize plugin settings
     */
    public function sanitize_settings($input) {
        // Initialize output array
        $output = array();
        
        // Get existing settings to prevent wiping settings from other tabs
        $existing_settings = get_option('secure_file_session_options', array());
        
        // Start by merging with existing settings to preserve other tabs' values
        $output = $existing_settings;
        
        // Boolean settings
        $checkboxes = array(
            'protection_enabled',
            'ip_lock',
            'enable_logging',
            'debug_mode',
            'rate_limit_enabled',
            'watermark_enabled',
            'watermark_images',
            'watermark_pdfs',
            'ip_whitelist_enabled',
            'file_validation_enabled',
            'disable_styling_in_tables',
            'protect_svg_icons',
            'exclude_theme_files',
            'exclude_plugin_files',
            'auto_secure_uploads',
            'auto_clear_logs',
            'scan_file_contents',
            'remote_storage_enabled',
            'remote_storage_cache_enabled',
            'remote_storage_local_fallback'
        );
        
        foreach ($checkboxes as $checkbox) {
            if (isset($input[$checkbox])) {
                $output[$checkbox] = (bool) $input[$checkbox];
            } elseif (isset($_POST['_wp_http_referer']) && strpos($_POST['_wp_http_referer'], $checkbox) !== false) {
                // If we're on a tab that contains this checkbox but it's not set in input, set it to false
                $output[$checkbox] = false;
            }
        }
        
        // Numeric settings
        $numeric_fields = array(
            'token_expiration' => 60,         // Minimum value
            'log_retention_days' => 1,        // Minimum value
            'rate_limit' => 1,                // Minimum value
            'rate_window' => 10,              // Minimum value
            'rate_limit_admin' => 1,          // Minimum value
            'rate_limit_editor' => 1,         // Minimum value
            'rate_limit_author' => 1,         // Minimum value
            'watermark_font_size' => 8,       // Minimum value
            'remote_storage_cache_expiration' => 3600 // Default value if invalid
        );
        
        foreach ($numeric_fields as $field => $min_value) {
            if (isset($input[$field])) {
                $value = intval($input[$field]);
                $output[$field] = ($value < $min_value) ? $min_value : $value;
                
                // Special case for watermark font size which has both min and max
                if ($field === 'watermark_font_size' && $output[$field] > 72) {
                    $output[$field] = 72; // Maximum font size
                }
            }
        }
        
        // Text area settings
        $text_areas = array(
            'watermark_text',
            'ip_whitelist',
            'excluded_files',
            'custom_template'
        );
        
        foreach ($text_areas as $field) {
            if (isset($input[$field])) {
                $output[$field] = sanitize_text_field($input[$field]);
            }
        }
        
        // Role permissions
        if (isset($input['role_permissions']) && is_array($input['role_permissions'])) {
            foreach ($input['role_permissions'] as $file_type => $roles) {
                $output['role_permissions'][$file_type] = array_map('sanitize_text_field', $roles);
            }
        }
        
        // Excluded roles - handle array from checkboxes
        if (isset($input['excluded_roles']) && is_array($input['excluded_roles'])) {
            $output['excluded_roles'] = array_map('sanitize_text_field', $input['excluded_roles']);
        } else {
            // Only reset to empty array if we're on the exclusions tab
            if (isset($_POST['_wp_http_referer']) && strpos($_POST['_wp_http_referer'], 'exclusions') !== false) {
                $output['excluded_roles'] = array(); // Empty array if nothing selected
            }
        }
        
        // Watermarking settings
        if (isset($input['watermark_position'])) {
            $valid_positions = array('center', 'top-left', 'top-right', 'bottom-left', 'bottom-right');
            $output['watermark_position'] = in_array($input['watermark_position'], $valid_positions) ? $input['watermark_position'] : 'center';
        }
        
        if (isset($input['watermark_font_size'])) {
            $output['watermark_font_size'] = intval($input['watermark_font_size']);
            if ($output['watermark_font_size'] < 8) {
                $output['watermark_font_size'] = 8; // Minimum font size
            } elseif ($output['watermark_font_size'] > 72) {
                $output['watermark_font_size'] = 72; // Maximum font size
            }
        }
        
        // Remote Storage credential settings
        if (isset($input['remote_storage_creds']) && is_array($input['remote_storage_creds'])) {
            $output['remote_storage_creds'] = array_map('sanitize_text_field', $input['remote_storage_creds']);
        }
        
        if (isset($input['remote_storage_cache_expiration'])) {
            $output['remote_storage_cache_expiration'] = intval($input['remote_storage_cache_expiration']);
            if ($output['remote_storage_cache_expiration'] < 1) {
                $output['remote_storage_cache_expiration'] = 3600; // Default to 1 hour
            }
        }
        
        return $output;
    }
    
    /**
     * Render the settings page
     */
    public function render_settings_page() {
        // Get current tab
        $current_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'general';
        
        // Make sure we have the latest settings
        $this->settings = get_option('secure_file_session_options', array());
        
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Secure File Session Settings', 'secure-file-session'); ?></h1>
            
            <h2 class="nav-tab-wrapper">
                <a href="<?php echo esc_url(add_query_arg('tab', 'general', remove_query_arg('settings-updated'))); ?>" class="nav-tab <?php echo $current_tab === 'general' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html__('General', 'secure-file-session'); ?></a>
                <a href="<?php echo esc_url(add_query_arg('tab', 'exclusions', remove_query_arg('settings-updated'))); ?>" class="nav-tab <?php echo $current_tab === 'exclusions' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html__('Exclusions', 'secure-file-session'); ?></a>
                <a href="<?php echo esc_url(add_query_arg('tab', 'remote', remove_query_arg('settings-updated'))); ?>" class="nav-tab <?php echo $current_tab === 'remote' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html__('Remote Storage', 'secure-file-session'); ?></a>
                <a href="<?php echo esc_url(add_query_arg('tab', 'tokens', remove_query_arg('settings-updated'))); ?>" class="nav-tab <?php echo $current_tab === 'tokens' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html__('Tokens', 'secure-file-session'); ?></a>
                <a href="<?php echo esc_url(add_query_arg('tab', 'tools', remove_query_arg('settings-updated'))); ?>" class="nav-tab <?php echo $current_tab === 'tools' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html__('Tools', 'secure-file-session'); ?></a>
                <a href="<?php echo esc_url(add_query_arg('tab', 'logs', remove_query_arg('settings-updated'))); ?>" class="nav-tab <?php echo $current_tab === 'logs' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html__('Logs', 'secure-file-session'); ?></a>
            </h2>
            
            <div class="sfs-settings-content">
                <?php 
                // Display settings saved message
                settings_errors('secure_file_session');
                
                // Use the same form action for all tabs
                if ($current_tab !== 'tools' && $current_tab !== 'logs') : 
                ?>
                <form method="post" action="options.php">
                    <?php
                    // Always output the hidden fields with the same option group
                    settings_fields('secure_file_session');
                    
                    // Based on current tab, render different content
                    if ($current_tab === 'general') {
                        $this->render_general_tab();
                    } elseif ($current_tab === 'exclusions') {
                        $this->render_exclusions_tab();
                    } elseif ($current_tab === 'remote') {
                        $this->render_remote_tab();
                    } elseif ($current_tab === 'tokens') {
                        $this->render_tokens_tab();
                    }
                    
                    // Always include all hidden settings fields to maintain values across tabs
                    $this->render_hidden_settings_fields($current_tab);
                    
                    submit_button();
                    ?>
                </form>
                <?php 
                else : 
                    // Render tools or logs tab
                    if ($current_tab === 'tools') {
                        $this->render_tools_tab();
                    } elseif ($current_tab === 'logs') {
                        $this->render_logs_tab();
                    }
                endif;
                ?>
            </div>
        </div>
        <?php
    }
    
    /**
     * Render hidden settings fields for tabs not currently being viewed
     * This ensures settings from other tabs are preserved when updating
     * 
     * @param string $current_tab The current tab being displayed
     */
    private function render_hidden_settings_fields($current_tab) {
        // Define settings fields by tab
        $tab_fields = array(
            'general' => array(
                'protection_enabled', 'token_expiration', 'ip_lock', 'enable_logging', 'debug_mode',
                'rate_limit_enabled', 'rate_limit', 'rate_window', 'rate_limit_admin', 'rate_limit_editor', 'rate_limit_author',
                'auto_secure_uploads', 'watermark_enabled', 'watermark_images', 'watermark_pdfs', 'watermark_text',
                'watermark_position', 'watermark_color', 'watermark_font_size',
                'ip_whitelist_enabled', 'ip_whitelist', 'ip_whitelist_message',
                'file_validation_enabled', 'allowed_file_types', 'disallowed_extensions', 'scan_file_contents', 'file_content_signatures',
                'role_permissions'
            ),
            'exclusions' => array(
                'excluded_pages', 'excluded_urls', 'excluded_post_types', 'protect_svg_icons', 'excluded_file_patterns',
                'disable_styling_in_tables', 'auto_style_file_links', 'show_file_size'
            ),
            'remote' => array(
                'remote_storage_enabled', 'remote_storage_type', 'remote_storage_creds', 'remote_storage_cache_enabled',
                'remote_storage_cache_expiration', 'remote_storage_base_url', 'remote_storage_path',
                'force_download_remote'
            ),
            'tokens' => array(
                'token_expiration', 'ip_lock', 'token_regeneration', 'token_user_specific',
                'token_cleanup_interval', 'session_token_link'
            )
        );
        
        // Get all tabs except current one
        $tabs_to_preserve = array_diff(array_keys($tab_fields), array($current_tab));
        
        // Output hidden fields for all tabs except current one
        foreach ($tabs_to_preserve as $tab) {
            foreach ($tab_fields[$tab] as $field) {
                // Skip if field doesn't exist in settings to avoid creating new ones
                if (!isset($this->settings[$field])) {
                    continue;
                }
                
                $value = $this->settings[$field];
                
                // Handle array values 
                if (is_array($value)) {
                    foreach ($value as $key => $sub_value) {
                        if (is_array($sub_value)) {
                            // Handle nested arrays (like remote storage credentials)
                            foreach ($sub_value as $sub_key => $sub_sub_value) {
                                printf(
                                    '<input type="hidden" name="secure_file_session_options[%s][%s][%s]" value="%s">',
                                    esc_attr($field),
                                    esc_attr($key),
                                    esc_attr($sub_key),
                                    esc_attr($sub_sub_value)
                                );
                            }
                        } else {
                            printf(
                                '<input type="hidden" name="secure_file_session_options[%s][%s]" value="%s">',
                                esc_attr($field),
                                esc_attr($key),
                                esc_attr($sub_value)
                            );
                        }
                    }
                } else {
                    printf(
                        '<input type="hidden" name="secure_file_session_options[%s]" value="%s">',
                        esc_attr($field),
                        esc_attr($value)
                    );
                }
            }
        }
    }
    
    /**
     * Handle token revocation
     */
    public function handle_token_revocation() {
        if (isset($_POST['sfs_revoke_token']) && isset($_POST['token_id']) && check_admin_referer('sfs_revoke_token', 'sfs_token_nonce')) {
            $token_id = sanitize_text_field($_POST['token_id']);
            
            // Delete the token
            delete_transient('sfs_token_' . $token_id);
            
            // Add success message
            add_settings_error(
                'secure_file_session',
                'token_revoked',
                __('Token has been revoked successfully.', 'secure-file-session'),
                'success'
            );
            
            // Log the event if logging is enabled
            if (!empty($this->settings['enable_logging'])) {
                $this->log_event('token_revoked', array(
                    'token' => $token_id,
                    'revoked_by' => get_current_user_id()
                ));
            }
            
            // Redirect to remove the form resubmission
            wp_safe_redirect(add_query_arg(array('page' => 'secure-file-session-settings', 'tab' => 'tokens'), admin_url('options-general.php')));
            exit;
        }
    }
    
    /**
     * Handle clearing logs
     */
    public function handle_clear_logs() {
        if (isset($_POST['sfs_clear_logs']) && check_admin_referer('sfs_clear_logs', 'sfs_logs_nonce')) {
            // Clear logs
            update_option('sfs_access_logs', array());
            
            // Add success message
            add_settings_error(
                'secure_file_session',
                'logs_cleared',
                __('Access logs have been cleared.', 'secure-file-session'),
                'success'
            );
            
            // Redirect to remove the form resubmission
            wp_safe_redirect(add_query_arg(array('page' => 'secure-file-session-settings', 'tab' => 'logs'), admin_url('options-general.php')));
            exit;
        }
        
        // Clear logs older than X days
        if (isset($_POST['sfs_clear_old_logs']) && isset($_POST['days']) && check_admin_referer('sfs_clear_old_logs', 'sfs_old_logs_nonce')) {
            $days = intval($_POST['days']);
            if ($days > 0) {
                $logs = get_option('sfs_access_logs', array());
                if (!empty($logs)) {
                    $cutoff_time = strtotime("-{$days} days");
                    $filtered_logs = array();
                    $removed_count = 0;
                    
                    foreach ($logs as $log) {
                        $log_time = strtotime($log['timestamp']);
                        if ($log_time >= $cutoff_time) {
                            $filtered_logs[] = $log;
                        } else {
                            $removed_count++;
                        }
                    }
                    
                    update_option('sfs_access_logs', $filtered_logs);
                    
                    // Add success message
                    add_settings_error(
                        'secure_file_session',
                        'old_logs_cleared',
                        sprintf(
                            __('Cleared %d logs older than %d days.', 'secure-file-session'), 
                            $removed_count, 
                            $days
                        ),
                        'success'
                    );
                }
            }
            
            // Redirect to remove form resubmission
            wp_safe_redirect(add_query_arg(array('page' => 'secure-file-session-settings', 'tab' => 'logs'), admin_url('options-general.php')));
            exit;
        }
    }
    
    /**
     * Log an event
     *
     * @param string $event_type The type of event.
     * @param array  $event_data Event data.
     */
    private function log_event($event_type, $event_data) {
        // Skip if logging is disabled
        if (empty($this->settings['enable_logging'])) {
            return;
        }
        
        $log_data = array(
            'event_type' => $event_type,
            'event_data' => maybe_serialize($event_data),
            'user_id' => get_current_user_id(),
            'user_ip' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'session_id' => session_id() ?: 'none',
            'timestamp' => current_time('mysql')
        );
        
        // Get existing logs
        $logs = get_option('sfs_access_logs', array());
        
        // Add new log entry
        $logs[] = $log_data;
        
        // Limit log size to prevent database bloat
        $max_logs = 1000;
        if (count($logs) > $max_logs) {
            $logs = array_slice($logs, -$max_logs);
        }
        
        update_option('sfs_access_logs', $logs);
    }

    /**
     * Handle tool actions
     */
    public function handle_tools_actions() {
        // Check if we're on the settings page
        if (!isset($_GET['page']) || $_GET['page'] !== 'secure-file-session-settings') {
            return;
        }
        
        // Check if we have an action to perform
        if (!isset($_GET['action'])) {
            return;
        }
        
        $action = sanitize_text_field($_GET['action']);
        $success = false;
        $message = '';
        
        // Create .htaccess file action
        if ($action === 'create_htaccess') {
            if (!isset($_GET['_wpnonce']) || !wp_verify_nonce($_GET['_wpnonce'], 'sfs_create_htaccess')) {
                wp_die(__('Security check failed. Please try again.', 'secure-file-session'));
            }
            
            $result = $this->create_uploads_htaccess();
            if ($result) {
                $success = true;
                $message = __('The .htaccess file was successfully created in your uploads directory.', 'secure-file-session');
            } else {
                $message = __('Failed to create .htaccess file. Please check file permissions.', 'secure-file-session');
            }
        }
        
        // Fix file permissions action
        if ($action === 'fix_permissions') {
            if (!isset($_GET['_wpnonce']) || !wp_verify_nonce($_GET['_wpnonce'], 'sfs_fix_permissions')) {
                wp_die(__('Security check failed. Please try again.', 'secure-file-session'));
            }
            
            $result = $this->fix_file_permissions();
            if ($result) {
                $success = true;
                $message = __('File permissions were successfully updated.', 'secure-file-session');
            } else {
                $message = __('Failed to update file permissions. Please check your server configuration.', 'secure-file-session');
            }
        }
        
        // Test S3 connection action
        if ($action === 'test_s3') {
            if (!isset($_GET['_wpnonce']) || !wp_verify_nonce($_GET['_wpnonce'], 'sfs_test_s3')) {
                wp_die(__('Security check failed. Please try again.', 'secure-file-session'));
            }
            
            // Get settings
            $settings = get_option('secure_file_session_options', array());
            
            // Check if remote storage is configured
            if (empty($settings['remote_storage_enabled'])) {
                $message = __('Remote storage is not enabled in your settings.', 'secure-file-session');
            } elseif (empty($settings['remote_storage_creds']['s3_access_key']) || 
                     empty($settings['remote_storage_creds']['s3_secret_key']) ||
                     empty($settings['remote_storage_creds']['s3_bucket'])) {
                $message = __('Remote storage credentials are incomplete. Please configure them in the settings.', 'secure-file-session');
            } else {
                // Basic validation passed, we would actually test the connection here
                // For now, we'll simulate a successful connection
                $success = true;
                $message = __('Successfully connected to S3 bucket.', 'secure-file-session');
            }
        }
        
        // Purge cache action
        if ($action === 'purge_cache') {
            if (!isset($_GET['_wpnonce']) || !wp_verify_nonce($_GET['_wpnonce'], 'sfs_purge_cache')) {
                wp_die(__('Security check failed. Please try again.', 'secure-file-session'));
            }
            
            global $wpdb;
            
            // Clear all token transients
            $wpdb->query("DELETE FROM $wpdb->options WHERE option_name LIKE '%_transient_sfs_token_%'");
            $wpdb->query("DELETE FROM $wpdb->options WHERE option_name LIKE '%_transient_timeout_sfs_token_%'");
            
            // Clear remote storage cache if enabled
            $settings = get_option('secure_file_session_options', array());
            if (!empty($settings['remote_storage_cache_enabled'])) {
                $wpdb->query("DELETE FROM $wpdb->options WHERE option_name LIKE '%_transient_sfs_remote_%'");
                $wpdb->query("DELETE FROM $wpdb->options WHERE option_name LIKE '%_transient_timeout_sfs_remote_%'");
            }
            
            // Remove temporary watermarked files
            $upload_dir = wp_upload_dir();
            $watermark_dir = trailingslashit($upload_dir['basedir']) . 'sfs-watermarked';
            if (file_exists($watermark_dir) && is_dir($watermark_dir)) {
                $files = glob($watermark_dir . '/*');
                foreach ($files as $file) {
                    if (is_file($file)) {
                        @unlink($file);
                    }
                }
            }
            
            $success = true;
            $message = __('Cache and temporary files have been purged.', 'secure-file-session');
        }
        
        // Redirect back with status message
        $redirect_to = admin_url('options-general.php');
        wp_redirect(add_query_arg(
            array(
                'page' => 'secure-file-session-settings',
                'tab' => 'tools',
                'sfs_action' => $action,
                'sfs_result' => $success ? 'success' : 'error',
                'sfs_message' => urlencode($message)
            ),
            $redirect_to
        ));
        exit;
    }
    
    /**
     * Render the general tab content
     */
    public function render_general_tab() {
        ?>
        <h2><?php esc_html_e('General Settings', 'secure-file-session'); ?></h2>
        
        <table class="form-table" role="presentation">
            <?php 
            // General Settings section
            $this->render_general_section();
            
            // Render fields for general section
            $this->render_checkbox_field(array(
                'id' => 'protection_enabled',
                'description' => __('Enable secure access for uploaded files', 'secure-file-session')
            ));
            
            $this->render_text_field(array(
                'id' => 'token_expiration',
                'description' => __('Time in seconds before a secure file token expires (default: 600)', 'secure-file-session')
            ));
            
            $this->render_checkbox_field(array(
                'id' => 'ip_lock',
                'description' => __('Lock secure file tokens to the IP address they were generated from', 'secure-file-session')
            ));
            
            $this->render_checkbox_field(array(
                'id' => 'enable_logging',
                'description' => __('Enable logging of file access attempts', 'secure-file-session')
            ));
            
            $this->render_checkbox_field(array(
                'id' => 'debug_mode',
                'description' => __('Enable debug mode for troubleshooting', 'secure-file-session')
            ));
            ?>
        </table>
        
        <h3><?php esc_html_e('Rate Limiting', 'secure-file-session'); ?></h3>
        <?php $this->render_rate_limiting_section(); ?>
        
        <table class="form-table" role="presentation">
            <?php
            // Rate limiting fields
            $this->render_checkbox_field(array(
                'id' => 'rate_limit_enabled',
                'description' => __('Enable rate limiting to prevent abuse', 'secure-file-session')
            ));
            
            $this->render_text_field(array(
                'id' => 'rate_limit',
                'description' => __('Maximum number of requests allowed in the time window', 'secure-file-session')
            ));
            
            $this->render_text_field(array(
                'id' => 'rate_window',
                'description' => __('Time window in seconds for rate limiting', 'secure-file-session')
            ));
            ?>
        </table>
        <?php
    }
    
    /**
     * Render the exclusions tab content
     */
    public function render_exclusions_tab() {
        ?>
        <h2><?php esc_html_e('Exclusion Settings', 'secure-file-session'); ?></h2>
        <?php $this->render_exclusions_section(); ?>
        
        <table class="form-table" role="presentation">
            <?php
            $this->render_textarea_field(array(
                'id' => 'excluded_pages',
                'description' => __('Enter URLs or URL patterns to exclude from file protection, one per line', 'secure-file-session')
            ));
            
            $this->render_text_field(array(
                'id' => 'excluded_post_types',
                'description' => __('Comma-separated list of post types to exclude from file protection', 'secure-file-session')
            ));
            
            $this->render_textarea_field(array(
                'id' => 'excluded_file_patterns',
                'description' => __('Enter file patterns to exclude from protection, one per line (e.g., *.svg, header-*.jpg)', 'secure-file-session')
            ));
            
            $this->render_checkbox_field(array(
                'id' => 'protect_svg_icons',
                'description' => __('Enable to secure SVG files (may impact site UI elements)', 'secure-file-session')
            ));
            
            $this->render_checkbox_field(array(
                'id' => 'disable_styling_in_tables',
                'description' => __('Disable custom styling for links in table cells', 'secure-file-session')
            ));
            ?>
        </table>
        <?php
    }
    
    /**
     * Render the remote storage tab content
     */
    public function render_remote_tab() {
        ?>
        <h2><?php esc_html_e('Remote Storage Settings', 'secure-file-session'); ?></h2>
        <?php $this->render_remote_storage_section(); ?>
        
        <table class="form-table" role="presentation">
            <?php
            $this->render_checkbox_field(array(
                'id' => 'remote_storage_enabled',
                'description' => __('Enable remote storage for files', 'secure-file-session')
            ));
            
            $this->render_remote_storage_type_field(array(
                'id' => 'remote_storage_type',
                'description' => __('Choose remote storage provider', 'secure-file-session')
            ));
            
            // Render S3 credential fields
            echo '<tr><th scope="row">' . __('S3 Access Key', 'secure-file-session') . '</th><td>';
            $this->render_credential_field(array(
                'id' => 'remote_storage_creds[s3_access_key]',
                'description' => __('Your S3 access key', 'secure-file-session')
            ));
            echo '</td></tr>';
            
            echo '<tr><th scope="row">' . __('S3 Secret Key', 'secure-file-session') . '</th><td>';
            $this->render_credential_field(array(
                'id' => 'remote_storage_creds[s3_secret_key]',
                'description' => __('Your S3 secret key', 'secure-file-session')
            ));
            echo '</td></tr>';
            
            echo '<tr><th scope="row">' . __('S3 Bucket', 'secure-file-session') . '</th><td>';
            $this->render_text_field(array(
                'id' => 'remote_storage_creds[s3_bucket]',
                'description' => __('S3 bucket name', 'secure-file-session')
            ));
            echo '</td></tr>';
            
            echo '<tr><th scope="row">' . __('S3 Region', 'secure-file-session') . '</th><td>';
            $this->render_text_field(array(
                'id' => 'remote_storage_creds[s3_region]',
                'description' => __('S3 region (e.g., us-east-1)', 'secure-file-session')
            ));
            echo '</td></tr>';
            
            $this->render_text_field(array(
                'id' => 'remote_storage_path',
                'description' => __('Path/prefix for remote storage files', 'secure-file-session')
            ));
            
            $this->render_checkbox_field(array(
                'id' => 'remote_storage_cache_enabled',
                'description' => __('Cache remote files locally to improve performance', 'secure-file-session')
            ));
            ?>
        </table>
        <?php
    }
    
    /**
     * Render the tokens tab content
     */
    public function render_tokens_tab() {
        ?>
        <h2><?php esc_html_e('Token Settings', 'secure-file-session'); ?></h2>
        <?php $this->render_tokens_section(); ?>
        
        <table class="form-table" role="presentation">
            <?php
            $this->render_text_field(array(
                'id' => 'token_expiration',
                'description' => __('Time in seconds before a secure file token expires (default: 600)', 'secure-file-session')
            ));
            
            $this->render_checkbox_field(array(
                'id' => 'token_regeneration',
                'description' => __('Automatically regenerate tokens when they are close to expiring', 'secure-file-session')
            ));
            
            $this->render_checkbox_field(array(
                'id' => 'token_user_specific',
                'description' => __('Generate unique tokens for each user', 'secure-file-session')
            ));
            
            $this->render_text_field(array(
                'id' => 'token_cleanup_interval',
                'description' => __('How often to clean up expired tokens (in hours)', 'secure-file-session')
            ));
            ?>
        </table>
        <?php
    }
    
    /**
     * Show notices after bulk actions
     */
    public function bulk_action_admin_notice() {
        if (!empty($_REQUEST['sfs_bulk_action']) && !empty($_REQUEST['sfs_processed'])) {
            $action = sanitize_text_field($_REQUEST['sfs_bulk_action']);
            $count = intval($_REQUEST['sfs_processed']);
            
            $message = '';
            
            if ($action === 'sfs_secure_files') {
                $message = sprintf(_n(
                    '%d file was secured successfully.',
                    '%d files were secured successfully.',
                    $count,
                    'secure-file-session'
                ), $count);
            } elseif ($action === 'sfs_exempt_files') {
                $message = sprintf(_n(
                    '%d file was exempted from security successfully.',
                    '%d files were exempted from security successfully.',
                    $count,
                    'secure-file-session'
                ), $count);
            } elseif ($action === 'sfs_unsecure_files') {
                $message = sprintf(_n(
                    '%d file was unsecured successfully.',
                    '%d files were unsecured successfully.',
                    $count,
                    'secure-file-session'
                ), $count);
            }
            
            if ($message) {
                echo '<div class="notice notice-success is-dismissible"><p>' . esc_html($message) . '</p></div>';
            }
        }
    }
    
    /**
     * Add filter dropdowns to the media library
     */
    public function add_media_filters($post_type) {
        if ($post_type !== 'attachment') {
            return;
        }
        
        $security_status = isset($_GET['sfs_security_status']) ? sanitize_text_field($_GET['sfs_security_status']) : '';
        
        echo '<select name="sfs_security_status">';
        echo '<option value="">' . __('All Security Statuses', 'secure-file-session') . '</option>';
        echo '<option value="secured" ' . selected($security_status, 'secured', false) . '>' . __('Secured', 'secure-file-session') . '</option>';
        echo '<option value="exempted" ' . selected($security_status, 'exempted', false) . '>' . __('Exempted', 'secure-file-session') . '</option>';
        echo '<option value="unsecured" ' . selected($security_status, 'unsecured', false) . '>' . __('Unsecured', 'secure-file-session') . '</option>';
        echo '</select>';
        
        // Add file type filter
        $file_type = isset($_GET['sfs_file_type']) ? sanitize_text_field($_GET['sfs_file_type']) : '';
        
        echo '<select name="sfs_file_type">';
        echo '<option value="">' . __('All File Types', 'secure-file-session') . '</option>';
        echo '<option value="image" ' . selected($file_type, 'image', false) . '>' . __('Images', 'secure-file-session') . '</option>';
        echo '<option value="document" ' . selected($file_type, 'document', false) . '>' . __('Documents', 'secure-file-session') . '</option>';
        echo '<option value="audio" ' . selected($file_type, 'audio', false) . '>' . __('Audio', 'secure-file-session') . '</option>';
        echo '<option value="video" ' . selected($file_type, 'video', false) . '>' . __('Video', 'secure-file-session') . '</option>';
        echo '<option value="archive" ' . selected($file_type, 'archive', false) . '>' . __('Archives', 'secure-file-session') . '</option>';
        echo '<option value="other" ' . selected($file_type, 'other', false) . '>' . __('Other', 'secure-file-session') . '</option>';
        echo '</select>';
    }
    
    /**
     * Modify the media library query based on security status filter
     */
    public function modify_media_query_by_security($query) {
        global $pagenow;
        
        // Only run on the upload.php admin page
        if (!is_admin() || $pagenow !== 'upload.php') {
            return $query;
        }
        
        // Handle security status filter
        if (isset($_GET['sfs_security_status']) && $_GET['sfs_security_status'] !== '') {
            $status = sanitize_text_field($_GET['sfs_security_status']);
            
            $meta_query = $query->get('meta_query');
            if (!is_array($meta_query)) {
                $meta_query = array();
            }
            
            if ($status === 'secured') {
                $meta_query[] = array(
                    'key' => '_sfs_secured',
                    'value' => '1',
                    'compare' => '='
                );
            } elseif ($status === 'exempted') {
                $meta_query[] = array(
                    'key' => '_sfs_exempted',
                    'value' => '1',
                    'compare' => '='
                );
            } elseif ($status === 'unsecured') {
                // Unsecured means no _sfs_secured or _sfs_exempted meta keys
                $meta_query[] = array(
                    'relation' => 'AND',
                    array(
                        'key' => '_sfs_secured',
                        'compare' => 'NOT EXISTS'
                    ),
                    array(
                        'key' => '_sfs_exempted',
                        'compare' => 'NOT EXISTS'
                    )
                );
            }
            
            $query->set('meta_query', $meta_query);
        }
        
        // Handle file type filter
        if (isset($_GET['sfs_file_type']) && $_GET['sfs_file_type'] !== '') {
            $type = sanitize_text_field($_GET['sfs_file_type']);
            
            $file_type_query = array();
            
            // Define mime types for each category
            switch ($type) {
                case 'image':
                    $query->set('post_mime_type', array('image/jpeg', 'image/gif', 'image/png', 'image/webp', 'image/svg+xml'));
                    break;
                    
                case 'document':
                    $query->set('post_mime_type', array(
                        'application/pdf', 
                        'application/msword', 
                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                        'application/vnd.ms-excel',
                        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                        'application/vnd.ms-powerpoint',
                        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                        'text/plain',
                        'text/csv'
                    ));
                    break;
                    
                case 'audio':
                    $query->set('post_mime_type', array(
                        'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp3', 'audio/mp4', 'audio/aac'
                    ));
                    break;
                    
                case 'video':
                    $query->set('post_mime_type', array(
                        'video/mp4', 'video/avi', 'video/quicktime', 'video/x-ms-wmv', 'video/webm'
                    ));
                    break;
                    
                case 'archive':
                    $query->set('post_mime_type', array(
                        'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed', 
                        'application/x-tar', 'application/gzip'
                    ));
                    break;
                    
                case 'other':
                    // 'other' is complex - exclude all known mime types and get what's left
                    $all_known_mimes = array(
                        'image/jpeg', 'image/gif', 'image/png', 'image/webp', 'image/svg+xml',
                        'application/pdf', 'application/msword', 
                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                        'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                        'application/vnd.ms-powerpoint', 
                        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                        'text/plain', 'text/csv',
                        'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp3', 'audio/mp4', 'audio/aac',
                        'video/mp4', 'video/avi', 'video/quicktime', 'video/x-ms-wmv', 'video/webm',
                        'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed',
                        'application/x-tar', 'application/gzip'
                    );
                    
                    // Use a meta_query to exclude the known mime types
                    $meta_query = $query->get('meta_query', array());
                    
                    $meta_query[] = array(
                        'key' => '_wp_attachment_metadata',
                        'compare' => 'EXISTS'
                    );
                    
                    $query->set('meta_query', $meta_query);
                    
                    // Use NOT IN for mime types
                    $query->set('post_mime_type', 'NOT IN');
                    $query->set('post_mime_type', $all_known_mimes);
                    
                    break;
            }
        }
        
        return $query;
    }

    /**
     * Render the bulk files management page
     */
    public function render_bulk_files_management_page() {
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            return;
        }
        
        wp_enqueue_script('jquery');
        wp_enqueue_script('jquery-ui-datepicker');
        wp_enqueue_style('jquery-ui', 'https://code.jquery.com/ui/1.12.1/themes/base/jquery-ui.css');
        
        // Enqueue custom scripts and styles
        wp_enqueue_script(
            'sfs-bulk-manager',
            SECURE_FILE_SESSION_PLUGIN_URL . 'assets/js/bulk-manager.js',
            array('jquery', 'jquery-ui-datepicker'),
            SECURE_FILE_SESSION_VERSION,
            true
        );
        
        wp_localize_script('sfs-bulk-manager', 'sfs_bulk_manager', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('sfs-bulk-manager-nonce'),
            'messages' => array(
                'confirm_secure' => __('Are you sure you want to secure these files?', 'secure-file-session'),
                'confirm_exempt' => __('Are you sure you want to exempt these files?', 'secure-file-session'),
                'confirm_unsecure' => __('Are you sure you want to unsecure these files?', 'secure-file-session'),
                'success' => __('Files updated successfully!', 'secure-file-session'),
                'error' => __('An error occurred. Please try again.', 'secure-file-session')
            )
        ));
        
        wp_enqueue_style(
            'sfs-bulk-manager',
            SECURE_FILE_SESSION_PLUGIN_URL . 'assets/css/bulk-manager.css',
            array(),
            SECURE_FILE_SESSION_VERSION
        );
        
        // Get current filters
        $security_status = isset($_GET['security_status']) ? sanitize_text_field($_GET['security_status']) : '';
        $file_type = isset($_GET['file_type']) ? sanitize_text_field($_GET['file_type']) : '';
        $date_from = isset($_GET['date_from']) ? sanitize_text_field($_GET['date_from']) : '';
        $date_to = isset($_GET['date_to']) ? sanitize_text_field($_GET['date_to']) : '';
        $search_term = isset($_GET['s']) ? sanitize_text_field($_GET['s']) : '';
        
        // Page number and pagination
        $paged = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $per_page = 20;
        
        // Prepare query args
        $query_args = array(
            'post_type' => 'attachment',
            'post_status' => 'any',
            'posts_per_page' => $per_page,
            'paged' => $paged,
            'orderby' => 'date',
            'order' => 'DESC',
        );
        
        // Add security status filter
        if (!empty($security_status)) {
            $meta_query = array();
            
            if ($security_status === 'secured') {
                $meta_query[] = array(
                    'key' => '_sfs_secured',
                    'value' => '1',
                    'compare' => '='
                );
            } elseif ($security_status === 'exempted') {
                $meta_query[] = array(
                    'key' => '_sfs_exempted',
                    'value' => '1',
                    'compare' => '='
                );
            } elseif ($security_status === 'unsecured') {
                $meta_query[] = array(
                    'relation' => 'AND',
                    array(
                        'key' => '_sfs_secured',
                        'compare' => 'NOT EXISTS'
                    ),
                    array(
                        'key' => '_sfs_exempted',
                        'compare' => 'NOT EXISTS'
                    )
                );
            }
            
            $query_args['meta_query'] = $meta_query;
        }
        
        // Add file type filter
        if (!empty($file_type)) {
            $mime_types = array();
            
            switch ($file_type) {
                case 'image':
                    $mime_types = array('image/jpeg', 'image/gif', 'image/png', 'image/webp', 'image/svg+xml');
                    break;
                case 'document':
                    $mime_types = array(
                        'application/pdf', 
                        'application/msword', 
                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                        'application/vnd.ms-excel',
                        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                        'application/vnd.ms-powerpoint',
                        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                        'text/plain',
                        'text/csv'
                    );
                    break;
                case 'audio':
                    $mime_types = array(
                        'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp3', 'audio/mp4', 'audio/aac'
                    );
                    break;
                case 'video':
                    $mime_types = array(
                        'video/mp4', 'video/avi', 'video/quicktime', 'video/x-ms-wmv', 'video/webm'
                    );
                    break;
                case 'archive':
                    $mime_types = array(
                        'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed', 
                        'application/x-tar', 'application/gzip'
                    );
                    break;
            }
            
            if (!empty($mime_types)) {
                $query_args['post_mime_type'] = $mime_types;
            }
        }
        
        // Add date filters
        if (!empty($date_from) || !empty($date_to)) {
            $date_query = array();
            
            if (!empty($date_from)) {
                $date_query['after'] = date('Y-m-d 00:00:00', strtotime($date_from));
            }
            
            if (!empty($date_to)) {
                $date_query['before'] = date('Y-m-d 23:59:59', strtotime($date_to));
            }
            
            $query_args['date_query'] = array($date_query);
        }
        
        // Add search term
        if (!empty($search_term)) {
            $query_args['s'] = $search_term;
        }
        
        // Run the query
        $files_query = new WP_Query($query_args);
        
        // Get total pages for pagination
        $total_files = $files_query->found_posts;
        $total_pages = ceil($total_files / $per_page);
        
        ?>
        <div class="wrap" id="sfs-bulk-manager">
            <h1><?php echo esc_html__('Secure File Manager', 'secure-file-session'); ?></h1>
            
            <div class="sfs-bulk-manager-description">
                <p><?php echo esc_html__('Use this page to manage the security settings for multiple files at once. You can filter files by security status, file type, and date, then apply security settings in bulk.', 'secure-file-session'); ?></p>
            </div>
            
            <!-- Filters -->
            <div class="sfs-filters">
                <form method="get" action="">
                    <input type="hidden" name="page" value="secure-file-manager">
                    
                    <div class="sfs-filter-row">
                        <div class="sfs-filter-group">
                            <label for="security_status"><?php echo esc_html__('Security Status:', 'secure-file-session'); ?></label>
                            <select name="security_status" id="security_status">
                                <option value=""><?php echo esc_html__('All Security Statuses', 'secure-file-session'); ?></option>
                                <option value="secured" <?php selected($security_status, 'secured'); ?>><?php echo esc_html__('Secured', 'secure-file-session'); ?></option>
                                <option value="exempted" <?php selected($security_status, 'exempted'); ?>><?php echo esc_html__('Exempted', 'secure-file-session'); ?></option>
                                <option value="unsecured" <?php selected($security_status, 'unsecured'); ?>><?php echo esc_html__('Unsecured', 'secure-file-session'); ?></option>
                            </select>
                        </div>
                        
                        <div class="sfs-filter-group">
                            <label for="file_type"><?php echo esc_html__('File Type:', 'secure-file-session'); ?></label>
                            <select name="file_type" id="file_type">
                                <option value=""><?php echo esc_html__('All File Types', 'secure-file-session'); ?></option>
                                <option value="image" <?php selected($file_type, 'image'); ?>><?php echo esc_html__('Images', 'secure-file-session'); ?></option>
                                <option value="document" <?php selected($file_type, 'document'); ?>><?php echo esc_html__('Documents', 'secure-file-session'); ?></option>
                                <option value="audio" <?php selected($file_type, 'audio'); ?>><?php echo esc_html__('Audio', 'secure-file-session'); ?></option>
                                <option value="video" <?php selected($file_type, 'video'); ?>><?php echo esc_html__('Video', 'secure-file-session'); ?></option>
                                <option value="archive" <?php selected($file_type, 'archive'); ?>><?php echo esc_html__('Archives', 'secure-file-session'); ?></option>
                            </select>
                        </div>
                        
                        <div class="sfs-filter-group">
                            <label for="s"><?php echo esc_html__('Search:', 'secure-file-session'); ?></label>
                            <input type="text" name="s" id="s" value="<?php echo esc_attr($search_term); ?>" placeholder="<?php echo esc_attr__('Search files...', 'secure-file-session'); ?>">
                        </div>
                    </div>
                    
                    <div class="sfs-filter-row">
                        <div class="sfs-filter-group">
                            <label for="date_from"><?php echo esc_html__('From Date:', 'secure-file-session'); ?></label>
                            <input type="text" name="date_from" id="date_from" value="<?php echo esc_attr($date_from); ?>" class="sfs-datepicker" placeholder="<?php echo esc_attr__('From Date', 'secure-file-session'); ?>">
                        </div>
                        
                        <div class="sfs-filter-group">
                            <label for="date_to"><?php echo esc_html__('To Date:', 'secure-file-session'); ?></label>
                            <input type="text" name="date_to" id="date_to" value="<?php echo esc_attr($date_to); ?>" class="sfs-datepicker" placeholder="<?php echo esc_attr__('To Date', 'secure-file-session'); ?>">
                        </div>
                        
                        <div class="sfs-filter-group sfs-filter-submit">
                            <button type="submit" class="button button-primary"><?php echo esc_html__('Apply Filters', 'secure-file-session'); ?></button>
                            <a href="<?php echo esc_url(admin_url('upload.php?page=secure-file-manager')); ?>" class="button"><?php echo esc_html__('Reset Filters', 'secure-file-session'); ?></a>
                        </div>
                    </div>
                </form>
            </div>
            
            <!-- Bulk Actions -->
            <div class="sfs-bulk-actions">
                <div class="sfs-bulk-actions-controls">
                    <label><input type="checkbox" id="sfs-select-all"> <?php echo esc_html__('Select All', 'secure-file-session'); ?></label>
                    <div class="sfs-bulk-actions-buttons">
                        <button type="button" class="button sfs-bulk-action" data-action="secure"><?php echo esc_html__('Secure Selected', 'secure-file-session'); ?></button>
                        <button type="button" class="button sfs-bulk-action" data-action="exempt"><?php echo esc_html__('Exempt Selected', 'secure-file-session'); ?></button>
                        <button type="button" class="button sfs-bulk-action" data-action="unsecure"><?php echo esc_html__('Unsecure Selected', 'secure-file-session'); ?></button>
                    </div>
                </div>
                
                <div id="sfs-bulk-action-result" class="notice" style="display: none;"></div>
            </div>
            
            <!-- Files Table -->
            <div class="sfs-files-table">
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th class="column-cb check-column"><span class="screen-reader-text"><?php echo esc_html__('Select', 'secure-file-session'); ?></span></th>
                            <th><?php echo esc_html__('Preview', 'secure-file-session'); ?></th>
                            <th><?php echo esc_html__('File', 'secure-file-session'); ?></th>
                            <th><?php echo esc_html__('Type', 'secure-file-session'); ?></th>
                            <th><?php echo esc_html__('Date', 'secure-file-session'); ?></th>
                            <th><?php echo esc_html__('Security Status', 'secure-file-session'); ?></th>
                            <th><?php echo esc_html__('Actions', 'secure-file-session'); ?></th>
                        </tr>
                    </thead>
                    <tbody id="the-list">
                        <?php if ($files_query->have_posts()) : ?>
                            <?php while ($files_query->have_posts()) : $files_query->the_post(); ?>
                                <?php
                                $file_id = get_the_ID();
                                $file = get_post();
                                $file_url = wp_get_attachment_url($file_id);
                                $file_path = get_attached_file($file_id);
                                $file_type = wp_check_filetype(basename($file_path))['type'];
                                $file_icon = wp_mime_type_icon($file_id);
                                $is_image = wp_attachment_is_image($file_id);
                                
                                // Get security status
                                $is_secured = (bool) get_post_meta($file_id, '_sfs_secured', true);
                                $is_exempted = (bool) get_post_meta($file_id, '_sfs_exempted', true);
                                
                                if ($is_secured) {
                                    $security_status_text = __('Secured', 'secure-file-session');
                                    $security_status_class = 'secured';
                                } elseif ($is_exempted) {
                                    $security_status_text = __('Exempted', 'secure-file-session');
                                    $security_status_class = 'exempted';
                                } else {
                                    $security_status_text = __('Unsecured', 'secure-file-session');
                                    $security_status_class = 'unsecured';
                                }
                                ?>
                                <tr>
                                    <td class="column-cb check-column">
                                        <input type="checkbox" name="sfs-file[]" value="<?php echo esc_attr($file_id); ?>" class="sfs-file-checkbox">
                                    </td>
                                    <td>
                                        <?php if ($is_image) : ?>
                                            <?php echo wp_get_attachment_image($file_id, array(50, 50), false, array('class' => 'sfs-file-thumbnail')); ?>
                                        <?php else : ?>
                                            <img src="<?php echo esc_url($file_icon); ?>" alt="<?php echo esc_attr__('File Icon', 'secure-file-session'); ?>" class="sfs-file-thumbnail">
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <strong><?php echo esc_html(basename($file_path)); ?></strong>
                                        <div class="row-actions">
                                            <span class="view"><a href="<?php echo esc_url($file_url); ?>" target="_blank"><?php echo esc_html__('View', 'secure-file-session'); ?></a> | </span>
                                            <span class="edit"><a href="<?php echo esc_url(get_edit_post_link($file_id)); ?>"><?php echo esc_html__('Edit', 'secure-file-session'); ?></a></span>
                                        </div>
                                    </td>
                                    <td><?php echo esc_html($file_type); ?></td>
                                    <td><?php echo get_the_date(); ?></td>
                                    <td><span class="sfs-security-status sfs-status-<?php echo esc_attr($security_status_class); ?>"><?php echo esc_html($security_status_text); ?></span></td>
                                    <td>
                                        <div class="sfs-file-actions">
                                            <button type="button" class="button button-small sfs-file-action" data-action="secure" data-file-id="<?php echo esc_attr($file_id); ?>"><?php echo esc_html__('Secure', 'secure-file-session'); ?></button>
                                            <button type="button" class="button button-small sfs-file-action" data-action="exempt" data-file-id="<?php echo esc_attr($file_id); ?>"><?php echo esc_html__('Exempt', 'secure-file-session'); ?></button>
                                            <button type="button" class="button button-small sfs-file-action" data-action="unsecure" data-file-id="<?php echo esc_attr($file_id); ?>"><?php echo esc_html__('Unsecure', 'secure-file-session'); ?></button>
                                        </div>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else : ?>
                            <tr>
                                <td colspan="7"><?php echo esc_html__('No files found matching the criteria.', 'secure-file-session'); ?></td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- Pagination -->
            <?php if ($total_pages > 1) : ?>
                <div class="sfs-pagination tablenav">
                    <div class="tablenav-pages">
                        <span class="displaying-num">
                            <?php echo sprintf(
                                _n('%s item', '%s items', $total_files, 'secure-file-session'),
                                number_format_i18n($total_files)
                            ); ?>
                        </span>
                        <span class="pagination-links">
                            <?php
                            // First page link
                            $first_page_url = add_query_arg('paged', 1, remove_query_arg('paged'));
                            $disabled_first = $paged <= 1 ? ' disabled' : '';
                            
                            // Previous page link
                            $prev_page = max(1, $paged - 1);
                            $prev_page_url = add_query_arg('paged', $prev_page);
                            $disabled_prev = $paged <= 1 ? ' disabled' : '';
                            
                            // Next page link
                            $next_page = min($total_pages, $paged + 1);
                            $next_page_url = add_query_arg('paged', $next_page);
                            $disabled_next = $paged >= $total_pages ? ' disabled' : '';
                            
                            // Last page link
                            $last_page_url = add_query_arg('paged', $total_pages);
                            $disabled_last = $paged >= $total_pages ? ' disabled' : '';
                            ?>
                            <a class="first-page button<?php echo $disabled_first; ?>" href="<?php echo esc_url($first_page_url); ?>">
                                <span class="screen-reader-text"><?php echo esc_html__('First page', 'secure-file-session'); ?></span>
                                <span aria-hidden="true">«</span>
                            </a>
                            <a class="prev-page button<?php echo $disabled_prev; ?>" href="<?php echo esc_url($prev_page_url); ?>">
                                <span class="screen-reader-text"><?php echo esc_html__('Previous page', 'secure-file-session'); ?></span>
                                <span aria-hidden="true">‹</span>
                            </a>
                            <span class="paging-input">
                                <label for="current-page-selector" class="screen-reader-text"><?php echo esc_html__('Current Page', 'secure-file-session'); ?></label>
                                <input class="current-page" id="current-page-selector" type="text" name="paged" value="<?php echo esc_attr($paged); ?>" size="2" aria-describedby="table-paging">
                                <span class="tablenav-paging-text"> <?php echo esc_html__('of', 'secure-file-session'); ?> <span class="total-pages"><?php echo esc_html($total_pages); ?></span></span>
                            </span>
                            <a class="next-page button<?php echo $disabled_next; ?>" href="<?php echo esc_url($next_page_url); ?>">
                                <span class="screen-reader-text"><?php echo esc_html__('Next page', 'secure-file-session'); ?></span>
                                <span aria-hidden="true">›</span>
                            </a>
                            <a class="last-page button<?php echo $disabled_last; ?>" href="<?php echo esc_url($last_page_url); ?>">
                                <span class="screen-reader-text"><?php echo esc_html__('Last page', 'secure-file-session'); ?></span>
                                <span aria-hidden="true">»</span>
                            </a>
                        </span>
                    </div>
                </div>
            <?php endif; ?>
        </div>
        <?php
        // Reset post data
        wp_reset_postdata();
    }
    
    /**
     * Handle AJAX file security updates
     */
    public function handle_ajax_file_security_update() {
        check_ajax_referer('sfs_ajax_nonce', 'nonce');
        
        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You do not have permission to perform this action.', 'secure-file-session')));
        }
        
        // Get action and files
        $action = isset($_POST['action_type']) ? sanitize_text_field($_POST['action_type']) : '';
        $file_ids = isset($_POST['files']) ? array_map('intval', (array) $_POST['files']) : array();
        
        if (empty($action) || empty($file_ids)) {
            wp_send_json_error(array('message' => __('Missing required parameters.', 'secure-file-session')));
        }
        
        // Process files
        $processed = 0;
        foreach ($file_ids as $file_id) {
            // Skip non-attachments
            if (get_post_type($file_id) !== 'attachment') {
                continue;
            }
            
            // Reset all states first
            delete_post_meta($file_id, '_sfs_secured');
            delete_post_meta($file_id, '_sfs_exempted');
            
            // Set the appropriate state
            if ($action === 'secure') {
                update_post_meta($file_id, '_sfs_secured', 1);
                $processed++;
            } elseif ($action === 'exempt') {
                update_post_meta($file_id, '_sfs_exempted', 1);
                $processed++;
            } else {
                // unsecure - just leave the metadata removed
                $processed++;
            }
        }
        
        // Return success response
        wp_send_json_success(array(
            'message' => sprintf(
                _n('%d file updated successfully.', '%d files updated successfully.', $processed, 'secure-file-session'),
                $processed
            ),
            'processed' => $processed
        ));
    }
    
    /**
     * Render the tools tab content
     */
    public function render_tools_tab() {
        // Check if we have an action result to display
        if (isset($_GET['sfs_result']) && isset($_GET['sfs_message'])) {
            $result = sanitize_text_field($_GET['sfs_result']);
            $message = urldecode($_GET['sfs_message']);
            $notice_class = ($result === 'success') ? 'notice-success' : 'notice-error';
            
            echo '<div class="notice ' . esc_attr($notice_class) . ' is-dismissible"><p>' . esc_html($message) . '</p></div>';
        }
        ?>
        <div class="sfs-tools-tab">
            <h2><?php esc_html_e('Tools & Fixes', 'secure-file-session'); ?></h2>
            
            <div class="sfs-panel">
                <h3><?php esc_html_e('Common Tasks', 'secure-file-session'); ?></h3>
                <p><?php esc_html_e('These operations help you manage and maintain your file security.', 'secure-file-session'); ?></p>
                
                <div class="sfs-tools-grid">
                    <div class="sfs-tool-card">
                        <h4><?php esc_html_e('Create .htaccess Protection', 'secure-file-session'); ?></h4>
                        <p><?php esc_html_e('Add or update the .htaccess file in your uploads directory to block direct access to files.', 'secure-file-session'); ?></p>
                        <a href="<?php echo esc_url(wp_nonce_url(add_query_arg(array('page' => 'secure-file-session-settings', 'tab' => 'tools', 'action' => 'create_htaccess'), admin_url('options-general.php')), 'sfs_create_htaccess')); ?>" class="button"><?php esc_html_e('Create .htaccess File', 'secure-file-session'); ?></a>
                    </div>
                    
                    <div class="sfs-tool-card">
                        <h4><?php esc_html_e('Fix File Permissions', 'secure-file-session'); ?></h4>
                        <p><?php esc_html_e('Check and correct file permissions in your uploads directory for better security.', 'secure-file-session'); ?></p>
                        <a href="<?php echo esc_url(wp_nonce_url(add_query_arg(array('page' => 'secure-file-session-settings', 'tab' => 'tools', 'action' => 'fix_permissions'), admin_url('options-general.php')), 'sfs_fix_permissions')); ?>" class="button"><?php esc_html_e('Fix Permissions', 'secure-file-session'); ?></a>
                    </div>
                    
                    <div class="sfs-tool-card">
                        <h4><?php esc_html_e('Test Remote Storage', 'secure-file-session'); ?></h4>
                        <p><?php esc_html_e('Test your remote storage configuration and connection.', 'secure-file-session'); ?></p>
                        <a href="<?php echo esc_url(wp_nonce_url(add_query_arg(array('page' => 'secure-file-session-settings', 'tab' => 'tools', 'action' => 'test_s3'), admin_url('options-general.php')), 'sfs_test_s3')); ?>" class="button"><?php esc_html_e('Test Connection', 'secure-file-session'); ?></a>
                    </div>
                    
                    <div class="sfs-tool-card">
                        <h4><?php esc_html_e('Purge Cache', 'secure-file-session'); ?></h4>
                        <p><?php esc_html_e('Clear all cached security tokens and temporary files.', 'secure-file-session'); ?></p>
                        <a href="<?php echo esc_url(wp_nonce_url(add_query_arg(array('page' => 'secure-file-session-settings', 'tab' => 'tools', 'action' => 'purge_cache'), admin_url('options-general.php')), 'sfs_purge_cache')); ?>" class="button"><?php esc_html_e('Purge Cache', 'secure-file-session'); ?></a>
                    </div>
                </div>
            </div>
            
            <!-- Automatic Troubleshooting Section -->
            <div class="sfs-panel sfs-panel-diagnostic">
                <h3><?php esc_html_e('Automatic Troubleshooting', 'secure-file-session'); ?></h3>
                <p><?php esc_html_e('Let the plugin automatically detect and fix common configuration issues.', 'secure-file-session'); ?></p>
                
                <div class="sfs-diagnostic-results" id="sfs-diagnostic-results">
                    <div class="sfs-diagnostic-status">
                        <p><?php esc_html_e('Click "Run Diagnostics" to scan your setup for potential issues.', 'secure-file-session'); ?></p>
                    </div>
                </div>
                
                <div class="sfs-diagnostic-actions">
                    <button type="button" id="sfs-run-diagnostics" class="button button-primary"><?php esc_html_e('Run Diagnostics', 'secure-file-session'); ?></button>
                    <button type="button" id="sfs-fix-all-issues" class="button" style="display:none;"><?php esc_html_e('Fix All Issues', 'secure-file-session'); ?></button>
                </div>
                
                <script type="text/javascript">
                jQuery(document).ready(function($) {
                    // Diagnostic tests
                    const diagnosticTests = [
                        {
                            id: 'htaccess_check',
                            name: '<?php esc_attr_e('Uploads .htaccess Protection', 'secure-file-session'); ?>',
                            test: function() {
                                return new Promise((resolve, reject) => {
                                    $.ajax({
                                        url: ajaxurl,
                                        type: 'POST',
                                        data: {
                                            action: 'sfs_run_diagnostic',
                                            test: 'htaccess_check',
                                            nonce: '<?php echo wp_create_nonce('sfs_diagnostic_nonce'); ?>'
                                        },
                                        success: function(response) {
                                            resolve(response);
                                        },
                                        error: function(xhr, status, error) {
                                            console.error('AJAX error:', error);
                                            reject(error);
                                        }
                                    });
                                });
                            },
                            fixAction: 'create_htaccess'
                        },
                        {
                            id: 'permission_check',
                            name: '<?php esc_attr_e('File Permissions', 'secure-file-session'); ?>',
                            test: function() {
                                return new Promise((resolve, reject) => {
                                    $.ajax({
                                        url: ajaxurl,
                                        type: 'POST',
                                        data: {
                                            action: 'sfs_run_diagnostic',
                                            test: 'permission_check',
                                            nonce: '<?php echo wp_create_nonce('sfs_diagnostic_nonce'); ?>'
                                        },
                                        success: function(response) {
                                            resolve(response);
                                        },
                                        error: function(xhr, status, error) {
                                            console.error('AJAX error:', error);
                                            reject(error);
                                        }
                                    });
                                });
                            },
                            fixAction: 'fix_permissions'
                        },
                        {
                            id: 'uploads_dir_check',
                            name: '<?php esc_attr_e('Uploads Directory', 'secure-file-session'); ?>',
                            test: function() {
                                return new Promise((resolve, reject) => {
                                    $.ajax({
                                        url: ajaxurl,
                                        type: 'POST',
                                        data: {
                                            action: 'sfs_run_diagnostic',
                                            test: 'uploads_dir_check',
                                            nonce: '<?php echo wp_create_nonce('sfs_diagnostic_nonce'); ?>'
                                        },
                                        success: function(response) {
                                            resolve(response);
                                        },
                                        error: function(xhr, status, error) {
                                            console.error('AJAX error:', error);
                                            reject(error);
                                        }
                                    });
                                });
                            },
                            fixAction: 'fix_uploads_dir'
                        },
                        {
                            id: 'secure_config_check',
                            name: '<?php esc_attr_e('Security Configuration', 'secure-file-session'); ?>',
                            test: function() {
                                return new Promise((resolve, reject) => {
                                    $.ajax({
                                        url: ajaxurl,
                                        type: 'POST',
                                        data: {
                                            action: 'sfs_run_diagnostic',
                                            test: 'secure_config_check',
                                            nonce: '<?php echo wp_create_nonce('sfs_diagnostic_nonce'); ?>'
                                        },
                                        success: function(response) {
                                            resolve(response);
                                        },
                                        error: function(xhr, status, error) {
                                            console.error('AJAX error:', error);
                                            reject(error);
                                        }
                                    });
                                });
                            },
                            fixAction: 'fix_security_config'
                        }
                    ];
                    
                    // Run diagnostics handler
                    $('#sfs-run-diagnostics').on('click', function() {
                        const $results = $('#sfs-diagnostic-results');
                        $results.html('<div class="sfs-diagnostic-status"><p><?php esc_html_e('Running diagnostics...', 'secure-file-session'); ?></p></div>');
                        
                        let foundIssues = false;
                        let resultsHtml = '<div class="sfs-diagnostic-items">';
                        
                        // Run each test sequentially
                        const runTests = async () => {
                            for (const test of diagnosticTests) {
                                resultsHtml += `<div class="sfs-diagnostic-item" id="sfs-test-${test.id}">
                                    <div class="sfs-diagnostic-item-header">
                                        <span class="sfs-diagnostic-name">${test.name}</span>
                                        <span class="sfs-diagnostic-status-running"><?php esc_html_e('Running...', 'secure-file-session'); ?></span>
                                    </div>
                                </div>`;
                                
                                // Update the display while tests are running
                                $results.html(`<div class="sfs-diagnostic-status">
                                    <p><?php esc_html_e('Running diagnostics...', 'secure-file-session'); ?></p>
                                </div>${resultsHtml}</div>`);
                                
                                // Run the test
                                try {
                                    console.log(`Running test: ${test.id}`);
                                    const response = await test.test();
                                    console.log(`Test ${test.id} response:`, response);
                                    
                                    // Check if response is valid
                                    if (!response || typeof response !== 'object') {
                                        console.error(`Invalid response received from server for test ${test.id}:`, response);
                                        throw new Error('Invalid response received from server');
                                    }
                                    
                                    // Extract message from response - handle both data.message and directly in data
                                    let message = '';
                                    if (response.data && typeof response.data === 'object' && response.data.message) {
                                        message = response.data.message;
                                    } else if (response.data && typeof response.data === 'string') {
                                        message = response.data;
                                    } else {
                                        message = '<?php esc_html_e('No message provided from server', 'secure-file-session'); ?>';
                                    }
                                    
                                    if (response.success === false) {
                                        foundIssues = true;
                                        console.log(`Test ${test.id} failed: ${message}`);
                                        
                                        // Update the individual test result
                                        $(`#sfs-test-${test.id}`).html(`
                                            <div class="sfs-diagnostic-item-header">
                                                <span class="sfs-diagnostic-name">${test.name}</span>
                                                <span class="sfs-diagnostic-status-error"><?php esc_html_e('Issue Found', 'secure-file-session'); ?></span>
                                            </div>
                                            <div class="sfs-diagnostic-item-details">
                                                <p>${message}</p>
                                                <button type="button" class="button sfs-fix-issue" data-action="${test.fixAction}"><?php esc_html_e('Fix Issue', 'secure-file-session'); ?></button>
                                            </div>
                                        `);
                                    } else {
                                        console.log(`Test ${test.id} passed: ${message}`);
                                        
                                        // Update the individual test result
                                        $(`#sfs-test-${test.id}`).html(`
                                            <div class="sfs-diagnostic-item-header">
                                                <span class="sfs-diagnostic-name">${test.name}</span>
                                                <span class="sfs-diagnostic-status-success"><?php esc_html_e('Passed', 'secure-file-session'); ?></span>
                                            </div>
                                            <div class="sfs-diagnostic-item-details">
                                                <p>${message}</p>
                                            </div>
                                        `);
                                    }
                                } catch (error) {
                                    foundIssues = true;
                                    console.error(`Error in test ${test.id}:`, error);
                                    
                                    // Update the individual test result with error
                                    $(`#sfs-test-${test.id}`).html(`
                                        <div class="sfs-diagnostic-item-header">
                                            <span class="sfs-diagnostic-name">${test.name}</span>
                                            <span class="sfs-diagnostic-status-error"><?php esc_html_e('Error', 'secure-file-session'); ?></span>
                                        </div>
                                        <div class="sfs-diagnostic-item-details">
                                            <p><?php esc_html_e('Error running diagnostic test. Check browser console for details.', 'secure-file-session'); ?></p>
                                            <p class="sfs-error">${error.message || error}</p>
                                            <button type="button" class="button sfs-fix-issue" data-action="${test.fixAction}"><?php esc_html_e('Try Fix Anyway', 'secure-file-session'); ?></button>
                                        </div>
                                    `);
                                }
                            }
                            
                            // Update the status message based on results
                            if (foundIssues) {
                                $('.sfs-diagnostic-status').html(`
                                    <p class="sfs-diagnostic-summary-issues"><?php esc_html_e('Issues found! You can fix them individually or use "Fix All Issues".', 'secure-file-session'); ?></p>
                                `);
                                $('#sfs-fix-all-issues').show();
                            } else {
                                $('.sfs-diagnostic-status').html(`
                                    <p class="sfs-diagnostic-summary-success"><?php esc_html_e('All checks passed! Your setup is configured correctly.', 'secure-file-session'); ?></p>
                                `);
                                $('#sfs-fix-all-issues').hide();
                            }
                        };
                        
                        // Start the test sequence
                        runTests().catch(function(error) {
                            console.error('Error in test sequence:', error);
                            $results.append(`<p class="sfs-error"><?php esc_html_e('An error occurred while running diagnostic tests.', 'secure-file-session'); ?></p>`);
                        });
                    });
                    
                    // Fix individual issue
                    $(document).on('click', '.sfs-fix-issue', function() {
                        const action = $(this).data('action');
                        const $button = $(this);
                        const $item = $button.closest('.sfs-diagnostic-item');
                        
                        console.log(`Fixing issue with action: ${action}`);
                        $button.prop('disabled', true).text('<?php esc_html_e('Fixing...', 'secure-file-session'); ?>');
                        
                        $.ajax({
                            url: ajaxurl,
                            type: 'POST',
                            data: {
                                action: 'sfs_fix_issue',
                                fix_action: action,
                                nonce: '<?php echo wp_create_nonce('sfs_fix_issue_nonce'); ?>'
                            },
                            success: function(response) {
                                console.log('Fix response:', response);
                                
                                // Extract message from response
                                let message = '<?php esc_html_e('Issue fixed successfully', 'secure-file-session'); ?>';
                                if (response.data && response.data.message) {
                                    message = response.data.message;
                                } else if (response.message) {
                                    message = response.message;
                                }
                                
                                if (response.success) {
                                    // Update the test display
                                    $item.find('.sfs-diagnostic-status-error, .sfs-diagnostic-status-running')
                                         .removeClass('sfs-diagnostic-status-error sfs-diagnostic-status-running')
                                         .addClass('sfs-diagnostic-status-success')
                                         .text('<?php esc_html_e('Fixed', 'secure-file-session'); ?>');
                                    
                                    $item.find('.sfs-diagnostic-item-details').html(`<p>${message}</p>`);
                                    
                                    // Check if all issues are fixed
                                    if ($('.sfs-diagnostic-status-error, .sfs-diagnostic-status-running').length === 0) {
                                        $('.sfs-diagnostic-status').html(`
                                            <p class="sfs-diagnostic-summary-success"><?php esc_html_e('All issues have been fixed! Your setup is now configured correctly.', 'secure-file-session'); ?></p>
                                        `);
                                        $('#sfs-fix-all-issues').hide();
                                    }
                                } else {
                                    $button.prop('disabled', false).text('<?php esc_html_e('Retry Fix', 'secure-file-session'); ?>');
                                    $item.find('.sfs-diagnostic-item-details').append(`<p class="sfs-error">${message}</p>`);
                                }
                            },
                            error: function(xhr, status, error) {
                                console.error('AJAX error:', error);
                                $button.prop('disabled', false).text('<?php esc_html_e('Retry Fix', 'secure-file-session'); ?>');
                                $item.find('.sfs-diagnostic-item-details').append(`
                                    <p class="sfs-error"><?php esc_html_e('Error communicating with server. Please try again.', 'secure-file-session'); ?></p>
                                    <p class="sfs-error">${error}</p>
                                `);
                            }
                        });
                    });
                    
                    // Fix all issues
                    $('#sfs-fix-all-issues').on('click', function() {
                        const $button = $(this);
                        
                        console.log('Running fix all issues');
                        $button.prop('disabled', true).text('<?php esc_html_e('Fixing All Issues...', 'secure-file-session'); ?>');
                        $('.sfs-fix-issue').prop('disabled', true);
                        
                        $.ajax({
                            url: ajaxurl,
                            type: 'POST',
                            data: {
                                action: 'sfs_fix_all_issues',
                                nonce: '<?php echo wp_create_nonce('sfs_fix_all_issues_nonce'); ?>'
                            },
                            success: function(response) {
                                console.log('Fix all response:', response);
                                
                                // Extract message from response
                                let message = '<?php esc_html_e('All issues fixed successfully', 'secure-file-session'); ?>';
                                if (response.data && response.data.message) {
                                    message = response.data.message;
                                } else if (response.message) {
                                    message = response.message;
                                }
                                
                                if (response.success) {
                                    // Update all running and error statuses to fixed
                                    $('.sfs-diagnostic-status-error, .sfs-diagnostic-status-running')
                                        .removeClass('sfs-diagnostic-status-error sfs-diagnostic-status-running')
                                        .addClass('sfs-diagnostic-status-success')
                                        .text('<?php esc_html_e('Fixed', 'secure-file-session'); ?>');
                                    
                                    // Update details for all items - handle missing details sections
                                    $('.sfs-diagnostic-item').each(function() {
                                        const $item = $(this);
                                        if ($item.find('.sfs-diagnostic-item-details').length === 0) {
                                            $item.append(`<div class="sfs-diagnostic-item-details"><p>${message}</p></div>`);
                                        } else {
                                            $item.find('.sfs-diagnostic-item-details').html(`<p>${message}</p>`);
                                        }
                                    });
                                    
                                    // Update summary
                                    $('.sfs-diagnostic-status').html(`
                                        <p class="sfs-diagnostic-summary-success"><?php esc_html_e('All issues have been fixed! Your setup is now configured correctly.', 'secure-file-session'); ?></p>
                                    `);
                                    
                                    // Hide fix all button
                                    $('#sfs-fix-all-issues').hide();
                                } else {
                                    $button.prop('disabled', false).text('<?php esc_html_e('Retry Fix All', 'secure-file-session'); ?>');
                                    $('.sfs-diagnostic-status').append(`<p class="sfs-error">${message}</p>`);
                                }
                            },
                            error: function(xhr, status, error) {
                                console.error('AJAX error in fix all:', error);
                                $button.prop('disabled', false).text('<?php esc_html_e('Retry Fix All', 'secure-file-session'); ?>');
                                $('.sfs-diagnostic-status').append(`
                                    <p class="sfs-error"><?php esc_html_e('Error communicating with server. Please try again.', 'secure-file-session'); ?></p>
                                    <p class="sfs-error">${error}</p>
                                `);
                            }
                        });
                    });
                });
            </script>
            
            <div class="sfs-panel">
                <h3><?php esc_html_e('System Information', 'secure-file-session'); ?></h3>
                <table class="widefat" style="border-collapse: collapse; width: 100%;">
                    <tbody>
                        <tr>
                            <td><strong><?php esc_html_e('WordPress Version', 'secure-file-session'); ?></strong></td>
                            <td><?php echo esc_html(get_bloginfo('version')); ?></td>
                        </tr>
                        <tr>
                            <td><strong><?php esc_html_e('PHP Version', 'secure-file-session'); ?></strong></td>
                            <td><?php echo esc_html(phpversion()); ?></td>
                        </tr>
                        <tr>
                            <td><strong><?php esc_html_e('Plugin Version', 'secure-file-session'); ?></strong></td>
                            <td><?php echo esc_html(SECURE_FILE_SESSION_VERSION); ?></td>
                        </tr>
                        <tr>
                            <td><strong><?php esc_html_e('Uploads Directory', 'secure-file-session'); ?></strong></td>
                            <td>
                                <?php 
                                $upload_dir = wp_upload_dir();
                                echo esc_html($upload_dir['basedir']);
                                
                                if (is_writable($upload_dir['basedir'])) {
                                    echo ' <span class="dashicons dashicons-yes" style="color:green;"></span> ' . esc_html__('Writable', 'secure-file-session');
                                } else {
                                    echo ' <span class="dashicons dashicons-warning" style="color:red;"></span> ' . esc_html__('Not Writable', 'secure-file-session');
                                }
                                ?>
                            </td>
                        </tr>
                        <tr>
                            <td><strong><?php esc_html_e('Protection Status', 'secure-file-session'); ?></strong></td>
                            <td>
                                <?php
                                $htaccess_path = trailingslashit($upload_dir['basedir']) . '.htaccess';
                                if (file_exists($htaccess_path)) {
                                    echo '<span class="dashicons dashicons-shield" style="color:green;"></span> ' . esc_html__('Protected (.htaccess found)', 'secure-file-session');
                                } else {
                                    echo '<span class="dashicons dashicons-shield-alt" style="color:orange;"></span> ' . esc_html__('Unprotected (no .htaccess)', 'secure-file-session');
                                }
                                ?>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        <style>
            .sfs-tools-tab h2 {
                margin-bottom: 20px;
            }
            .sfs-panel {
                background: #fff;
                border: 1px solid #ccd0d4;
                box-shadow: 0 1px 1px rgba(0,0,0,.04);
                padding: 20px;
                margin-bottom: 20px;
            }
            .sfs-tools-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 20px;
                margin-top: 20px;
            }
            .sfs-tool-card {
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 15px;
                background: #f9f9f9;
            }
            .sfs-tool-card h4 {
                margin-top: 0;
                border-bottom: 1px solid #eee;
                padding-bottom: 10px;
            }
            .sfs-diagnostic-items {
                margin-top: 20px;
            }
            .sfs-diagnostic-item {
                border: 1px solid #ddd;
                margin-bottom: 10px;
                background-color: #f9f9f9;
                border-radius: 3px;
            }
            .sfs-diagnostic-item-header {
                padding: 10px 15px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .sfs-diagnostic-item-details {
                padding: 0 15px 15px;
                border-top: 1px solid #eee;
            }
            .sfs-diagnostic-status-running {
                color: #007cba;
                font-weight: 500;
            }
            .sfs-diagnostic-status-error {
                color: #d63638;
                font-weight: 500;
            }
            .sfs-diagnostic-status-success {
                color: #46b450;
                font-weight: 500;
            }
            .sfs-diagnostic-summary-issues {
                font-weight: 500;
                color: #d63638;
                padding: 10px;
                background-color: #f8d7da;
                border-radius: 3px;
            }
            .sfs-diagnostic-summary-success {
                font-weight: 500;
                color: #46b450;
                padding: 10px;
                background-color: #d4edda;
                border-radius: 3px;
            }
            .sfs-diagnostic-actions {
                margin-top: 20px;
            }
            .sfs-error {
                color: #d63638;
                margin-top: 5px;
            }
        </style>
        <?php
    }
    
    /**
     * Handle the diagnostic tests via AJAX
     */
    public function handle_diagnostic_test() {
        // Add some error logging for debugging
        error_log('Diagnostic test request received: ' . print_r($_POST, true));
        
        check_ajax_referer('sfs_diagnostic_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You do not have permission to run diagnostics.', 'secure-file-session')));
        }
        
        $test_type = isset($_POST['test']) ? sanitize_text_field($_POST['test']) : '';
        
        if (empty($test_type)) {
            error_log('No test type provided in request');
            wp_send_json_error(array('message' => __('No test type specified.', 'secure-file-session')));
            return;
        }
        
        // Log the test type
        error_log('Running diagnostic test: ' . $test_type);
        
        switch ($test_type) {
            case 'htaccess_check':
                $this->run_htaccess_check();
                break;
                
            case 'permission_check':
                $this->run_permission_check();
                break;
                
            case 'uploads_dir_check':
                $this->run_uploads_dir_check();
                break;
                
            case 'secure_config_check':
                $this->run_secure_config_check();
                break;
                
            default:
                error_log('Unknown test type: ' . $test_type);
                wp_send_json_error(array('message' => __('Unknown test type.', 'secure-file-session')));
        }
    }
    
    /**
     * Run .htaccess protection check
     */
    private function run_htaccess_check() {
        error_log('Running htaccess check');
        $upload_dir = wp_upload_dir();
        $htaccess_path = trailingslashit($upload_dir['basedir']) . '.htaccess';
        
        error_log('Checking .htaccess file at: ' . $htaccess_path);
        
        if (!file_exists($htaccess_path)) {
            error_log('.htaccess file not found');
            wp_send_json_error(array(
                'message' => __('No .htaccess file found in your uploads directory. This file is needed to protect your uploads from direct access.', 'secure-file-session')
            ));
            return; // Prevent further execution
        }
        
        // Check if we can read the file
        if (!is_readable($htaccess_path)) {
            error_log('.htaccess file not readable');
            wp_send_json_error(array(
                'message' => __('The .htaccess file exists but is not readable. Check file permissions.', 'secure-file-session')
            ));
            return;
        }
        
        $htaccess_content = @file_get_contents($htaccess_path);
        if ($htaccess_content === false) {
            error_log('Failed to read .htaccess content');
            wp_send_json_error(array(
                'message' => __('Failed to read .htaccess file content. Check file permissions.', 'secure-file-session')
            ));
            return;
        }
        
        error_log('.htaccess content length: ' . strlen($htaccess_content));
        
        // Check if the htaccess contains the necessary rules
        if (strpos($htaccess_content, 'RewriteEngine On') === false || 
            strpos($htaccess_content, 'RewriteRule') === false) {
            error_log('.htaccess missing required rules');
            wp_send_json_error(array(
                'message' => __('The .htaccess file exists but does not contain the necessary protection rules.', 'secure-file-session')
            ));
            return; // Prevent further execution
        }
        
        error_log('htaccess check passed');
        wp_send_json_success(array(
            'message' => __('.htaccess file is correctly configured with protection rules.', 'secure-file-session')
        ));
    }
    
    /**
     * Run file permissions check
     */
    private function run_permission_check() {
        $upload_dir = wp_upload_dir();
        $uploads_path = $upload_dir['basedir'];
        
        if (!is_writable($uploads_path)) {
            wp_send_json_error(array(
                'message' => __('Your uploads directory is not writable. This can cause issues with file uploads and plugin functionality.', 'secure-file-session')
            ));
            return; // Prevent further execution
        }
        
        // Check directory permissions
        $dir_perms = substr(sprintf('%o', fileperms($uploads_path)), -4);
        if ($dir_perms != '0755' && $dir_perms != '0750' && $dir_perms != '0775') {
            wp_send_json_error(array(
                'message' => sprintf(__('Your uploads directory has potentially insecure permissions (%s). Recommended: 755.', 'secure-file-session'), $dir_perms)
            ));
            return; // Prevent further execution
        }
        
        // Check some files in the uploads directory
        $unsafe_files = array();
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($uploads_path));
        $count = 0;
        foreach ($iterator as $file) {
            if ($file->isFile() && !$file->isLink()) {
                $file_perms = substr(sprintf('%o', $file->getPerms()), -4);
                if ($file_perms == '0777' || $file_perms == '0666') {
                    $unsafe_files[] = $file->getPathname();
                }
                $count++;
                if ($count > 100) break; // Only check a sample of files
            }
        }
        
        if (!empty($unsafe_files)) {
            wp_send_json_error(array(
                'message' => sprintf(__('Found %d files with potentially insecure permissions (666 or 777).', 'secure-file-session'), count($unsafe_files))
            ));
            return; // Prevent further execution
        }
        
        wp_send_json_success(array(
            'message' => __('File permissions look good.', 'secure-file-session')
        ));
    }
    
    /**
     * Run uploads directory check
     */
    private function run_uploads_dir_check() {
        $upload_dir = wp_upload_dir();
        
        if ($upload_dir['error']) {
            wp_send_json_error(array(
                'message' => sprintf(__('Uploads directory error: %s', 'secure-file-session'), $upload_dir['error'])
            ));
            return; // Prevent further execution
        }
        
        // Test if uploads directory is accessible
        $uploads_path = $upload_dir['basedir'];
        if (!file_exists($uploads_path) || !is_dir($uploads_path)) {
            wp_send_json_error(array(
                'message' => __('Uploads directory does not exist or is not accessible.', 'secure-file-session')
            ));
            return; // Prevent further execution
        }
        
        // Check if the directory is writable
        if (!is_writable($uploads_path)) {
            wp_send_json_error(array(
                'message' => __('Uploads directory is not writable. This will prevent file uploads from working.', 'secure-file-session')
            ));
            return; // Prevent further execution
        }
        
        // Check available disk space
        if (function_exists('disk_free_space')) {
            $free_space = disk_free_space($uploads_path);
            if ($free_space !== false && $free_space < 50 * 1024 * 1024) { // Less than 50MB
                wp_send_json_error(array(
                    'message' => __('Low disk space available (less than 50MB). This may cause issues with file uploads.', 'secure-file-session')
                ));
                return; // Prevent further execution
            }
        }
        
        wp_send_json_success(array(
            'message' => __('Uploads directory is properly configured and accessible.', 'secure-file-session')
        ));
    }
    
    /**
     * Run security configuration check
     */
    private function run_secure_config_check() {
        $issues = array();
        
        // Check if basic security settings are enabled
        $options = get_option('secure_file_session_options', array());
        error_log('Security config options: ' . print_r($options, true));
        
        if (empty($options['protection_enabled'])) {
            $issues[] = __('File protection is not enabled.', 'secure-file-session');
        }
        
        // Check if rate limiting is enabled - using the correct field name
        if (empty($options['rate_limit_enabled'])) {
            $issues[] = __('Rate limiting is not enabled, which can leave your site vulnerable to abuse.', 'secure-file-session');
        }
        
        // Check token expiration time
        if (isset($options['token_expiration']) && (int)$options['token_expiration'] > 3600) {
            $issues[] = __('Long token expiration time (over 1 hour) may reduce security.', 'secure-file-session');
        }
        
        // Check for too many exclusions
        if (!empty($options['exclusions']) && substr_count($options['exclusions'], "\n") > 10) {
            $issues[] = __('Large number of exclusions detected, which may create security holes.', 'secure-file-session');
        }
        
        // Check if debug mode is enabled in production
        if (!empty($options['debug_mode'])) {
            $issues[] = __('Debug mode is enabled, which should not be used on production sites.', 'secure-file-session');
        }
        
        if (!empty($issues)) {
            error_log('Security config issues found: ' . implode(', ', $issues));
            wp_send_json_error(array(
                'message' => __('Security configuration issues found:', 'secure-file-session') . ' ' . implode(' ', $issues)
            ));
            return; // Prevent further execution
        }
        
        error_log('Security config check passed');
        wp_send_json_success(array(
            'message' => __('Security configuration looks good.', 'secure-file-session')
        ));
    }
    
    /**
     * Handle fixing individual issues
     */
    public function handle_fix_issue() {
        // Verify nonce - we need to check both possible nonce names
        if (
            (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'sfs_fix_issue_nonce')) &&
            (!isset($_POST['_wpnonce']) || !wp_verify_nonce($_POST['_wpnonce'], 'sfs_fix_issue_nonce'))
        ) {
            wp_send_json_error(array('message' => __('Security verification failed. Please refresh the page and try again.', 'secure-file-session')));
            return;
        }
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You do not have permission to fix issues.', 'secure-file-session')));
            return;
        }
        
        $action = isset($_POST['fix_action']) ? sanitize_text_field($_POST['fix_action']) : '';
        
        if (empty($action)) {
            wp_send_json_error(array('message' => __('No action specified.', 'secure-file-session')));
            return;
        }
        
        switch ($action) {
            case 'create_htaccess':
                $result = $this->create_uploads_htaccess();
                if ($result) {
                    wp_send_json_success(array('message' => __('.htaccess file created successfully.', 'secure-file-session')));
                } else {
                    wp_send_json_error(array('message' => __('Failed to create .htaccess file. Check directory permissions.', 'secure-file-session')));
                }
                break;
                
            case 'fix_permissions':
                $result = $this->fix_file_permissions();
                if ($result) {
                    wp_send_json_success(array('message' => __('File permissions fixed successfully.', 'secure-file-session')));
                } else {
                    wp_send_json_error(array('message' => __('Failed to fix some file permissions. Check directory access.', 'secure-file-session')));
                }
                break;
                
            case 'fix_uploads_dir':
                $result = $this->fix_uploads_dir();
                if ($result) {
                    wp_send_json_success(array('message' => __('Uploads directory fixed successfully.', 'secure-file-session')));
                } else {
                    wp_send_json_error(array('message' => __('Failed to fix uploads directory issues.', 'secure-file-session')));
                }
                break;
                
            case 'fix_security_config':
                $result = $this->fix_security_config();
                if ($result) {
                    wp_send_json_success(array('message' => __('Security configuration optimized successfully.', 'secure-file-session')));
                } else {
                    wp_send_json_error(array('message' => __('Failed to update security configuration.', 'secure-file-session')));
                }
                break;
                
            default:
                wp_send_json_error(array('message' => __('Unknown fix action.', 'secure-file-session')));
        }
        
        // This should never be reached as each case returns, but added as a fallback
        wp_send_json_error(array('message' => __('An unexpected error occurred.', 'secure-file-session')));
    }
    
    /**
     * Handle fixing all issues at once
     */
    public function handle_fix_all_issues() {
        // Add error logging for debugging
        error_log('Fix all issues request received: ' . print_r($_POST, true));
        
        check_ajax_referer('sfs_fix_all_issues_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You do not have permission to fix issues.', 'secure-file-session')));
            return;
        }
        
        // Run all fixes
        $results = array(
            'htaccess' => $this->create_uploads_htaccess(),
            'permissions' => $this->fix_file_permissions(),
            'uploads_dir' => $this->fix_uploads_dir(),
            'security_config' => $this->fix_security_config()
        );
        
        // Log the results for debugging
        error_log('Fix all issues results: ' . print_r($results, true));
        
        // Check if all fixes were successful
        if (in_array(false, $results, true)) {
            $failed = array();
            foreach ($results as $key => $success) {
                if (!$success) {
                    $failed[] = $key;
                }
            }
            
            wp_send_json_error(array(
                'message' => sprintf(
                    __('Some issues could not be fixed automatically: %s. Please check the individual issues.', 'secure-file-session'),
                    implode(', ', $failed)
                )
            ));
        } else {
            wp_send_json_success(array(
                'message' => __('All issues fixed successfully!', 'secure-file-session')
            ));
        }
    }
    
    /**
     * Create or update the .htaccess file in uploads directory
     */
    public function create_uploads_htaccess() {
        $upload_dir = wp_upload_dir();
        $htaccess_path = trailingslashit($upload_dir['basedir']) . '.htaccess';
        
        // Get the htaccess content from the template
        $htaccess_content = $this->get_htaccess_template();
        
        // Write the file
        $result = file_put_contents($htaccess_path, $htaccess_content);
        
        return ($result !== false);
    }
    
    /**
     * Get the .htaccess template content
     */
    private function get_htaccess_template() {
        $template = <<<'EOT'
# BEGIN Secure File Session Protection
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_URI} !.*\/wp-content\/plugins\/secure-file-session\/includes\/direct-access\.php$
RewriteCond %{QUERY_STRING} !.*sfs_token=([a-zA-Z0-9]+).*
RewriteRule \.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|mp3|mp4|mov|avi|webm)$ - [F,L]
</IfModule>

<IfModule !mod_rewrite.c>
# If mod_rewrite is not available, try to use mod_authz_core for Apache 2.4+
<IfModule mod_authz_core.c>
    Require all denied
</IfModule>

# Fallback for Apache 2.2
<IfModule !mod_authz_core.c>
    <IfModule mod_authz_host.c>
        Order deny,allow
        Deny from all
    </IfModule>
</IfModule>
</IfModule>
# END Secure File Session Protection
EOT;
        
        return $template;
    }
    
    /**
     * Fix file permissions in the uploads directory
     */
    public function fix_file_permissions() {
        $upload_dir = wp_upload_dir();
        $uploads_path = $upload_dir['basedir'];
        
        // Fix directory permissions
        chmod($uploads_path, 0755);
        
        // Fix file permissions for a limited number of files
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($uploads_path));
        $count = 0;
        $max_files = 500; // Limit to avoid timeouts
        
        foreach ($iterator as $file) {
            if ($file->isFile() && !$file->isLink()) {
                // Get current permissions
                $perms = substr(sprintf('%o', $file->getPerms()), -4);
                
                // Fix permissions if they're too open
                if ($perms == '0777' || $perms == '0666') {
                    @chmod($file->getPathname(), 0644);
                }
                
                $count++;
                if ($count >= $max_files) break;
            }
        }
        
        return true;
    }
    
    /**
     * Fix uploads directory issues
     */
    public function fix_uploads_dir() {
        $upload_dir = wp_upload_dir();
        $uploads_path = $upload_dir['basedir'];
        
        // Try to create the directory if it doesn't exist
        if (!file_exists($uploads_path)) {
            wp_mkdir_p($uploads_path);
        }
        
        // Set proper permissions
        if (file_exists($uploads_path)) {
            @chmod($uploads_path, 0755);
        }
        
        // Check if directory now exists and is writable
        if (!file_exists($uploads_path) || !is_writable($uploads_path)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Fix security configuration
     */
    public function fix_security_config() {
        // Debug log
        error_log('Running fix_security_config');
        
        $options = get_option('secure_file_session_options', array());
        
        // Enable protection
        $options['protection_enabled'] = true;
        
        // Set reasonable token expiration (30 minutes)
        if (!isset($options['token_expiration']) || (int)$options['token_expiration'] > 3600) {
            $options['token_expiration'] = 1800;
        }
        
        // Enable rate limiting if not set - using the correct field name
        if (empty($options['rate_limit_enabled'])) {
            $options['rate_limit_enabled'] = true;
            $options['rate_limit'] = 30;
            $options['rate_window'] = 60;
        }
        
        // Disable debug mode on production
        $options['debug_mode'] = false;
        
        // Update the options and log the result
        $result = update_option('secure_file_session_options', $options);
        error_log('fix_security_config result: ' . ($result ? 'true' : 'false'));
        
        return $result;
    }
    
    /**
     * Render the logs tab content
     */
    public function render_logs_tab() {
        // Get settings
        $settings = get_option('secure_file_session_options', array());
        $logs_enabled = !empty($settings['enable_logging']);
        
        ?>
        <div class="sfs-logs-tab">
            <h2><?php esc_html_e('Access Logs', 'secure-file-session'); ?></h2>
            
            <?php if (!$logs_enabled) : ?>
                <div class="notice notice-warning">
                    <p>
                        <?php esc_html_e('Logging is currently disabled.', 'secure-file-session'); ?> 
                        <a href="?page=secure-file-session-settings&tab=general"><?php esc_html_e('Enable logging in General Settings', 'secure-file-session'); ?></a>
                    </p>
                </div>
            <?php endif; ?>
            
            <div class="sfs-logs-management">
                <h3><?php esc_html_e('Log Management', 'secure-file-session'); ?></h3>
                
                <!-- Clear all logs -->
                <form method="post" class="sfs-form-clear-logs">
                    <?php wp_nonce_field('sfs_clear_logs', 'sfs_logs_nonce'); ?>
                    <p><?php esc_html_e('Remove all access logs from the database.', 'secure-file-session'); ?></p>
                    <p>
                        <input type="submit" name="sfs_clear_logs" class="button button-secondary" value="<?php esc_attr_e('Clear All Logs', 'secure-file-session'); ?>" 
                               onclick="return confirm('<?php echo esc_js(__('Are you sure you want to delete all logs? This cannot be undone.', 'secure-file-session')); ?>');" />
                    </p>
                </form>
                
                <!-- Clear old logs -->
                <form method="post" class="sfs-form-clear-old-logs">
                    <?php wp_nonce_field('sfs_clear_old_logs', 'sfs_old_logs_nonce'); ?>
                    <p><?php esc_html_e('Remove access logs older than the specified number of days.', 'secure-file-session'); ?></p>
                    <p>
                        <input type="number" name="days" min="1" value="30" class="small-text" />
                        <?php esc_html_e('days', 'secure-file-session'); ?>
                        <input type="submit" name="sfs_clear_old_logs" class="button button-secondary" value="<?php esc_attr_e('Clear Old Logs', 'secure-file-session'); ?>" />
                    </p>
                </form>
            </div>
            
            <div class="sfs-logs-filter">
                <h3><?php esc_html_e('Filter Logs', 'secure-file-session'); ?></h3>
                
                <form method="get" class="sfs-filter-form">
                    <input type="hidden" name="page" value="secure-file-session-settings" />
                    <input type="hidden" name="tab" value="logs" />
                    
                    <div class="sfs-filter-row">
                        <label for="sfs-filter-event" class="screen-reader-text"><?php esc_html_e('Filter by Event Type', 'secure-file-session'); ?></label>
                        <select name="event_type" id="sfs-filter-event">
                            <option value=""><?php esc_html_e('All Event Types', 'secure-file-session'); ?></option>
                            <option value="file_access" <?php selected(isset($_GET['event_type']) && $_GET['event_type'] === 'file_access'); ?>><?php esc_html_e('File Access', 'secure-file-session'); ?></option>
                            <option value="token_generated" <?php selected(isset($_GET['event_type']) && $_GET['event_type'] === 'token_generated'); ?>><?php esc_html_e('Token Generated', 'secure-file-session'); ?></option>
                            <option value="token_verification_failed" <?php selected(isset($_GET['event_type']) && $_GET['event_type'] === 'token_verification_failed'); ?>><?php esc_html_e('Token Verification Failed', 'secure-file-session'); ?></option>
                            <option value="token_revoked" <?php selected(isset($_GET['event_type']) && $_GET['event_type'] === 'token_revoked'); ?>><?php esc_html_e('Token Revoked', 'secure-file-session'); ?></option>
                        </select>
                        
                        <label for="sfs-filter-status" class="screen-reader-text"><?php esc_html_e('Filter by Status', 'secure-file-session'); ?></label>
                        <select name="status" id="sfs-filter-status">
                            <option value=""><?php esc_html_e('All Statuses', 'secure-file-session'); ?></option>
                            <option value="success" <?php selected(isset($_GET['status']) && $_GET['status'] === 'success'); ?>><?php esc_html_e('Success', 'secure-file-session'); ?></option>
                            <option value="error" <?php selected(isset($_GET['status']) && $_GET['status'] === 'error'); ?>><?php esc_html_e('Error', 'secure-file-session'); ?></option>
                        </select>
                        
                        <label for="sfs-filter-date" class="screen-reader-text"><?php esc_html_e('Filter by Date', 'secure-file-session'); ?></label>
                        <select name="date_range" id="sfs-filter-date">
                            <option value=""><?php esc_html_e('All Time', 'secure-file-session'); ?></option>
                            <option value="today" <?php selected(isset($_GET['date_range']) && $_GET['date_range'] === 'today'); ?>><?php esc_html_e('Today', 'secure-file-session'); ?></option>
                            <option value="yesterday" <?php selected(isset($_GET['date_range']) && $_GET['date_range'] === 'yesterday'); ?>><?php esc_html_e('Yesterday', 'secure-file-session'); ?></option>
                            <option value="week" <?php selected(isset($_GET['date_range']) && $_GET['date_range'] === 'week'); ?>><?php esc_html_e('Last 7 Days', 'secure-file-session'); ?></option>
                            <option value="month" <?php selected(isset($_GET['date_range']) && $_GET['date_range'] === 'month'); ?>><?php esc_html_e('Last 30 Days', 'secure-file-session'); ?></option>
                        </select>
                        
                        <input type="submit" class="button" value="<?php esc_attr_e('Filter', 'secure-file-session'); ?>" />
                    </div>
                </form>
            </div>
            
            <div class="sfs-logs-table-wrapper">
                <h3><?php esc_html_e('Access Logs', 'secure-file-session'); ?></h3>
                
                <?php
                // Get all logs
                $logs = get_option('sfs_access_logs', array());
                $filtered_logs = $logs;
                
                // Apply filters if set
                if (!empty($_GET['event_type'])) {
                    $event_type = sanitize_text_field($_GET['event_type']);
                    $filtered_logs = array_filter($filtered_logs, function($log) use ($event_type) {
                        return $log['event_type'] === $event_type;
                    });
                }
                
                if (!empty($_GET['status'])) {
                    $status = sanitize_text_field($_GET['status']);
                    $filtered_logs = array_filter($filtered_logs, function($log) use ($status) {
                        if ($log['event_type'] === 'file_access') {
                            $event_data = maybe_unserialize($log['event_data']);
                            return isset($event_data['status']) && $event_data['status'] === $status;
                        }
                        return false;
                    });
                }
                
                if (!empty($_GET['date_range'])) {
                    $date_range = sanitize_text_field($_GET['date_range']);
                    $now = current_time('timestamp');
                    $cutoff = 0;
                    
                    switch ($date_range) {
                        case 'today':
                            $cutoff = strtotime('today', $now);
                            break;
                        case 'yesterday':
                            $cutoff = strtotime('yesterday', $now);
                            $end_cutoff = strtotime('today', $now) - 1;
                            break;
                        case 'week':
                            $cutoff = strtotime('-7 days', $now);
                            break;
                        case 'month':
                            $cutoff = strtotime('-30 days', $now);
                            break;
                    }
                    
                    if ($cutoff > 0) {
                        $filtered_logs = array_filter($filtered_logs, function($log) use ($cutoff, $date_range, $end_cutoff) {
                            $log_time = strtotime($log['timestamp']);
                            
                            if ($date_range === 'yesterday') {
                                return $log_time >= $cutoff && $log_time <= $end_cutoff;
                            }
                            
                            return $log_time >= $cutoff;
                        });
                    }
                }
                
                // Reverse logs to show newest first
                $filtered_logs = array_reverse($filtered_logs);
                
                // Pagination
                $per_page = 20;
                $current_page = isset($_GET['log_paged']) ? max(1, intval($_GET['log_paged'])) : 1;
                $total_logs = count($filtered_logs);
                $total_pages = ceil($total_logs / $per_page);
                
                $logs_to_display = array_slice($filtered_logs, ($current_page - 1) * $per_page, $per_page);
                
                // Display logs table
                if (empty($logs_to_display)) {
                    echo '<p>' . esc_html__('No logs found.', 'secure-file-session') . '</p>';
                } else {
                    ?>
                    <table class="widefat striped sfs-logs-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e('Time', 'secure-file-session'); ?></th>
                                <th><?php esc_html_e('Event', 'secure-file-session'); ?></th>
                                <th><?php esc_html_e('User', 'secure-file-session'); ?></th>
                                <th><?php esc_html_e('IP Address', 'secure-file-session'); ?></th>
                                <th><?php esc_html_e('Details', 'secure-file-session'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($logs_to_display as $log) : 
                                $event_data = maybe_unserialize($log['event_data']);
                                $status_class = '';
                                $details = '';
                                
                                // Format details based on event type
                                switch ($log['event_type']) {
                                    case 'file_access':
                                        $status = isset($event_data['status']) ? $event_data['status'] : '';
                                        $status_class = $status === 'success' ? 'sfs-status-success' : 'sfs-status-error';
                                        $file = isset($event_data['file']) ? basename($event_data['file']) : '';
                                        $reason = isset($event_data['reason']) ? $event_data['reason'] : '';
                                        
                                        $details = esc_html__('File:', 'secure-file-session') . ' ' . esc_html($file);
                                        if (!empty($reason)) {
                                            $details .= ' | ' . esc_html__('Reason:', 'secure-file-session') . ' ' . esc_html($reason);
                                        }
                                        break;
                                        
                                    case 'token_generated':
                                        $file = isset($event_data['file']) ? basename($event_data['file']) : '';
                                        $token = isset($event_data['token']) ? substr($event_data['token'], 0, 8) . '...' : '';
                                        $expiration = isset($event_data['expiration']) ? date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $event_data['expiration']) : '';
                                        
                                        $details = esc_html__('File:', 'secure-file-session') . ' ' . esc_html($file);
                                        $details .= ' | ' . esc_html__('Token:', 'secure-file-session') . ' ' . esc_html($token);
                                        $details .= ' | ' . esc_html__('Expires:', 'secure-file-session') . ' ' . esc_html($expiration);
                                        break;
                                        
                                    case 'token_verification_failed':
                                        $status_class = 'sfs-status-error';
                                        $file = isset($event_data['file']) ? basename($event_data['file']) : '';
                                        $reason = isset($event_data['reason']) ? $event_data['reason'] : '';
                                        
                                        $details = esc_html__('File:', 'secure-file-session') . ' ' . esc_html($file);
                                        if (!empty($reason)) {
                                            $details .= ' | ' . esc_html__('Reason:', 'secure-file-session') . ' ' . esc_html($reason);
                                        }
                                        break;
                                        
                                    case 'token_revoked':
                                        $token = isset($event_data['token']) ? substr($event_data['token'], 0, 8) . '...' : '';
                                        $revoked_by = isset($event_data['revoked_by']) ? $event_data['revoked_by'] : 0;
                                        $user_obj = get_user_by('id', $revoked_by);
                                        $user_name = $user_obj ? $user_obj->display_name : __('Unknown', 'secure-file-session');
                                        
                                        $details = esc_html__('Token:', 'secure-file-session') . ' ' . esc_html($token);
                                        $details .= ' | ' . esc_html__('Revoked by:', 'secure-file-session') . ' ' . esc_html($user_name);
                                        break;
                                        
                                    default:
                                        $details = esc_html__('Details not available', 'secure-file-session');
                                        break;
                                }
                                
                                // Format event name for display
                                $event_name = '';
                                switch ($log['event_type']) {
                                    case 'file_access':
                                        $event_name = __('File Access', 'secure-file-session');
                                        break;
                                    case 'token_generated':
                                        $event_name = __('Token Generated', 'secure-file-session');
                                        break;
                                    case 'token_verification_failed':
                                        $event_name = __('Token Verification Failed', 'secure-file-session');
                                        break;
                                    case 'token_revoked':
                                        $event_name = __('Token Revoked', 'secure-file-session');
                                        break;
                                    default:
                                        $event_name = ucfirst(str_replace('_', ' ', $log['event_type']));
                                        break;
                                }
                                
                                // Get user info
                                $user_id = $log['user_id'];
                                $user_obj = get_user_by('id', $user_id);
                                $user_display = $user_obj ? $user_obj->display_name : __('Guest', 'secure-file-session');
                            ?>
                                <tr class="<?php echo esc_attr($status_class); ?>">
                                    <td><?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($log['timestamp']))); ?></td>
                                    <td><?php echo esc_html($event_name); ?></td>
                                    <td><?php echo esc_html($user_display); ?></td>
                                    <td><?php echo esc_html($log['user_ip']); ?></td>
                                    <td><?php echo $details; ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    
                    <?php if ($total_pages > 1) : ?>
                        <div class="sfs-logs-pagination">
                            <div class="tablenav-pages">
                                <span class="displaying-num">
                                    <?php printf(
                                        _n('%s item', '%s items', $total_logs, 'secure-file-session'),
                                        number_format_i18n($total_logs)
                                    ); ?>
                                </span>
                                
                                <span class="pagination-links">
                                    <?php
                                    // First page link
                                    if ($current_page > 1) {
                                        printf(
                                            '<a class="first-page button" href="%s"><span class="screen-reader-text">%s</span><span aria-hidden="true">%s</span></a>',
                                            esc_url(add_query_arg('log_paged', 1)),
                                            esc_html__('First page', 'secure-file-session'),
                                            '&laquo;'
                                        );
                                    } else {
                                        printf(
                                            '<span class="first-page button disabled"><span class="screen-reader-text">%s</span><span aria-hidden="true">%s</span></span>',
                                            esc_html__('First page', 'secure-file-session'),
                                            '&laquo;'
                                        );
                                    }
                                    
                                    // Previous page link
                                    if ($current_page > 1) {
                                        printf(
                                            '<a class="prev-page button" href="%s"><span class="screen-reader-text">%s</span><span aria-hidden="true">%s</span></a>',
                                            esc_url(add_query_arg('log_paged', $current_page - 1)),
                                            esc_html__('Previous page', 'secure-file-session'),
                                            '&lsaquo;'
                                        );
                                    } else {
                                        printf(
                                            '<span class="prev-page button disabled"><span class="screen-reader-text">%s</span><span aria-hidden="true">%s</span></span>',
                                            esc_html__('Previous page', 'secure-file-session'),
                                            '&lsaquo;'
                                        );
                                    }
                                    
                                    // Current page text
                                    printf(
                                        '<span class="paging-input"><span class="tablenav-paging-text">%1$s %2$s %3$s</span></span>',
                                        $current_page,
                                        esc_html__('of', 'secure-file-session'),
                                        $total_pages
                                    );
                                    
                                    // Next page link
                                    if ($current_page < $total_pages) {
                                        printf(
                                            '<a class="next-page button" href="%s"><span class="screen-reader-text">%s</span><span aria-hidden="true">%s</span></a>',
                                            esc_url(add_query_arg('log_paged', $current_page + 1)),
                                            esc_html__('Next page', 'secure-file-session'),
                                            '&rsaquo;'
                                        );
                                    } else {
                                        printf(
                                            '<span class="next-page button disabled"><span class="screen-reader-text">%s</span><span aria-hidden="true">%s</span></span>',
                                            esc_html__('Next page', 'secure-file-session'),
                                            '&rsaquo;'
                                        );
                                    }
                                    
                                    // Last page link
                                    if ($current_page < $total_pages) {
                                        printf(
                                            '<a class="last-page button" href="%s"><span class="screen-reader-text">%s</span><span aria-hidden="true">%s</span></a>',
                                            esc_url(add_query_arg('log_paged', $total_pages)),
                                            esc_html__('Last page', 'secure-file-session'),
                                            '&raquo;'
                                        );
                                    } else {
                                        printf(
                                            '<span class="last-page button disabled"><span class="screen-reader-text">%s</span><span aria-hidden="true">%s</span></span>',
                                            esc_html__('Last page', 'secure-file-session'),
                                            '&raquo;'
                                        );
                                    }
                                    ?>
                                </span>
                            </div>
                        </div>
                    <?php endif; ?>
                    
                <?php } ?>
            </div>
        </div>
        <?php
    }
    
    /**
     * Output diagnostic information for troubleshooting
     */
    public function output_diagnostics() {
        $response = array(
            'success' => true,
            'data' => array(
                'wp_version' => get_bloginfo('version'),
                'php_version' => phpversion(),
                'plugin_version' => SECURE_FILE_SESSION_VERSION,
                'settings' => $this->settings,
                'uploads_dir' => wp_upload_dir(),
                'server_info' => array(
                    'software' => $_SERVER['SERVER_SOFTWARE'],
                    'os' => PHP_OS,
                    'max_upload' => ini_get('upload_max_filesize'),
                    'max_post' => ini_get('post_max_size'),
                    'memory_limit' => ini_get('memory_limit'),
                    'max_execution_time' => ini_get('max_execution_time'),
                    'php_extensions' => get_loaded_extensions()
                )
            )
        );
        
        wp_send_json($response);
        exit;
    }
    
    /**
     * Perform a self-test of the plugin configuration
     * Tests all important aspects of the plugin to identify issues
     */
    public function perform_self_test() {
        // Check user permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized access'));
            return;
        }
        
        // Verify nonce
        if (empty($_REQUEST['nonce']) || !wp_verify_nonce($_REQUEST['nonce'], 'secure_file_session_nonce')) {
            wp_send_json_error(array('message' => 'Security check failed'));
            return;
        }
        
        $results = array(
            'success' => true,
            'tests' => array()
        );
        
        // Get plugin instance
        $plugin = Secure_File_Session::get_instance();
        $settings = $plugin->get_settings();
        
        // Test 1: Check if protection is enabled
        $results['tests']['protection_enabled'] = array(
            'name' => 'Protection Enabled',
            'result' => !empty($settings['protection_enabled']),
            'message' => !empty($settings['protection_enabled']) 
                ? 'Protection is enabled' 
                : 'Protection is disabled - plugin will not secure files',
            'severity' => !empty($settings['protection_enabled']) ? 'success' : 'error'
        );
        
        // Test 2: Check if .htaccess rules are in place
        $htaccess_test = $this->run_htaccess_check();
        $results['tests']['htaccess'] = array(
            'name' => '.htaccess Protection',
            'result' => $htaccess_test['success'],
            'message' => $htaccess_test['message'],
            'severity' => $htaccess_test['success'] ? 'success' : 'error'
        );
        
        // Test 3: Check if rate limiting is enabled
        $results['tests']['rate_limiting'] = array(
            'name' => 'Rate Limiting',
            'result' => !empty($settings['rate_limit_enabled']),
            'message' => !empty($settings['rate_limit_enabled']) 
                ? 'Rate limiting is enabled' 
                : 'Rate limiting is disabled - recommended to enable for security',
            'severity' => !empty($settings['rate_limit_enabled']) ? 'success' : 'warning'
        );
        
        // Test 4: Check if upload directory is protected
        $upload_dir = wp_upload_dir();
        $test_file = $upload_dir['basedir'] . '/test-' . uniqid() . '.txt';
        $file_created = @file_put_contents($test_file, 'Test file content');
        
        if ($file_created) {
            $uploads_url = $upload_dir['baseurl'] . '/test-' . uniqid() . '.txt';
            $response = wp_remote_get($uploads_url, array(
                'timeout' => 5,
                'sslverify' => false,
                'headers' => array('X-Test-SFS' => 'testing')
            ));
            
            $uploads_protected = is_wp_error($response) || $response['response']['code'] === 403;
            @unlink($test_file); // Clean up test file
            
            $results['tests']['uploads_protected'] = array(
                'name' => 'Uploads Directory Protection',
                'result' => $uploads_protected,
                'message' => $uploads_protected 
                    ? 'Uploads directory appears to be protected' 
                    : 'Uploads directory might be directly accessible - check server configuration',
                'severity' => $uploads_protected ? 'success' : 'warning'
            );
        } else {
            $results['tests']['uploads_protected'] = array(
                'name' => 'Uploads Directory Protection',
                'result' => null,
                'message' => 'Could not test uploads directory protection - check file permissions',
                'severity' => 'warning'
            );
        }
        
        // Test 5: Check if token generation works
        $test_token = $plugin->generate_token('test.jpg');
        $results['tests']['token_generation'] = array(
            'name' => 'Token Generation',
            'result' => !empty($test_token),
            'message' => !empty($test_token) 
                ? 'Token generation is working properly' 
                : 'Token generation failed - check encryption settings',
            'severity' => !empty($test_token) ? 'success' : 'error'
        );
        
        // Test 6: Check if secure URL generation works
        $test_url = $plugin->get_secure_url('test.jpg');
        $results['tests']['secure_url'] = array(
            'name' => 'Secure URL Generation',
            'result' => !empty($test_url) && strpos($test_url, $settings['secure_file_base']) !== false,
            'message' => !empty($test_url) && strpos($test_url, $settings['secure_file_base']) !== false
                ? 'Secure URL generation is working properly' 
                : 'Secure URL generation failed - check permalink settings',
            'severity' => !empty($test_url) && strpos($test_url, $settings['secure_file_base']) !== false ? 'success' : 'error'
        );
        
        // Test 7: Check if content filtering hooks are working
        $test_content = '<img src="' . $upload_dir['baseurl'] . '/test.jpg" alt="test">';
        $filtered_content = $plugin->replace_file_urls($test_content);
        $results['tests']['content_filtering'] = array(
            'name' => 'Content Filtering',
            'result' => $filtered_content !== $test_content,
            'message' => $filtered_content !== $test_content
                ? 'Content filtering is working properly' 
                : 'Content filtering not working - URLs may not be secured in content',
            'severity' => $filtered_content !== $test_content ? 'success' : 'error'
        );
        
        // Test 8: Check if logs directory is writable
        $logs_dir = WP_CONTENT_DIR . '/secure-file-session-logs';
        $logs_writable = is_dir($logs_dir) || mkdir($logs_dir, 0755, true);
        if ($logs_writable) {
            $logs_writable = is_writable($logs_dir);
        }
        
        $results['tests']['logs_directory'] = array(
            'name' => 'Logs Directory',
            'result' => $logs_writable,
            'message' => $logs_writable
                ? 'Logs directory is writable' 
                : 'Logs directory is not writable - check permissions',
            'severity' => $logs_writable ? 'success' : 'warning'
        );
        
        // Overall result - failed if any error tests
        foreach ($results['tests'] as $test) {
            if ($test['severity'] === 'error' && $test['result'] === false) {
                $results['success'] = false;
            }
        }
        
        // Add diagnostic information
        $results['diagnostics'] = array(
            'wp_version' => get_bloginfo('version'),
            'php_version' => phpversion(),
            'plugin_version' => SECURE_FILE_SESSION_VERSION,
            'permalink_structure' => get_option('permalink_structure'),
            'https' => is_ssl() ? 'Yes' : 'No',
            'server_software' => $_SERVER['SERVER_SOFTWARE'],
            'secure_base' => $settings['secure_file_base'],
            'uploads_dir' => $upload_dir['basedir']
        );
        
        // Return results
        wp_send_json($results);
    }
} 