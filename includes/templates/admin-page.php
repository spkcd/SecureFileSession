<?php
/**
 * Admin page template for Secure File Session
 *
 * @package SecureFileSession
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

// Get current settings
$options = get_option('secure_file_session_options', array(
    'protection_enabled' => true,
    'token_expiration' => 600,
    'post_types' => array('all'),
    'enable_logging' => false,
    'ip_lock' => false,
    'debug_mode' => false
));

// Get available post types
$post_types = get_post_types(array('public' => true), 'objects');

// Get active tokens
$active_tokens = array();
global $wpdb;
$transients = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT option_name, option_value 
        FROM {$wpdb->options} 
        WHERE option_name LIKE %s 
        ORDER BY option_id DESC 
        LIMIT 100",
        $wpdb->esc_like('_transient_sfs_token_') . '%'
    )
);

if ($transients) {
    foreach ($transients as $transient) {
        $token_id = str_replace('_transient_sfs_token_', '', $transient->option_name);
        $timeout_value = get_option('_transient_timeout_sfs_token_' . $token_id);
        
        if ($timeout_value) {
            $token_data = maybe_unserialize($transient->option_value);
            $token_data['token'] = $token_id;
            $token_data['expires_in'] = $timeout_value - time();
            $token_data['expires_at'] = date('Y-m-d H:i:s', $timeout_value);
            
            // Get original filename from encoded path
            $relative_path = base64_decode($token_data['file']);
            $token_data['filename'] = basename($relative_path);
            
            $active_tokens[] = $token_data;
        }
    }
}

// Get logs if enabled
$logs = array();
if (!empty($options['enable_logging'])) {
    $logs = get_option('sfs_access_logs', array());
    // Limit to last 100 records for display
    $logs = array_slice($logs, -100);
}
?>

<div class="wrap secure-file-session-admin">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
    
    <div class="sfs-admin-tabs">
        <nav class="nav-tab-wrapper">
            <a href="#settings" class="nav-tab nav-tab-active"><?php esc_html_e('Settings', 'secure-file-session'); ?></a>
            <a href="#tokens" class="nav-tab"><?php esc_html_e('Active Tokens', 'secure-file-session'); ?></a>
            <a href="#logs" class="nav-tab"><?php esc_html_e('Access Logs', 'secure-file-session'); ?></a>
            <a href="#debug" class="nav-tab"><?php esc_html_e('Debug', 'secure-file-session'); ?></a>
        </nav>
        
        <div class="tab-content">
            <!-- Settings Tab -->
            <div id="settings" class="tab-pane active">
                <form method="post" action="options.php">
                    <?php settings_fields('secure_file_session_options_group'); ?>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Protection Status', 'secure-file-session'); ?></th>
                            <td>
                                <label for="protection_enabled">
                                    <input type="checkbox" id="protection_enabled" name="secure_file_session_options[protection_enabled]" value="1" <?php checked(!empty($options['protection_enabled'])); ?> />
                                    <?php esc_html_e('Enable file protection', 'secure-file-session'); ?>
                                </label>
                                <p class="description"><?php esc_html_e('When enabled, files will be accessible only through secure tokens.', 'secure-file-session'); ?></p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th scope="row"><?php esc_html_e('Token Expiration', 'secure-file-session'); ?></th>
                            <td>
                                <input type="number" id="token_expiration" name="secure_file_session_options[token_expiration]" value="<?php echo esc_attr($options['token_expiration']); ?>" min="60" step="1" class="small-text" />
                                <?php esc_html_e('seconds', 'secure-file-session'); ?>
                                <span class="description">(<span id="expiration_minutes"><?php echo round($options['token_expiration'] / 60, 1); ?></span> <?php esc_html_e('minutes', 'secure-file-session'); ?>)</span>
                                <p class="description"><?php esc_html_e('How long a secure token remains valid after generation.', 'secure-file-session'); ?></p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th scope="row"><?php esc_html_e('Post Types', 'secure-file-session'); ?></th>
                            <td>
                                <?php foreach ($post_types as $post_type): ?>
                                <label>
                                    <input type="checkbox" name="secure_file_session_options[post_types][]" value="<?php echo esc_attr($post_type->name); ?>" <?php checked(in_array($post_type->name, $options['post_types']) || in_array('all', $options['post_types'])); ?> />
                                    <?php echo esc_html($post_type->label); ?>
                                </label><br>
                                <?php endforeach; ?>
                                <label>
                                    <input type="checkbox" name="secure_file_session_options[post_types][]" value="all" <?php checked(in_array('all', $options['post_types'])); ?> />
                                    <?php esc_html_e('All post types', 'secure-file-session'); ?>
                                </label>
                                <p class="description"><?php esc_html_e('Select which post types should have secure file links.', 'secure-file-session'); ?></p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th scope="row"><?php esc_html_e('Security Options', 'secure-file-session'); ?></th>
                            <td>
                                <label for="enable_logging">
                                    <input type="checkbox" id="enable_logging" name="secure_file_session_options[enable_logging]" value="1" <?php checked(!empty($options['enable_logging'])); ?> />
                                    <?php esc_html_e('Enable access logging', 'secure-file-session'); ?>
                                </label>
                                <p class="description"><?php esc_html_e('Log file access attempts and token verifications.', 'secure-file-session'); ?></p>
                                
                                <br>
                                
                                <label for="auto_clear_logs">
                                    <input type="checkbox" id="auto_clear_logs" name="secure_file_session_options[auto_clear_logs]" value="1" <?php checked(!empty($options['auto_clear_logs'])); ?> />
                                    <?php esc_html_e('Auto-clean logs', 'secure-file-session'); ?>
                                </label>
                                <p class="description"><?php esc_html_e('Automatically clean logs older than the specified retention period.', 'secure-file-session'); ?></p>
                                
                                <br>
                                
                                <label for="log_retention_days">
                                    <?php esc_html_e('Log retention (days):', 'secure-file-session'); ?>
                                    <input type="number" id="log_retention_days" name="secure_file_session_options[log_retention_days]" value="<?php echo isset($options['log_retention_days']) ? intval($options['log_retention_days']) : 30; ?>" min="1" step="1" class="small-text" />
                                </label>
                                <p class="description"><?php esc_html_e('Number of days to keep logs before automatic cleanup.', 'secure-file-session'); ?></p>
                                
                                <br>
                                
                                <label for="ip_lock">
                                    <input type="checkbox" id="ip_lock" name="secure_file_session_options[ip_lock]" value="1" <?php checked(!empty($options['ip_lock'])); ?> />
                                    <?php esc_html_e('Lock tokens to IP address', 'secure-file-session'); ?>
                                </label>
                                <p class="description"><?php esc_html_e('Tokens will only work from the same IP address they were generated from.', 'secure-file-session'); ?></p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th scope="row"><?php esc_html_e('Display Options', 'secure-file-session'); ?></th>
                            <td>
                                <label for="disable_styling_in_tables">
                                    <input type="checkbox" id="disable_styling_in_tables" name="secure_file_session_options[disable_styling_in_tables]" value="1" <?php checked(!empty($options['disable_styling_in_tables'])); ?> />
                                    <?php esc_html_e('Disable styling in tables', 'secure-file-session'); ?>
                                </label>
                                <p class="description"><?php esc_html_e('Don\'t apply styling, badges, or file size to download links in tables (like JetEngine tables).', 'secure-file-session'); ?></p>
                                
                                <br>
                                
                                <label for="protect_svg_icons">
                                    <input type="checkbox" id="protect_svg_icons" name="secure_file_session_options[protect_svg_icons]" value="1" <?php checked(!empty($options['protect_svg_icons'])); ?> />
                                    <?php esc_html_e('Protect SVG icons', 'secure-file-session'); ?>
                                </label>
                                <p class="description"><?php esc_html_e('Prevent plugin styling from affecting SVG icons on your site.', 'secure-file-session'); ?></p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th scope="row"><?php esc_html_e('URL Exclusions', 'secure-file-session'); ?></th>
                            <td>
                                <label for="excluded_pages">
                                    <?php esc_html_e('Exclude pages (one per line):', 'secure-file-session'); ?>
                                    <textarea id="excluded_pages" name="secure_file_session_options[excluded_pages]" rows="5" cols="50" class="large-text code"><?php echo isset($options['excluded_pages']) ? esc_textarea($options['excluded_pages']) : '/login/'; ?></textarea>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('Enter page URLs or URL patterns to exclude from file protection and styling (one per line).', 'secure-file-session'); ?><br>
                                    <?php esc_html_e('Examples: /login/, /account/, /my-account/*', 'secure-file-session'); ?><br>
                                    <?php esc_html_e('Images and files on these pages will maintain their original URLs.', 'secure-file-session'); ?>
                                </p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th scope="row"><?php esc_html_e('Debug Mode', 'secure-file-session'); ?></th>
                            <td>
                                <label for="debug_mode">
                                    <input type="checkbox" id="debug_mode" name="secure_file_session_options[debug_mode]" value="1" <?php checked(!empty($options['debug_mode'])); ?> class="debug-mode-toggle" />
                                    <?php esc_html_e('Enable debug mode', 'secure-file-session'); ?>
                                </label>
                                <p class="description"><?php esc_html_e('Shows detailed information about tokens and access. DO NOT enable on production sites.', 'secure-file-session'); ?></p>
                            </td>
                        </tr>
                    </table>
                    
                    <?php submit_button(); ?>
                </form>
            </div>
            
            <!-- Tokens Tab -->
            <div id="tokens" class="tab-pane">
                <h2><?php esc_html_e('Active Security Tokens', 'secure-file-session'); ?></h2>
                
                <?php if (empty($active_tokens)): ?>
                    <p><?php esc_html_e('No active tokens found.', 'secure-file-session'); ?></p>
                <?php else: ?>
                    <div class="token-viewer">
                        <table class="widefat striped">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e('Token', 'secure-file-session'); ?></th>
                                    <th><?php esc_html_e('File', 'secure-file-session'); ?></th>
                                    <th><?php esc_html_e('Session', 'secure-file-session'); ?></th>
                                    <th><?php esc_html_e('User IP', 'secure-file-session'); ?></th>
                                    <th><?php esc_html_e('Expires', 'secure-file-session'); ?></th>
                                    <th><?php esc_html_e('Actions', 'secure-file-session'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($active_tokens as $token): ?>
                                <tr>
                                    <td><?php echo esc_html(substr($token['token'], 0, 8) . '...'); ?></td>
                                    <td><?php echo esc_html($token['filename']); ?></td>
                                    <td><?php echo esc_html($token['session_id']); ?></td>
                                    <td><?php echo esc_html($token['user_ip']); ?></td>
                                    <td>
                                        <?php if ($token['expires_in'] > 0): ?>
                                            <?php echo esc_html(human_time_diff(time(), time() + $token['expires_in'])); ?>
                                            <br><small><?php echo esc_html($token['expires_at']); ?></small>
                                        <?php else: ?>
                                            <span class="expired"><?php esc_html_e('Expired', 'secure-file-session'); ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <form method="post" action="">
                                            <?php wp_nonce_field('sfs_revoke_token', 'sfs_token_nonce'); ?>
                                            <input type="hidden" name="token_id" value="<?php echo esc_attr($token['token']); ?>">
                                            <button type="submit" name="sfs_revoke_token" class="button button-small"><?php esc_html_e('Revoke', 'secure-file-session'); ?></button>
                                        </form>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
            
            <!-- Logs Tab -->
            <div id="logs" class="tab-pane">
                <h2><?php esc_html_e('Access Logs', 'secure-file-session'); ?></h2>
                
                <?php if (empty($options['enable_logging'])): ?>
                    <div class="notice notice-warning inline">
                        <p><?php esc_html_e('Logging is currently disabled. Enable logging in the Settings tab to view access logs.', 'secure-file-session'); ?></p>
                    </div>
                <?php elseif (empty($logs)): ?>
                    <p><?php esc_html_e('No logs found.', 'secure-file-session'); ?></p>
                <?php else: ?>
                    <div class="log-viewer">
                        <form method="post" action="">
                            <?php wp_nonce_field('sfs_clear_logs', 'sfs_logs_nonce'); ?>
                            <button type="submit" name="sfs_clear_logs" class="button"><?php esc_html_e('Clear All Logs', 'secure-file-session'); ?></button>
                        </form>
                        
                        <form method="post" action="" class="clear-logs-by-age">
                            <?php wp_nonce_field('sfs_clear_old_logs', 'sfs_old_logs_nonce'); ?>
                            <label for="clear_days">
                                <?php esc_html_e('Clear logs older than', 'secure-file-session'); ?>
                                <input type="number" id="clear_days" name="days" value="30" min="1" class="small-text" />
                                <?php esc_html_e('days', 'secure-file-session'); ?>
                            </label>
                            <button type="submit" name="sfs_clear_old_logs" class="button"><?php esc_html_e('Clear Old Logs', 'secure-file-session'); ?></button>
                        </form>
                        
                        <table class="widefat striped">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e('Time', 'secure-file-session'); ?></th>
                                    <th><?php esc_html_e('Event', 'secure-file-session'); ?></th>
                                    <th><?php esc_html_e('User', 'secure-file-session'); ?></th>
                                    <th><?php esc_html_e('IP', 'secure-file-session'); ?></th>
                                    <th><?php esc_html_e('Details', 'secure-file-session'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach (array_reverse($logs) as $log): ?>
                                <tr>
                                    <td><?php echo esc_html($log['timestamp']); ?></td>
                                    <td>
                                        <?php 
                                        $event_type = $log['event_type'];
                                        $event_class = 'normal';
                                        
                                        if (strpos($event_type, 'failed') !== false) {
                                            $event_class = 'error';
                                        } elseif ($event_type === 'file_access_success') {
                                            $event_class = 'success';
                                        }
                                        
                                        echo '<span class="event-type ' . esc_attr($event_class) . '">' . esc_html($event_type) . '</span>';
                                        ?>
                                    </td>
                                    <td>
                                        <?php 
                                        $user_id = $log['user_id'];
                                        if ($user_id > 0) {
                                            $user = get_userdata($user_id);
                                            echo esc_html($user ? $user->user_login : 'User #' . $user_id);
                                        } else {
                                            esc_html_e('Guest', 'secure-file-session');
                                        }
                                        ?>
                                    </td>
                                    <td><?php echo esc_html($log['user_ip']); ?></td>
                                    <td>
                                        <?php 
                                        $event_data = maybe_unserialize($log['event_data']);
                                        if (is_array($event_data)) {
                                            echo '<ul class="log-details">';
                                            foreach ($event_data as $key => $value) {
                                                if (is_array($value)) {
                                                    $value = json_encode($value);
                                                }
                                                echo '<li><strong>' . esc_html($key) . ':</strong> ' . esc_html($value) . '</li>';
                                            }
                                            echo '</ul>';
                                        } else {
                                            echo esc_html($event_data);
                                        }
                                        ?>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
            
            <!-- Debug Tab -->
            <div id="debug" class="tab-pane">
                <h2><?php esc_html_e('Debug Information', 'secure-file-session'); ?></h2>
                
                <?php if (empty($options['debug_mode'])): ?>
                    <div class="notice notice-warning inline">
                        <p><?php esc_html_e('Debug mode is currently disabled. Enable debug mode in the Settings tab to view debug information.', 'secure-file-session'); ?></p>
                    </div>
                <?php else: ?>
                    <div class="debug-section">
                        <h3><?php esc_html_e('Session Information', 'secure-file-session'); ?></h3>
                        <div class="debug-info">
                            <p><strong><?php esc_html_e('Session ID:', 'secure-file-session'); ?></strong> <?php echo esc_html(session_id() ?: 'Not started'); ?></p>
                            <p><strong><?php esc_html_e('User IP:', 'secure-file-session'); ?></strong> <?php echo esc_html($_SERVER['REMOTE_ADDR']); ?></p>
                            
                            <h4><?php esc_html_e('Session Content:', 'secure-file-session'); ?></h4>
                            <pre class="session-debug">
<?php
if (isset($_SESSION) && !empty($_SESSION)) {
    foreach ($_SESSION as $key => $value) {
        echo esc_html($key) . " = ";
        if (is_array($value)) {
            echo "Array(\n";
            foreach ($value as $sub_key => $sub_value) {
                echo "    " . esc_html($sub_key) . " => " . (is_array($sub_value) ? 'Array(' . count($sub_value) . ')' : esc_html($sub_value)) . "\n";
            }
            echo ")";
        } else {
            echo esc_html($value);
        }
        echo "\n";
    }
} else {
    esc_html_e('No session data found', 'secure-file-session');
}
?>
                            </pre>
                        </div>
                        
                        <h3><?php esc_html_e('Plugin Settings', 'secure-file-session'); ?></h3>
                        <div class="debug-info">
                            <pre class="settings-debug">
<?php print_r($options); ?>
                            </pre>
                        </div>
                        
                        <h3><?php esc_html_e('Page Exclusions', 'secure-file-session'); ?></h3>
                        <div class="debug-info">
                            <p><strong><?php esc_html_e('Current Request URI:', 'secure-file-session'); ?></strong> <?php echo esc_html($_SERVER['REQUEST_URI']); ?></p>
                            <?php 
                            // Get the plugin instance from global variable or create a new instance
                            global $secure_file_session;
                            $plugin = $secure_file_session;
                            if (!$plugin) {
                                $plugin = new Secure_File_Session();
                            }
                            $is_excluded = $plugin->is_excluded_page();
                            ?>
                            <p><strong><?php esc_html_e('Current Page Excluded:', 'secure-file-session'); ?></strong> 
                                <span style="color: <?php echo $is_excluded ? 'green' : 'red'; ?>; font-weight: bold;">
                                    <?php echo $is_excluded ? esc_html__('Yes', 'secure-file-session') : esc_html__('No', 'secure-file-session'); ?>
                                </span>
                            </p>
                            
                            <?php if (!empty($options['excluded_pages'])): ?>
                                <p><strong><?php esc_html_e('Excluded Paths:', 'secure-file-session'); ?></strong></p>
                                <ul>
                                    <?php 
                                    $excluded_paths = explode("\n", $options['excluded_pages']);
                                    foreach ($excluded_paths as $path): 
                                        $path = trim($path);
                                        if (empty($path)) continue;
                                    ?>
                                        <li><?php echo esc_html($path); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            <?php else: ?>
                                <p><?php esc_html_e('No exclusion paths configured.', 'secure-file-session'); ?></p>
                            <?php endif; ?>
                        </div>
                        
                        <h3><?php esc_html_e('System Information', 'secure-file-session'); ?></h3>
                        <div class="debug-info">
                            <table class="widefat striped">
                                <tr>
                                    <th><?php esc_html_e('WordPress Version', 'secure-file-session'); ?></th>
                                    <td><?php echo esc_html(get_bloginfo('version')); ?></td>
                                </tr>
                                <tr>
                                    <th><?php esc_html_e('PHP Version', 'secure-file-session'); ?></th>
                                    <td><?php echo esc_html(PHP_VERSION); ?></td>
                                </tr>
                                <tr>
                                    <th><?php esc_html_e('Plugin Version', 'secure-file-session'); ?></th>
                                    <td><?php echo esc_html(SECURE_FILE_SESSION_VERSION); ?></td>
                                </tr>
                                <tr>
                                    <th><?php esc_html_e('Upload Directory', 'secure-file-session'); ?></th>
                                    <td>
                                        <?php 
                                        $upload_dir = wp_upload_dir();
                                        echo esc_html($upload_dir['basedir']); 
                                        ?>
                                    </td>
                                </tr>
                                <tr>
                                    <th><?php esc_html_e('Session Module', 'secure-file-session'); ?></th>
                                    <td><?php echo esc_html(ini_get('session.save_handler')); ?></td>
                                </tr>
                                <tr>
                                    <th><?php esc_html_e('Session Path', 'secure-file-session'); ?></th>
                                    <td><?php echo esc_html(session_save_path()); ?></td>
                                </tr>
                            </table>
                        </div>
                        
                        <div class="security-notice">
                            <h3><?php esc_html_e('Security Notice', 'secure-file-session'); ?></h3>
                            <p><?php esc_html_e('Debug mode should be disabled on production sites. The information displayed here could potentially expose sensitive data.', 'secure-file-session'); ?></p>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div> 