<?php
/**
 * WordPress 403 Forbidden Errors - Comprehensive Fix Guide
 */

// Basic security check
if (!current_user_can('manage_options')) {
    wp_die('You do not have sufficient permissions to access this page.');
}

// Start HTML output
?>
<!DOCTYPE html>
<html>
<head>
    <title>WordPress 403 Forbidden Errors - Comprehensive Fix Guide</title>
    <style>
        body { font-family: sans-serif; line-height: 1.6; margin: 20px; color: #333; }
        .container { max-width: 800px; margin: 0 auto; }
        .header { background: #23282d; color: white; padding: 20px; margin-bottom: 20px; }
        .content { background: #f1f1f1; padding: 20px; border-radius: 5px; }
        .solution { background: #fff; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .solution h3 { margin-top: 0; color: #0073aa; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        code { background: #f6f6f6; padding: 2px 5px; font-family: monospace; border-radius: 3px; }
        pre { background: #f6f6f6; padding: 15px; overflow: auto; border-radius: 3px; }
        .tag { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; margin-right: 5px; }
        .server { background: #e2f0ff; color: #0073aa; }
        .wordpress { background: #e6f6e6; color: #218838; }
        .plugin { background: #fff4e2; color: #f90; }
        .permissions { background: #f2e5ff; color: #6f42c1; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WordPress 403 Forbidden Errors - Comprehensive Fix Guide</h1>
        </div>
        <div class="content">
            <h2>Understanding 403 Forbidden Errors</h2>
            <p>A 403 Forbidden error indicates that the server understands the request but refuses to authorize it. This guide covers solutions for 403 errors when accessing media files in WordPress.</p>
            
            <div class="solution">
                <h3><span class="tag server">Server</span> Check for Hotlink Protection</h3>
                <p>Hotlink protection prevents other websites from directly linking to your files, but can sometimes block legitimate access.</p>
                <ol>
                    <li>If you're using RunCloud, go to your Web Application settings → Security tab</li>
                    <li>Disable Hotlink Protection or configure it to allow access from your own domain</li>
                    <li>If you're using cPanel, check Hotlink Protection in the Security section</li>
                </ol>
            </div>
            
            <div class="solution">
                <h3><span class="tag server">Server</span> Check Server Configuration Files</h3>
                <p>Server configuration files can include rules that block access to certain file types.</p>
                
                <h4>LiteSpeed Server</h4>
                <p>Add these directives to your LiteSpeed configuration:</p>
                <pre>&lt;FilesMatch "\.(svg|png|jpe?g|gif|ico|webp)$"&gt;
  Order allow,deny
  Allow from all
  Satisfy any
&lt;/FilesMatch&gt;

&lt;Directory "/path/to/wp-content/uploads"&gt;
  Order allow,deny
  Allow from all
  Satisfy any
&lt;/Directory&gt;</pre>
                
                <h4>Nginx Server</h4>
                <p>Add these lines to your Nginx configuration:</p>
                <pre>location ~* \.(svg|png|jpe?g|gif|ico|webp)$ {
  allow all;
  try_files $uri $uri/ /index.php?$args;
}

location ^~ /wp-content/uploads/ {
  allow all;
  try_files $uri $uri/ /index.php?$args;
}</pre>
            </div>
            
            <div class="solution">
                <h3><span class="tag permissions">Permissions</span> Check File and Directory Permissions</h3>
                <p>Incorrect file permissions can cause 403 errors.</p>
                <ol>
                    <li>Directories should have permissions set to 755 (rwxr-xr-x)</li>
                    <li>Files should have permissions set to 644 (rw-r--r--)</li>
                </ol>
                <p>You can fix permissions with these commands (via SSH):</p>
                <pre>find /path/to/wp-content/uploads -type d -exec chmod 755 {} \;
find /path/to/wp-content/uploads -type f -exec chmod 644 {} \;</pre>
                
                <p>Or use the <a href="fix-permissions.php">Permission Fixing Tool</a> we've created.</p>
            </div>
            
            <div class="solution">
                <h3><span class="tag wordpress">WordPress</span> Create .htaccess in Uploads Directory</h3>
                <p>Create a new .htaccess file in your wp-content/uploads directory with these contents:</p>
                <pre># Allow direct access to all files in the uploads directory
&lt;IfModule mod_authz_core.c&gt;
  # Apache 2.4+
  Require all granted
&lt;/IfModule&gt;
&lt;IfModule !mod_authz_core.c&gt;
  # Apache 2.2 and earlier
  Order allow,deny
  Allow from all
&lt;/IfModule&gt;

# Disable any potential blocking rules
&lt;IfModule mod_rewrite.c&gt;
  RewriteEngine On
  
  # Media files - explicitly allow
  &lt;Files ~ "\.(svg|png|jpe?g|gif|ico|webp)$"&gt;
    Require all granted
    Allow from all
  &lt;/Files&gt;
&lt;/IfModule&gt;</pre>
                
                <?php
                // Attempt to create/update .htaccess in uploads directory
                $upload_dir = wp_upload_dir();
                $htaccess_file = trailingslashit($upload_dir['basedir']) . '.htaccess';
                $htaccess_content = <<<EOT
# Allow direct access to all files in the uploads directory
<IfModule mod_authz_core.c>
  # Apache 2.4+
  Require all granted
</IfModule>
<IfModule !mod_authz_core.c>
  # Apache 2.2 and earlier
  Order allow,deny
  Allow from all
</IfModule>

# Disable any potential blocking rules
<IfModule mod_rewrite.c>
  RewriteEngine On
  
  # Media files - explicitly allow
  <Files ~ "\\.(svg|png|jpe?g|gif|ico|webp)$">
    Require all granted
    Allow from all
  </Files>
</IfModule>
EOT;
                
                $result = @file_put_contents($htaccess_file, $htaccess_content);
                if ($result !== false) {
                    echo "<p>✅ <strong>Automatic fix:</strong> Created/updated .htaccess file in uploads directory.</p>";
                    @chmod($htaccess_file, 0644);
                } else {
                    echo "<p>⚠️ <strong>Manual action needed:</strong> Unable to automatically create .htaccess file. Please create it manually in {$upload_dir['basedir']} with the content above.</p>";
                }
                ?>
            </div>
            
            <div class="solution">
                <h3><span class="tag plugin">Plugin</span> Disable or Reconfigure Security Plugins</h3>
                <p>Security plugins can block access to certain file types or directories.</p>
                <ol>
                    <li>Temporarily disable security plugins like Wordfence, iThemes Security, All-In-One WP Security, etc.</li>
                    <li>If disabling resolves the issue, re-enable them one by one to identify the source</li>
                    <li>Check the plugin settings for file access restrictions or firewall rules</li>
                </ol>
            </div>
            
            <div class="solution">
                <h3><span class="tag plugin">Plugin</span> Check Secure File Session Plugin</h3>
                <p>If you're using the Secure File Session plugin:</p>
                <ol>
                    <li>Make sure SVG files are properly excluded in the plugin settings</li>
                    <li>Temporarily disable the plugin to see if that resolves the 403 errors</li>
                    <li>If it does, consider updating the plugin code according to the fixes we've implemented</li>
                </ol>
            </div>
            
            <div class="solution">
                <h3><span class="tag server">Server</span> Additional RunCloud-Specific Fixes</h3>
                <p>If you're using RunCloud, check our <a href="runcloud-fix.php">RunCloud-Specific Fix Guide</a> for more detailed solutions.</p>
            </div>
            
            <h2>Testing Your Fixes</h2>
            <p>After applying these fixes, test direct access to your problematic files:</p>
            
            <?php
            $test_urls = array(
                home_url('/wp-content/uploads/2025/01/download-3.svg'),
                home_url('/wp-content/uploads/2025/01/iphone_14_pro_mockup_03-914x1024.png'),
                home_url('/wp-content/uploads/2025/01/download-2.svg')
            );
            
            echo "<ul>";
            foreach ($test_urls as $url) {
                echo "<li><a href=\"$url\" target=\"_blank\">$url</a></li>";
            }
            echo "</ul>";
            ?>
            
            <p>Don't forget to:</p>
            <ol>
                <li>Clear your WordPress cache</li>
                <li>Clear your browser cache (Ctrl+F5 or Cmd+Shift+R)</li>
                <li>Clear any server-level caches (in RunCloud, cPanel, etc.)</li>
            </ol>
            
            <h2>Still Having Issues?</h2>
            <p>If you're still experiencing 403 errors after trying all these solutions, it's likely a server-level configuration issue. Contact your hosting provider's support team with:</p>
            <ol>
                <li>The specific URLs that are returning 403 errors</li>
                <li>A list of all the solutions you've already tried</li>
                <li>Request that they check server logs during your access attempts to identify the exact cause</li>
            </ol>
        </div>
    </div>
</body>
</html> 