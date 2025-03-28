<?php
/**
 * RunCloud Server Configuration Fix Script
 * 
 * This script attempts to diagnose and fix common RunCloud server configuration
 * issues that can cause 403 Forbidden errors for static files.
 * 
 * IMPORTANT: Only run this script as an administrator, then delete it.
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
    <title>RunCloud Server Configuration Fix</title>
    <style>
        body { font-family: sans-serif; line-height: 1.6; margin: 20px; }
        .container { max-width: 800px; margin: 0 auto; }
        .header { background: #23282d; color: white; padding: 20px; margin-bottom: 20px; }
        .content { background: #f1f1f1; padding: 20px; border-radius: 5px; }
        .button { background: #0073aa; color: white; padding: 10px 15px; text-decoration: none; border-radius: 3px; display: inline-block; }
        .log { background: #fff; padding: 15px; margin-top: 20px; border: 1px solid #ccc; max-height: 400px; overflow: auto; font-family: monospace; }
        .step { background: #fff; padding: 15px; margin-bottom: 15px; border-left: 4px solid #0073aa; }
        .step h3 { margin-top: 0; }
        pre { background: #f6f6f6; padding: 10px; overflow: auto; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>RunCloud Server Configuration Fix</h1>
        </div>
        <div class="content">
            <h2>Diagnose and Fix 403 Forbidden Errors</h2>
            
            <p>This tool provides a step-by-step guide to fix 403 Forbidden errors for static files in RunCloud-hosted WordPress sites.</p>
            
            <div class="log">
                <h3>Server Information:</h3>
                <?php
                    echo "<p>PHP Version: " . phpversion() . "</p>";
                    echo "<p>Server Software: " . $_SERVER['SERVER_SOFTWARE'] . "</p>";
                    echo "<p>Web Server: " . (strpos($_SERVER['SERVER_SOFTWARE'], 'LiteSpeed') !== false ? 'LiteSpeed' : (strpos($_SERVER['SERVER_SOFTWARE'], 'nginx') !== false ? 'Nginx' : 'Unknown')) . "</p>";
                ?>
            </div>
            
            <h2>Step-by-Step Fix</h2>
            
            <div class="step">
                <h3>Step 1: Check for RunCloud Web Application Settings</h3>
                <p>Log in to your RunCloud dashboard and check these settings for your web application:</p>
                <ol>
                    <li>Go to Web Applications → Select your application</li>
                    <li>Click "Settings" tab</li>
                    <li>Under "Security" section, verify that:<ul>
                        <li>Hotlink Protection is DISABLED</li>
                        <li>No IP blocking rules are targeting your IP</li>
                    </ul></li>
                </ol>
            </div>
            
            <div class="step">
                <h3>Step 2: LiteSpeed/Nginx Configuration</h3>
                <p>If you're using LiteSpeed or Nginx as your web server:</p>
                <ol>
                    <li>In RunCloud, go to Web Applications → Select your application</li>
                    <li>Click "Web Server" tab</li>
                    <li>Add the following rules to your server configuration:</li>
                </ol>
                
                <p><strong>For LiteSpeed:</strong></p>
<pre>
# Allow direct access to media files
&lt;FilesMatch "\.(svg|png|jpe?g|gif|ico|webp)$"&gt;
  Order allow,deny
  Allow from all
  Satisfy any
&lt;/FilesMatch&gt;

# Disable hotlinking protection for these directories
&lt;Directory "/home/runcloud/webapps/appoficiul/wp-content/uploads"&gt;
  Order allow,deny
  Allow from all
  Satisfy any
&lt;/Directory&gt;
</pre>
                
                <p><strong>For Nginx:</strong></p>
<pre>
# Allow direct access to media files
location ~* \.(svg|png|jpe?g|gif|ico|webp)$ {
  allow all;
  try_files $uri $uri/ /index.php?$args;
}

# Ensure uploads directory is accessible
location ^~ /wp-content/uploads/ {
  allow all;
  try_files $uri $uri/ /index.php?$args;
}
</pre>
            </div>
            
            <div class="step">
                <h3>Step 3: Create/Update .htaccess in Uploads Directory</h3>
                <p>Create an .htaccess file in your uploads directory with the following content:</p>
                
<pre>
# Allow direct access to all files in the uploads directory
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
  
  # SVG files - explicitly allow
  &lt;Files ~ "\.svg$"&gt;
    Require all granted
    Allow from all
  &lt;/Files&gt;
  
  # PNG files - explicitly allow
  &lt;Files ~ "\.png$"&gt;
    Require all granted
    Allow from all
  &lt;/Files&gt;

  # JPEG files - explicitly allow
  &lt;Files ~ "\.(jpg|jpeg)$"&gt;
    Require all granted
    Allow from all
  &lt;/Files&gt;
&lt;/IfModule&gt;
</pre>
                
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
  
  # SVG files - explicitly allow
  <Files ~ "\\.svg$">
    Require all granted
    Allow from all
  </Files>
  
  # PNG files - explicitly allow
  <Files ~ "\\.png$">
    Require all granted
    Allow from all
  </Files>

  # JPEG files - explicitly allow
  <Files ~ "\\.(jpg|jpeg)$">
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
            
            <div class="step">
                <h3>Step 4: Clear Caches</h3>
                <ol>
                    <li>Clear any WordPress caching plugins</li>
                    <li>In RunCloud dashboard, go to Web Applications → Select your app → Click "Clear Cache" button</li>
                    <li>Clear your browser cache (Ctrl+F5 or Cmd+Shift+R)</li>
                </ol>
            </div>
            
            <div class="step">
                <h3>Step 5: Test Access</h3>
                <p>Test direct access to the problematic files:</p>
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
                
                <p>If you still encounter 403 errors after implementing these fixes, contact RunCloud support with the following information:</p>
                <ol>
                    <li>The exact URLs that are returning 403 errors</li>
                    <li>The steps you've taken to resolve the issue</li>
                    <li>Ask them to check for any server-level rules that might be blocking access to these files</li>
                </ol>
            </div>
        </div>
    </div>
</body>
</html> 