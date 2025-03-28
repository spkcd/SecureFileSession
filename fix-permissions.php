<?php
/**
 * Permission Fixing Script for WordPress Uploads Directory
 * 
 * IMPORTANT: Only run this script as an administrator, then delete it.
 */

// Basic security check
if (!current_user_can('manage_options')) {
    wp_die('You do not have sufficient permissions to access this page.');
}

function fix_directory_permissions($dir, $file_mode = 0644, $dir_mode = 0755) {
    echo "Processing directory: $dir<br>";
    flush();
    
    // Fix directory permissions
    @chmod($dir, $dir_mode);
    
    $items = @scandir($dir);
    if (!$items) {
        echo "⚠️ Could not read directory: $dir<br>";
        return;
    }
    
    foreach ($items as $item) {
        // Skip . and ..
        if ($item == '.' || $item == '..') {
            continue;
        }
        
        $path = $dir . '/' . $item;
        
        // Check if it's a directory
        if (is_dir($path)) {
            // Recursively process subdirectories
            fix_directory_permissions($path, $file_mode, $dir_mode);
        } else {
            // Fix file permissions
            $before = substr(sprintf('%o', fileperms($path)), -4);
            @chmod($path, $file_mode);
            $after = substr(sprintf('%o', fileperms($path)), -4);
            
            if ($before !== $after) {
                echo "✅ Fixed: $path ($before → $after)<br>";
            }
        }
    }
}

// Start HTML output
?>
<!DOCTYPE html>
<html>
<head>
    <title>WordPress Uploads Permission Fixer</title>
    <style>
        body { font-family: sans-serif; line-height: 1.6; margin: 20px; }
        .container { max-width: 800px; margin: 0 auto; }
        .header { background: #23282d; color: white; padding: 20px; margin-bottom: 20px; }
        .content { background: #f1f1f1; padding: 20px; border-radius: 5px; }
        .button { background: #0073aa; color: white; padding: 10px 15px; text-decoration: none; border-radius: 3px; display: inline-block; }
        .log { background: #fff; padding: 15px; margin-top: 20px; border: 1px solid #ccc; max-height: 400px; overflow: auto; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WordPress Uploads Permission Fixer</h1>
        </div>
        <div class="content">
            <?php
            if (!isset($_POST['fix_permissions'])) {
                // Show information and confirmation button
                ?>
                <p><strong>This tool will:</strong></p>
                <ul>
                    <li>Set all directory permissions to 755 (rwxr-xr-x)</li>
                    <li>Set all file permissions to 644 (rw-r--r--)</li>
                    <li>Create a proper .htaccess file in the uploads directory</li>
                </ul>
                
                <p><strong>Warning:</strong> Only run this script if you're experiencing permission issues with your media files.</p>
                
                <form method="post">
                    <input type="submit" name="fix_permissions" value="Fix Permissions" class="button">
                </form>
                <?php
            } else {
                // Fix permissions
                echo "<h2>Processing Permissions</h2>";
                echo "<div class='log'>";
                
                // Get upload directory
                $upload_dir = wp_upload_dir();
                $base_dir = $upload_dir['basedir'];
                
                echo "<p>Uploads directory: $base_dir</p>";
                
                // Fix permissions recursively
                fix_directory_permissions($base_dir);
                
                // Create/update .htaccess in uploads directory
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
  <Files ~ "\.svg$">
    Require all granted
    Allow from all
  </Files>
  
  # PNG files - explicitly allow
  <Files ~ "\.png$">
    Require all granted
    Allow from all
  </Files>

  # JPEG files - explicitly allow
  <Files ~ "\.(jpg|jpeg)$">
    Require all granted
    Allow from all
  </Files>
</IfModule>
EOT;
                
                $htaccess_file = trailingslashit($base_dir) . '.htaccess';
                $result = @file_put_contents($htaccess_file, $htaccess_content);
                
                if ($result !== false) {
                    echo "✅ Created/updated .htaccess file in uploads directory<br>";
                    @chmod($htaccess_file, 0644);
                } else {
                    echo "⚠️ Failed to create .htaccess file in uploads directory<br>";
                }
                
                echo "</div>";
                
                echo "<p><strong>Next steps:</strong></p>";
                echo "<ol>";
                echo "<li>Clear your browser cache</li>";
                echo "<li>Refresh your site and check if media files load properly</li>";
                echo "<li>If issues persist, check server logs for more information</li>";
                echo "</ol>";
                
                echo "<p><a href='?'>Go back</a></p>";
            }
            ?>
        </div>
    </div>
</body>
</html> 