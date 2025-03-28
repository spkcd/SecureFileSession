<?php
// Simple test file to diagnose server access issues
header('Content-Type: text/plain');

echo "SERVER ACCESS TEST\n";
echo "==================\n\n";

// Basic server info
echo "Server Info:\n";
echo "PHP Version: " . phpversion() . "\n";
echo "Server Software: " . $_SERVER['SERVER_SOFTWARE'] . "\n";
echo "User Agent: " . $_SERVER['HTTP_USER_AGENT'] . "\n\n";

// Check file permissions in uploads directory
echo "Uploads Directory Access Check:\n";
$upload_dir = wp_upload_dir();
echo "Uploads Base Dir: " . $upload_dir['basedir'] . "\n";
echo "Uploads Base URL: " . $upload_dir['baseurl'] . "\n";

// Test file paths
$test_paths = [
    '/2025/01/download-3.svg',
    '/2025/01/iphone_14_pro_mockup_03-914x1024.png',
    '/2025/01/download-2.svg'
];

foreach ($test_paths as $rel_path) {
    $file_path = $upload_dir['basedir'] . $rel_path;
    echo "\nFile: $rel_path\n";
    echo "Full path: $file_path\n";
    echo "Exists: " . (file_exists($file_path) ? "YES" : "NO") . "\n";
    if (file_exists($file_path)) {
        echo "Readable: " . (is_readable($file_path) ? "YES" : "NO") . "\n";
        echo "File permissions: " . substr(sprintf('%o', fileperms($file_path)), -4) . "\n";
        echo "File owner: " . fileowner($file_path) . "\n";
        echo "Current PHP owner: " . getmyuid() . "\n";
    }
}

// Check .htaccess files
echo "\n\nHTAccess Files Check:\n";

// Root .htaccess
echo "\nRoot .htaccess:\n";
$root_htaccess = ABSPATH . '.htaccess';
if (file_exists($root_htaccess) && is_readable($root_htaccess)) {
    echo file_get_contents($root_htaccess);
} else {
    echo "Cannot read root .htaccess\n";
}

// Uploads .htaccess
echo "\n\nUploads .htaccess:\n";
$uploads_htaccess = $upload_dir['basedir'] . '/.htaccess';
if (file_exists($uploads_htaccess) && is_readable($uploads_htaccess)) {
    echo file_get_contents($uploads_htaccess);
} else {
    echo "No .htaccess found in uploads directory\n";
}

// Check RunCloud config if available
echo "\n\nRunCloud Configuration:\n";
$runcloud_config = '/home/runcloud/webapps/appoficiul/nginx.conf';
if (file_exists($runcloud_config) && is_readable($runcloud_config)) {
    echo "RunCloud nginx.conf exists and is readable\n";
    // Don't print the entire config for security reasons
    echo "First 10 lines:\n";
    $lines = file($runcloud_config);
    for ($i = 0; $i < min(10, count($lines)); $i++) {
        echo $lines[$i];
    }
} else {
    echo "Cannot access RunCloud configuration\n";
}

echo "\n\nTest completed."; 