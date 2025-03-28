<?php
/**
 * Remote Storage Integration for Secure File Session
 */
class Secure_File_Session_Remote_Storage {
    /**
     * Plugin settings
     */
    private $settings;
    
    /**
     * S3 client
     */
    private $s3_client;
    
    /**
     * Initialize remote storage
     */
    public function __construct($settings) {
        $this->settings = $settings;
    }
    
    /**
     * Check if remote storage is enabled and configured
     */
    public function is_enabled() {
        if (empty($this->settings['remote_storage_enabled'])) {
            return false;
        }
        
        switch ($this->settings['remote_storage_type']) {
            case 's3':
                return $this->is_s3_configured();
            default:
                return false;
        }
    }
    
    /**
     * Check if S3 credentials are configured
     */
    public function is_s3_configured() {
        $creds = isset($this->settings['remote_storage_creds']) ? $this->settings['remote_storage_creds'] : array();
        
        return !empty($creds['s3_access_key']) && 
               !empty($creds['s3_secret_key']) && 
               !empty($creds['s3_bucket']);
    }
    
    /**
     * Get file from remote storage
     * 
     * @param string $file_path The relative path to the file
     * @param string $destination The destination path to save the file
     * @return bool True if file was successfully retrieved
     */
    public function get_file($file_path, $destination) {
        $file_path = ltrim($file_path, '/');
        
        // Check if file exists in cache
        if ($this->settings['remote_storage_cache_enabled']) {
            $cached_file = $this->get_cached_file($file_path);
            if ($cached_file) {
                // Copy the cached file to destination
                if (copy($cached_file, $destination)) {
                    return true;
                }
            }
        }
        
        // Get file from remote storage
        switch ($this->settings['remote_storage_type']) {
            case 's3':
                return $this->get_file_from_s3($file_path, $destination);
            default:
                return false;
        }
    }
    
    /**
     * Get file from AWS S3
     * 
     * @param string $file_path The relative path to the file
     * @param string $destination The destination path to save the file
     * @return bool True if file was successfully retrieved
     */
    private function get_file_from_s3($file_path, $destination) {
        // Ensure AWS SDK is loaded
        if (!$this->load_aws_sdk()) {
            return false;
        }
        
        try {
            // Get S3 client
            $s3 = $this->get_s3_client();
            
            // Get S3 bucket
            $bucket = $this->settings['remote_storage_creds']['s3_bucket'];
            
            // Add path prefix if set
            if (!empty($this->settings['remote_storage_creds']['s3_path_prefix'])) {
                $prefix = trim($this->settings['remote_storage_creds']['s3_path_prefix'], '/');
                $file_path = $prefix . '/' . $file_path;
            }
            
            // Create directory for destination if it doesn't exist
            $destination_dir = dirname($destination);
            if (!file_exists($destination_dir)) {
                wp_mkdir_p($destination_dir);
            }
            
            // Download the file
            $result = $s3->getObject([
                'Bucket' => $bucket,
                'Key'    => $file_path,
                'SaveAs' => $destination,
            ]);
            
            // If caching is enabled, save a copy to the cache
            if ($this->settings['remote_storage_cache_enabled'] && file_exists($destination)) {
                $this->cache_file($file_path, $destination);
            }
            
            return file_exists($destination);
        } catch (Exception $e) {
            error_log('Secure File Session S3 Error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get cached file
     * 
     * @param string $file_path The relative path to the file
     * @return string|bool Path to cached file or false if not found
     */
    private function get_cached_file($file_path) {
        $cache_dir = $this->get_cache_dir();
        $cache_file = $cache_dir . '/' . md5($file_path) . '_' . basename($file_path);
        
        if (file_exists($cache_file)) {
            // Check if cache has expired
            $file_time = filemtime($cache_file);
            $cache_expiration = isset($this->settings['remote_storage_cache_expiration']) ? 
                                (int)$this->settings['remote_storage_cache_expiration'] : 3600;
            
            if (time() - $file_time < $cache_expiration) {
                return $cache_file;
            }
            
            // Cache expired, delete file
            @unlink($cache_file);
        }
        
        return false;
    }
    
    /**
     * Cache a file
     * 
     * @param string $file_path The original file path (for reference)
     * @param string $file The file to cache
     * @return bool True if file was successfully cached
     */
    private function cache_file($file_path, $file) {
        $cache_dir = $this->get_cache_dir();
        $cache_file = $cache_dir . '/' . md5($file_path) . '_' . basename($file_path);
        
        return copy($file, $cache_file);
    }
    
    /**
     * Get cache directory
     * 
     * @return string Path to cache directory
     */
    private function get_cache_dir() {
        $upload_dir = wp_upload_dir();
        $cache_dir = $upload_dir['basedir'] . '/sfs-remote-cache';
        
        if (!file_exists($cache_dir)) {
            wp_mkdir_p($cache_dir);
            
            // Create index.php to prevent directory listing
            $index_file = $cache_dir . '/index.php';
            if (!file_exists($index_file)) {
                file_put_contents($index_file, '<?php // Silence is golden');
            }
            
            // Create .htaccess to prevent direct access
            $htaccess_file = $cache_dir . '/.htaccess';
            if (!file_exists($htaccess_file)) {
                file_put_contents($htaccess_file, "Order deny,allow\nDeny from all");
            }
        }
        
        return $cache_dir;
    }
    
    /**
     * Check if file exists in remote storage
     * 
     * @param string $file_path The relative path to the file
     * @return bool True if file exists
     */
    public function file_exists($file_path) {
        $file_path = ltrim($file_path, '/');
        
        // Check local cache first
        if ($this->settings['remote_storage_cache_enabled']) {
            $cached_file = $this->get_cached_file($file_path);
            if ($cached_file) {
                return true;
            }
        }
        
        // Check remote storage
        switch ($this->settings['remote_storage_type']) {
            case 's3':
                return $this->file_exists_in_s3($file_path);
            default:
                return false;
        }
    }
    
    /**
     * Check if file exists in AWS S3
     * 
     * @param string $file_path The relative path to the file
     * @return bool True if file exists
     */
    private function file_exists_in_s3($file_path) {
        // Ensure AWS SDK is loaded
        if (!$this->load_aws_sdk()) {
            return false;
        }
        
        try {
            // Get S3 client
            $s3 = $this->get_s3_client();
            
            // Get S3 bucket
            $bucket = $this->settings['remote_storage_creds']['s3_bucket'];
            
            // Add path prefix if set
            if (!empty($this->settings['remote_storage_creds']['s3_path_prefix'])) {
                $prefix = trim($this->settings['remote_storage_creds']['s3_path_prefix'], '/');
                $file_path = $prefix . '/' . $file_path;
            }
            
            // Check if object exists
            return $s3->doesObjectExist($bucket, $file_path);
        } catch (Exception $e) {
            error_log('Secure File Session S3 Error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Clean up cache
     */
    public function cleanup_cache() {
        $cache_dir = $this->get_cache_dir();
        
        if (!file_exists($cache_dir)) {
            return;
        }
        
        $files = glob($cache_dir . '/*');
        $cache_expiration = isset($this->settings['remote_storage_cache_expiration']) ? 
                            (int)$this->settings['remote_storage_cache_expiration'] : 3600;
        
        foreach ($files as $file) {
            if (is_file($file) && basename($file) !== 'index.php' && basename($file) !== '.htaccess') {
                $file_time = filemtime($file);
                
                if (time() - $file_time > $cache_expiration) {
                    @unlink($file);
                }
            }
        }
    }
    
    /**
     * Get filesize from remote storage
     * 
     * @param string $file_path The relative path to the file
     * @return int File size in bytes
     */
    public function get_filesize($file_path) {
        $file_path = ltrim($file_path, '/');
        
        // Check local cache first
        if ($this->settings['remote_storage_cache_enabled']) {
            $cached_file = $this->get_cached_file($file_path);
            if ($cached_file) {
                return filesize($cached_file);
            }
        }
        
        // Get from remote storage
        switch ($this->settings['remote_storage_type']) {
            case 's3':
                return $this->get_filesize_from_s3($file_path);
            default:
                return 0;
        }
    }
    
    /**
     * Get filesize from AWS S3
     * 
     * @param string $file_path The relative path to the file
     * @return int File size in bytes
     */
    private function get_filesize_from_s3($file_path) {
        // Ensure AWS SDK is loaded
        if (!$this->load_aws_sdk()) {
            return 0;
        }
        
        try {
            // Get S3 client
            $s3 = $this->get_s3_client();
            
            // Get S3 bucket
            $bucket = $this->settings['remote_storage_creds']['s3_bucket'];
            
            // Add path prefix if set
            if (!empty($this->settings['remote_storage_creds']['s3_path_prefix'])) {
                $prefix = trim($this->settings['remote_storage_creds']['s3_path_prefix'], '/');
                $file_path = $prefix . '/' . $file_path;
            }
            
            // Get object metadata
            $result = $s3->headObject([
                'Bucket' => $bucket,
                'Key'    => $file_path,
            ]);
            
            return $result['ContentLength'] ?? 0;
        } catch (Exception $e) {
            error_log('Secure File Session S3 Error: ' . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Load AWS SDK
     * 
     * @return bool True if AWS SDK was loaded successfully
     */
    private function load_aws_sdk() {
        // Check if AWS SDK is already loaded
        if (class_exists('Aws\S3\S3Client')) {
            return true;
        }
        
        // Try to load AWS SDK from vendor directory
        $aws_autoloader = SECURE_FILE_SESSION_PLUGIN_DIR . 'vendor/autoload.php';
        
        if (file_exists($aws_autoloader)) {
            require_once $aws_autoloader;
            return class_exists('Aws\S3\S3Client');
        }
        
        // Try to load AWS SDK from other plugins
        $plugins_dir = WP_PLUGIN_DIR;
        $potential_paths = [
            '/amazon-s3-and-cloudfront/vendor/autoload.php',
            '/amazon-web-services/vendor/autoload.php',
            '/wp-offload-media/vendor/autoload.php',
            '/wp-offload-media-lite/vendor/autoload.php',
        ];
        
        foreach ($potential_paths as $path) {
            if (file_exists($plugins_dir . $path)) {
                require_once $plugins_dir . $path;
                if (class_exists('Aws\S3\S3Client')) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Get S3 client
     * 
     * @return \Aws\S3\S3Client S3 client
     */
    private function get_s3_client() {
        // Return existing client if available
        if ($this->s3_client) {
            return $this->s3_client;
        }
        
        // Ensure AWS SDK is loaded
        if (!$this->load_aws_sdk()) {
            throw new Exception('AWS SDK not found');
        }
        
        // Get S3 credentials
        $creds = $this->settings['remote_storage_creds'];
        
        // Build configuration array
        $config = [
            'version'     => 'latest',
            'region'      => $creds['s3_region'] ?? 'us-east-1',
            'credentials' => [
                'key'    => $creds['s3_access_key'],
                'secret' => $creds['s3_secret_key'],
            ],
        ];
        
        // Add custom endpoint if set (for S3-compatible storage like Minio, DigitalOcean Spaces, etc.)
        if (!empty($creds['s3_endpoint'])) {
            $config['endpoint'] = $creds['s3_endpoint'];
        }
        
        // Create S3 client
        $this->s3_client = new \Aws\S3\S3Client($config);
        
        return $this->s3_client;
    }
} 