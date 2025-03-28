<?php
/**
 * Integrations with form builders and page builders
 */
class Secure_File_Session_Integrations {
    /**
     * Main plugin instance
     */
    private $main;
    
    /**
     * Constructor
     */
    public function __construct($main) {
        $this->plugin = $main;
        $this->init();
    }
    
    /**
     * Initialize integrations
     */
    public function init() {
        // Add Elementor integration
        if (did_action('elementor/loaded')) {
            add_filter('elementor/frontend/the_content', array($this, 'process_elementor_content'), 999);
            add_action('elementor/element/before_parse_css', array($this, 'before_elementor_css'), 10, 2);
            add_action('elementor/frontend/after_enqueue_styles', array($this, 'enqueue_elementor_scripts'));
        }
        
        // Add JetEngine integration
        if (class_exists('Jet_Engine')) {
            add_filter('jet-engine/listings/frontend/rendered-content', array($this, 'process_jetengine_content'), 999);
        }
        
        // JetFormBuilder integration
        add_filter('jet-form-builder/file-upload/custom-url', array($this, 'secure_jetformbuilder_files'), 10, 3);
    }
    
    /**
     * Process Elementor content to secure file URLs
     */
    public function process_elementor_content($content) {
        // Skip if no content or upload URL is not available
        if (empty($content)) {
            return $content;
        }
        
        // Skip if on an excluded page
        if ($this->plugin->is_excluded_page()) {
            return $content;
        }
        
        // Get upload directory information
        $upload_dir = wp_upload_dir();
        $upload_url = $upload_dir['baseurl'];
        
        if (empty($upload_url)) {
            return $content;
        }
        
        // Get excluded files pattern
        $excluded_pattern = $this->plugin->get_excluded_files_pattern();
        
        // Replace file URLs with secure URLs
        $pattern = '/(href|src)=(["\'])('. preg_quote($upload_url, '/') . '([^"\']+))\\2/i';
        
        return preg_replace_callback($pattern, function($matches) use ($excluded_pattern) {
            $attr = $matches[1];
            $quote = $matches[2];
            $url = $matches[3];
            $file_path = $matches[4];
            
            // Skip if file matches excluded pattern
            if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
                return $attr . '=' . $quote . $url . $quote;
            }
            
            // Create secure URL
            $secure_url = $this->plugin->get_secure_url($file_path);
            
            return $attr . '=' . $quote . $secure_url . $quote;
        }, $content);
    }
    
    /**
     * Process JetEngine content to secure file URLs
     */
    public function process_jetengine_content($content) {
        // Skip if no content or upload URL is not available
        if (empty($content)) {
            return $content;
        }
        
        // Skip if on an excluded page
        if ($this->plugin->is_excluded_page()) {
            return $content;
        }
        
        // Get upload directory information
        $upload_dir = wp_upload_dir();
        $upload_url = $upload_dir['baseurl'];
        
        if (empty($upload_url)) {
            return $content;
        }
        
        // Get excluded files pattern
        $excluded_pattern = $this->plugin->get_excluded_files_pattern();
        
        // Replace file URLs with secure URLs
        $pattern = '/(href|src)=(["\'])('. preg_quote($upload_url, '/') . '([^"\']+))\\2/i';
        
        return preg_replace_callback($pattern, function($matches) use ($excluded_pattern) {
            $attr = $matches[1];
            $quote = $matches[2];
            $url = $matches[3];
            $file_path = $matches[4];
            
            // Skip if file matches excluded pattern
            if ($excluded_pattern && preg_match($excluded_pattern, $file_path)) {
                return $attr . '=' . $quote . $url . $quote;
            }
            
            // Create secure URL
            $secure_url = $this->plugin->get_secure_url($file_path);
            
            return $attr . '=' . $quote . $secure_url . $quote;
        }, $content);
    }
    
    /**
     * Secure files uploaded via Elementor forms
     */
    public function secure_elementor_form_files($record, $handler) {
        // Skip if on an excluded page
        if ($this->plugin->is_excluded_page()) {
            return;
        }
        
        $form_fields = $record->get('fields');
        
        // Check if there are file fields
        foreach ($form_fields as $id => $field) {
            if (isset($field['type']) && $field['type'] === 'upload' && !empty($field['value']['url'])) {
                // The file URL is already stored in the database, we just modify how it's accessed
                $this->register_elementor_file_for_js($field['value']['url'], $id);
            }
        }
    }
    
    /**
     * Add a script to replace Elementor file URLs in frontend
     */
    private function register_elementor_file_for_js($url, $field_id) {
        // Only enqueue script once
        static $script_added = false;
        
        if (!$script_added) {
            add_action('wp_footer', array($this, 'add_elementor_file_js'));
            $script_added = true;
        }
        
        // Store the URL to be processed
        add_filter('secure_file_session_elementor_urls', function($urls) use ($url, $field_id) {
            $urls[$field_id] = $url;
            return $urls;
        });
    }
    
    /**
     * Add JavaScript to replace Elementor file URLs
     */
    public function add_elementor_file_js() {
        $urls = apply_filters('secure_file_session_elementor_urls', array());
        
        if (empty($urls)) {
            return;
        }
        
        echo '<script type="text/javascript">';
        echo 'document.addEventListener("DOMContentLoaded", function() {';
        
        // Add helper functions for file size
        echo 'function formatFileSize(bytes) {
            if (bytes === 0) return "0 Bytes";
            const k = 1024;
            const sizes = ["Bytes", "KB", "MB", "GB"];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
        }
        
        async function getFileSize(url) {
            try {
                const response = await fetch(url, { 
                    method: "HEAD",
                    cache: "no-store",
                    headers: {
                        "Pragma": "no-cache",
                        "Cache-Control": "no-cache"
                    }
                });
                if (response.ok) {
                    const contentLength = response.headers.get("Content-Length");
                    if (contentLength) {
                        return formatFileSize(parseInt(contentLength, 10));
                    } else {
                        return "(File)";
                    }
                } else {
                    return "(File)";
                }
            } catch (e) {
                console.log("Error fetching file size", e);
                return "(File)";
            }
        }';
        
        foreach ($urls as $field_id => $url) {
            // Only secure if it's an upload URL
            $upload_url = wp_upload_dir()['baseurl'];
            if (strpos($url, $upload_url) === 0) {
                // Get relative path to file
                $file_path = str_replace($upload_url . '/', '', $url);
                
                // Extract original filename from the path
                $original_filename = basename($file_path);
                
                // Get file extension for styling
                $file_ext = strtolower(pathinfo($original_filename, PATHINFO_EXTENSION));
                
                // Get secure URL from main plugin and file size
                $secure_url = $this->plugin->get_secure_url($file_path);
                
                // Extract the file size from URL if it's included
                echo 'var fileSize = "";';
                echo 'const urlParams = new URLSearchParams(' . esc_js($secure_url) . '.split("?")[1]);';
                echo 'if (urlParams.has("sfs_size")) {';
                echo '    fileSize = decodeURIComponent(urlParams.get("sfs_size"));';
                echo '}';
                
                // Update any links in the DOM
                echo 'var links = document.querySelectorAll("a[href=\'' . esc_js($url) . '\']");';
                echo 'for (var i = 0; i < links.length; i++) {';
                // Force download
                echo '  links[i].setAttribute("download", "");';
                // Set secure URL
                echo '  links[i].href = "' . esc_js($secure_url) . '";';
                // Preserve the original filename as the link text with file extension badge
                echo '  if (links[i].textContent === "' . esc_js($url) . '" || links[i].textContent.includes("secure-file-session.php")) {';
                echo '    links[i].textContent = "";';
                
                // Add file extension badge
                echo '    var extBadge = document.createElement("span");';
                echo '    extBadge.className = "sfs-ext-badge sfs-ext-' . esc_js($file_ext) . '";';
                echo '    extBadge.textContent = "' . esc_js($file_ext) . '";';
                
                // Create file details container with filename and size
                echo '    var fileDetails = document.createElement("div");';
                echo '    fileDetails.className = "sfs-file-details";';
                
                // Add filename
                echo '    var filenameElement = document.createElement("span");';
                echo '    filenameElement.textContent = "' . esc_js($original_filename) . '";';
                echo '    fileDetails.appendChild(filenameElement);';
                
                // Add file size element
                echo '    var fileSizeElement = document.createElement("span");';
                echo '    fileSizeElement.className = "sfs-file-size";';
                
                // Use server-provided size if available
                echo '    if (fileSize) {';
                echo '      fileSizeElement.textContent = fileSize;';
                echo '    } else {';
                echo '      fileSizeElement.textContent = "Fetching size...";';
                echo '      // Fetch and update file size';
                echo '      (function(element) {';
                echo '        getFileSize("' . esc_js($secure_url) . '").then(function(size) {';
                echo '          if (size) {';
                echo '            element.textContent = size;';
                echo '          } else {';
                echo '            element.textContent = "(File)";';
                echo '          }';
                echo '        });';
                echo '      })(fileSizeElement);';
                echo '    }';
                echo '    fileDetails.appendChild(fileSizeElement);';
                
                // Add the badge and file details to the link
                echo '    links[i].appendChild(extBadge);';
                echo '    links[i].appendChild(fileDetails);';
                
                echo '  }';
                echo '}';
            }
        }
        
        echo '});';
        echo '</script>';
    }
    
    /**
     * Hook for securing JetEngine forms uploaded files
     */
    public function secure_jetengine_files($url, $file_data) {
        // Skip if on an excluded page
        if ($this->plugin->is_excluded_page()) {
            return $url;
        }
        
        // Only secure if it's an upload URL
        $upload_url = wp_upload_dir()['baseurl'];
        if (strpos($url, $upload_url) !== 0) {
            return $url;
        }
        
        // Get the file path relative to uploads directory
        $file_path = str_replace($upload_url . '/', '', $url);
        
        // Get the secure URL from main plugin
        return $this->plugin->get_secure_url($file_path);
    }
    
    /**
     * Hook for securing JetFormBuilder uploads
     */
    public function secure_jetformbuilder_files($url, $path, $field_name) {
        // Skip if on an excluded page
        if ($this->plugin->is_excluded_page()) {
            return $url;
        }
        
        // Only secure if it's an upload URL
        $upload_url = wp_upload_dir()['baseurl'];
        if (strpos($url, $upload_url) !== 0) {
            return $url;
        }
        
        // Get the file path relative to uploads directory
        $file_path = str_replace($upload_url . '/', '', $url);
        
        // Get the secure URL from main plugin
        return $this->plugin->get_secure_url($file_path);
    }
    
    /**
     * Handle Elementor CSS to secure background image URLs
     */
    public function before_elementor_css($post_css, $element) {
        // Skip if on an excluded page
        if ($this->plugin->is_excluded_page()) {
            return;
        }
        
        // Get upload directory information
        $upload_dir = wp_upload_dir();
        $upload_url = $upload_dir['baseurl'];
        
        // Check URL patterns in CSS
        $css = $post_css->get_stylesheet();
        
        // Replace upload URLs with secure URLs in background images
        $pattern = '/url\s*\(\s*[\'"]?\s*(' . preg_quote($upload_url, '/') . '([^)\'"]*))[\'"]?\s*\)/i';
        
        $css->add_changes('sfs_secure_css', [
            'type' => 'update',
            'callback' => function($css_string) use ($pattern, $upload_url) {
                return preg_replace_callback($pattern, function($matches) use ($upload_url) {
                    $full_url = $matches[1];
                    $file_path = str_replace($upload_url . '/', '', $full_url);
                    
                    // Get secure URL
                    $secure_url = $this->plugin->get_secure_url($file_path);
                    
                    return 'url("' . $secure_url . '")';
                }, $css_string);
            }
        ]);
    }
    
    /**
     * Enqueue scripts and styles for Elementor frontend
     */
    public function enqueue_elementor_scripts() {
        // Skip if on an excluded page
        if ($this->plugin->is_excluded_page()) {
            return;
        }
        
        // Add inline CSS for file styling
        $css = '
        .sfs-ext-badge {
            display: inline-block;
            background: #f1f1f1;
            color: #333;
            text-transform: uppercase;
            padding: 2px 6px;
            font-size: 10px;
            border-radius: 3px;
            margin-right: 8px;
            font-weight: bold;
        }
        .sfs-file-details {
            display: flex;
            flex-direction: column;
            margin-left: 4px;
        }
        .sfs-file-size {
            color: #777;
            font-size: 0.8em;
            font-style: italic;
        }
        
        /* Specific extension colors */
        .sfs-ext-pdf { background: #f40f02; color: white; }
        .sfs-ext-doc, .sfs-ext-docx { background: #295498; color: white; }
        .sfs-ext-xls, .sfs-ext-xlsx { background: #1f7244; color: white; }
        .sfs-ext-ppt, .sfs-ext-pptx { background: #d24625; color: white; }
        .sfs-ext-zip, .sfs-ext-rar { background: #ffd700; color: #333; }
        .sfs-ext-jpg, .sfs-ext-jpeg, .sfs-ext-png, 
        .sfs-ext-gif, .sfs-ext-svg { background: #3db46d; color: white; }
        ';
        
        wp_add_inline_style('elementor-frontend', $css);
    }
} 