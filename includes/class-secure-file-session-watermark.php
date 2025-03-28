<?php
/**
 * Watermarking functionality for Secure File Session
 */
class Secure_File_Session_Watermark {
    /**
     * Settings
     */
    private $settings;
    
    /**
     * Initialize the watermarking functionality
     */
    public function __construct($settings) {
        $this->settings = $settings;
    }
    
    /**
     * Apply watermark to a file based on its type
     * 
     * @param string $file_path Path to the original file
     * @param string $user_info User information for watermark
     * @return string Path to the watermarked file or original file if watermarking fails
     */
    public function apply_watermark($file_path, $user_info = '') {
        // Check if watermarking is enabled
        if (empty($this->settings['watermark_enabled'])) {
            return $file_path;
        }
        
        // Get file extension
        $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        
        // Create temporary directory if it doesn't exist
        $upload_dir = wp_upload_dir();
        $temp_dir = $upload_dir['basedir'] . '/sfs-watermarked';
        
        if (!file_exists($temp_dir)) {
            wp_mkdir_p($temp_dir);
            
            // Create .htaccess file to prevent direct access
            $htaccess_file = $temp_dir . '/.htaccess';
            $htaccess_content = "Order deny,allow\nDeny from all\n";
            file_put_contents($htaccess_file, $htaccess_content);
            
            // Create index.php file to prevent directory listing
            $index_file = $temp_dir . '/index.php';
            $index_content = "<?php\n// Silence is golden.\n";
            file_put_contents($index_file, $index_content);
        }
        
        // Create a watermarked file name
        $filename = basename($file_path);
        $watermarked_filename = md5($filename . time() . rand(1000, 9999)) . '.' . $ext;
        $watermarked_file = $temp_dir . '/' . $watermarked_filename;
        
        // Apply watermark based on file type
        $result = false;
        
        if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif']) && !empty($this->settings['watermark_images'])) {
            $result = $this->watermark_image($file_path, $watermarked_file, $user_info);
        } elseif ($ext === 'pdf' && !empty($this->settings['watermark_pdfs'])) {
            $result = $this->watermark_pdf($file_path, $watermarked_file, $user_info);
        }
        
        // If watermarking was successful, return the path to the watermarked file
        if ($result) {
            // Schedule cleanup of watermarked file (delete after 1 hour)
            wp_schedule_single_event(time() + 3600, 'sfs_cleanup_watermarked_file', array($watermarked_file));
            return $watermarked_file;
        }
        
        // If watermarking failed, return the original file
        return $file_path;
    }
    
    /**
     * Add watermark to an image
     */
    private function watermark_image($source_file, $destination_file, $user_info) {
        // Check if GD library is available
        if (!function_exists('imagecreatetruecolor')) {
            return false;
        }
        
        // Get image information
        $info = getimagesize($source_file);
        if (!$info) {
            return false;
        }
        
        // Create image resource based on file type
        $source_image = $this->create_image_from_file($source_file, $info[2]);
        if (!$source_image) {
            return false;
        }
        
        // Get image dimensions
        $width = imagesx($source_image);
        $height = imagesy($source_image);
        
        // Prepare watermark text
        $watermark_text = $this->prepare_watermark_text($user_info);
        
        // Get watermark text settings
        $font_size = !empty($this->settings['watermark_font_size']) ? (int)$this->settings['watermark_font_size'] : 20;
        $font_file = SECURE_FILE_SESSION_PLUGIN_DIR . 'assets/fonts/OpenSans-Regular.ttf';
        
        // If the font file doesn't exist, try to use a system font
        if (!file_exists($font_file)) {
            $font_file = 5; // Use built-in font
        }
        
        // Calculate text size
        $text_box = imagettfbbox($font_size, 0, $font_file, $watermark_text);
        $text_width = abs($text_box[4] - $text_box[0]);
        $text_height = abs($text_box[5] - $text_box[1]);
        
        // Get watermark position
        $position = !empty($this->settings['watermark_position']) ? $this->settings['watermark_position'] : 'center';
        
        // Calculate watermark position
        list($pos_x, $pos_y) = $this->calculate_position($position, $width, $height, $text_width, $text_height);
        
        // Parse watermark color
        $color = !empty($this->settings['watermark_color']) ? $this->settings['watermark_color'] : 'rgba(0,0,0,0.3)';
        $rgba = $this->parse_color($color);
        
        // Create watermark text color
        $text_color = imagecolorallocatealpha(
            $source_image, 
            $rgba['r'], 
            $rgba['g'], 
            $rgba['b'], 
            (1 - $rgba['a']) * 127 // Convert 0-1 to 0-127
        );
        
        // Add watermark text to image
        if (function_exists('imagettftext')) {
            imagettftext(
                $source_image, 
                $font_size, 
                0, 
                $pos_x, 
                $pos_y, 
                $text_color, 
                $font_file, 
                $watermark_text
            );
        } else {
            // Fallback to simple text
            imagestring(
                $source_image, 
                5, 
                $pos_x, 
                $pos_y, 
                $watermark_text, 
                $text_color
            );
        }
        
        // Save watermarked image
        $result = $this->save_image($source_image, $destination_file, $info[2]);
        
        // Clean up
        imagedestroy($source_image);
        
        return $result;
    }
    
    /**
     * Add watermark to a PDF
     */
    private function watermark_pdf($source_file, $destination_file, $user_info) {
        // Check if FPDI/TCPDF libraries are available
        if (!class_exists('FPDI') && !class_exists('setasign\\Fpdi\\Fpdi')) {
            // Try to include FPDI from the plugin
            $fpdi_file = SECURE_FILE_SESSION_PLUGIN_DIR . 'includes/vendor/autoload.php';
            if (file_exists($fpdi_file)) {
                require_once $fpdi_file;
            } else {
                return false;
            }
        }
        
        // Load FPDI library
        if (class_exists('setasign\\Fpdi\\Fpdi')) {
            $pdf = new \setasign\Fpdi\Fpdi();
        } elseif (class_exists('FPDI')) {
            $pdf = new FPDI();
        } else {
            return false;
        }
        
        try {
            // Get number of pages
            $page_count = $pdf->setSourceFile($source_file);
            
            // Prepare watermark text
            $watermark_text = $this->prepare_watermark_text($user_info);
            
            // Loop through all pages
            for ($i = 1; $i <= $page_count; $i++) {
                // Import page
                $template = $pdf->importPage($i);
                $size = $pdf->getTemplateSize($template);
                
                // Add page with same orientation
                $pdf->AddPage($size['width'] > $size['height'] ? 'L' : 'P', array($size['width'], $size['height']));
                
                // Use the imported page
                $pdf->useTemplate($template);
                
                // Get watermark position
                $position = !empty($this->settings['watermark_position']) ? $this->settings['watermark_position'] : 'center';
                
                // Parse watermark color
                $color = !empty($this->settings['watermark_color']) ? $this->settings['watermark_color'] : 'rgba(0,0,0,0.3)';
                $rgba = $this->parse_color($color);
                
                // Set text color
                $pdf->SetTextColor($rgba['r'], $rgba['g'], $rgba['b']);
                $pdf->SetAlpha($rgba['a']);
                
                // Set font
                $font_size = !empty($this->settings['watermark_font_size']) ? (int)$this->settings['watermark_font_size'] : 20;
                $pdf->SetFont('Helvetica', '', $font_size);
                
                // Get text width
                $text_width = $pdf->GetStringWidth($watermark_text);
                
                // Calculate position
                switch ($position) {
                    case 'top-left':
                        $x = 10;
                        $y = 10 + $font_size;
                        break;
                    case 'top-right':
                        $x = $size['width'] - $text_width - 10;
                        $y = 10 + $font_size;
                        break;
                    case 'bottom-left':
                        $x = 10;
                        $y = $size['height'] - 10;
                        break;
                    case 'bottom-right':
                        $x = $size['width'] - $text_width - 10;
                        $y = $size['height'] - 10;
                        break;
                    case 'center':
                    default:
                        $x = ($size['width'] - $text_width) / 2;
                        $y = $size['height'] / 2;
                        break;
                }
                
                // Add watermark text
                $pdf->Text($x, $y, $watermark_text);
            }
            
            // Save to file
            $pdf->Output($destination_file, 'F');
            
            return true;
        } catch (Exception $e) {
            error_log('Error watermarking PDF: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Prepare watermark text with placeholders
     */
    private function prepare_watermark_text($user_info = '') {
        $text = !empty($this->settings['watermark_text']) ? $this->settings['watermark_text'] : 'Downloaded by: %username% on %date%';
        
        // Get current user info
        $current_user = wp_get_current_user();
        $username = $current_user->exists() ? $current_user->user_login : 'Guest';
        $display_name = $current_user->exists() ? $current_user->display_name : 'Guest';
        $email = $current_user->exists() ? $current_user->user_email : 'Unknown';
        $user_ip = $_SERVER['REMOTE_ADDR'];
        
        // If additional user info was provided, use it
        if (!empty($user_info)) {
            $username = isset($user_info['username']) ? $user_info['username'] : $username;
            $display_name = isset($user_info['display_name']) ? $user_info['display_name'] : $display_name;
            $email = isset($user_info['email']) ? $user_info['email'] : $email;
            $user_ip = isset($user_info['ip']) ? $user_info['ip'] : $user_ip;
        }
        
        // Replace placeholders
        $text = str_replace(
            array('%username%', '%display_name%', '%email%', '%ip%', '%date%', '%time%'),
            array(
                $username,
                $display_name,
                $email,
                $user_ip,
                date_i18n(get_option('date_format')),
                date_i18n(get_option('time_format'))
            ),
            $text
        );
        
        return $text;
    }
    
    /**
     * Calculate position for watermark
     */
    private function calculate_position($position, $width, $height, $text_width, $text_height) {
        switch ($position) {
            case 'top-left':
                return array(10, 10 + $text_height);
            case 'top-right':
                return array($width - $text_width - 10, 10 + $text_height);
            case 'bottom-left':
                return array(10, $height - 10);
            case 'bottom-right':
                return array($width - $text_width - 10, $height - 10);
            case 'center':
            default:
                return array(($width - $text_width) / 2, ($height + $text_height) / 2);
        }
    }
    
    /**
     * Parse color from rgba() or hex format
     */
    private function parse_color($color) {
        // Default rgba values
        $rgba = array(
            'r' => 0,
            'g' => 0,
            'b' => 0,
            'a' => 0.3
        );
        
        // Parse rgba() format
        if (preg_match('/rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([\d\.]+)\s*\)/i', $color, $matches)) {
            $rgba['r'] = (int)$matches[1];
            $rgba['g'] = (int)$matches[2];
            $rgba['b'] = (int)$matches[3];
            $rgba['a'] = (float)$matches[4];
        }
        // Parse rgb() format
        elseif (preg_match('/rgb\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)/i', $color, $matches)) {
            $rgba['r'] = (int)$matches[1];
            $rgba['g'] = (int)$matches[2];
            $rgba['b'] = (int)$matches[3];
            $rgba['a'] = 1;
        }
        // Parse hex format (#RGB or #RRGGBB)
        elseif (preg_match('/#([0-9a-f]{3}|[0-9a-f]{6})/i', $color, $matches)) {
            $hex = $matches[1];
            if (strlen($hex) == 3) {
                $hex = $hex[0] . $hex[0] . $hex[1] . $hex[1] . $hex[2] . $hex[2];
            }
            $rgba['r'] = hexdec(substr($hex, 0, 2));
            $rgba['g'] = hexdec(substr($hex, 2, 2));
            $rgba['b'] = hexdec(substr($hex, 4, 2));
            $rgba['a'] = 1;
        }
        
        // Ensure values are in valid range
        $rgba['r'] = min(255, max(0, $rgba['r']));
        $rgba['g'] = min(255, max(0, $rgba['g']));
        $rgba['b'] = min(255, max(0, $rgba['b']));
        $rgba['a'] = min(1, max(0, $rgba['a']));
        
        return $rgba;
    }
    
    /**
     * Create image resource from file
     */
    private function create_image_from_file($file, $type) {
        switch ($type) {
            case IMAGETYPE_JPEG:
                return imagecreatefromjpeg($file);
            case IMAGETYPE_PNG:
                return imagecreatefrompng($file);
            case IMAGETYPE_GIF:
                return imagecreatefromgif($file);
            default:
                return false;
        }
    }
    
    /**
     * Save image to file
     */
    private function save_image($image, $file, $type) {
        switch ($type) {
            case IMAGETYPE_JPEG:
                return imagejpeg($image, $file, 90);
            case IMAGETYPE_PNG:
                return imagepng($image, $file, 9);
            case IMAGETYPE_GIF:
                return imagegif($image, $file);
            default:
                return false;
        }
    }
} 