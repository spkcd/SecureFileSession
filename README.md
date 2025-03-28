# Secure File Session

A WordPress plugin that secures uploaded files by generating session-based secure URLs, preventing direct access to your uploads.

## Description

Secure File Session protects your WordPress uploads by dynamically replacing file links with secure, tokenized URLs. Files are only accessible to users with a valid token in their current browsing session. This prevents unauthorized access to your files through direct URL sharing.

### Key Features

- **Secure Token Generation**: Creates session-bound, time-limited tokens for file access
- **Original Filename Display**: Shows original filenames instead of cryptic secure URLs
- **File Size Display**: Shows file size beneath filenames for better user experience
- **Multiple Integration Points**: Works with standard content, Elementor, and JetEngine
- **Admin Settings Panel**: Easily configure protection settings
- **Token Viewer**: See all active tokens and their expiration times
- **Session Debugging**: Troubleshoot session-related issues
- **Access Logging**: Track file access attempts (successful and failed)
- **IP Locking**: Further restrict access by binding tokens to the user's IP address

## Installation

1. Upload the `secure-file-session` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Configure the plugin via Settings > Secure File Session

## Configuration

### General Settings

- **Protection Status**: Enable or disable file protection
- **Token Expiration**: Set how long tokens remain valid (in seconds)
- **Post Types**: Choose which post types should have protected file links

### Security Options

- **Access Logging**: Enable to track file access attempts
- **IP Lock**: Bind tokens to the user's IP address for extra security
- **Debug Mode**: Enable detailed debugging information (not recommended for production)
- **Excluded Pages**: Specify pages where file URLs should not be secured, such as login pages

## Usage

Once activated, the plugin automatically replaces file URLs in your content with secure, tokenized links. No additional setup is required for basic functionality.

### Admin Interface

The plugin adds a settings page under Settings > Secure File Session with the following tabs:

1. **Settings**: Configure protection and security options
2. **Active Tokens**: View and manage active security tokens
3. **Access Logs**: View file access attempts if logging is enabled
4. **Debug**: View session and system information for troubleshooting

### Excluding Pages

You can specify certain pages where files should not be secured by adding their paths to the Excluded Pages setting. This is useful for pages like:

- `/login/` - Prevent securing images on the login page
- `/public-downloads/*` - Skip securing files in a public downloads section
- `/landing/` - Keep marketing landing pages using direct URLs

Exclusions accept exact paths, partial matches, and wildcard patterns (using * at the end).

## Technical Details

### How it Works

1. When content is rendered, the plugin scans for file links
2. File URLs are replaced with secure links containing a token
3. Tokens are stored as transients with an expiration time
4. When a user clicks a secure link, the token is validated
5. If valid, the file is served securely via PHP
6. The file is streamed with proper headers for download/display

### Security Measures

- **Session Binding**: Tokens are bound to the user's PHP session
- **Time Limitation**: Tokens expire after a configurable time period
- **IP Restriction**: Optional binding of tokens to the user's IP address
- **Path Validation**: Server-side validation prevents path traversal attacks
- **Direct Access Prevention**: Files are served through PHP, not directly

## FAQ

### Does this work with page caching?

Yes, the plugin is designed to work with page caching plugins. The secure URLs are generated client-side via JavaScript after the page loads.

### Can I still use direct links in some cases?

Yes, you can selectively choose which post types to secure.

### Will this slow down my site?

The plugin is optimized for performance and should have minimal impact on your site's speed.

## Changelog

### 1.0.0
- Initial release

## Requirements

- WordPress 5.0 or higher
- PHP 7.0 or higher

## Credits

Developed by [Your Name/Company] 