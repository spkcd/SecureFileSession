=== SecureFileSession ===
Contributors: wpdeveloper
Tags: security, file protection, uploads, forms
Requires at least: 5.0
Tested up to: 6.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Protect uploaded files with session-based tokens, ensuring secure access to sensitive documents.

== Description ==

SecureFileSession is a WordPress plugin that adds an extra layer of security to files uploaded through forms. Instead of allowing direct access to uploaded files, the plugin intercepts and rewrites URLs, replacing them with secure, token-protected links.

= Key Features =

* **Secure File URLs**: Automatically rewrites file URLs to prevent direct access.
* **Session-Based Tokens**: Generates unique tokens tied to user sessions, valid for 10 minutes.
* **Form Builder Compatibility**: Works with Elementor, JetEngine, and JetFormBuilder without modifying how they store files.
* **Smart Protection**: Only protects uploaded files while leaving theme assets (logos, illustrations) accessible.
* **Zero Configuration**: Works out of the box with no settings required.

= How It Works =

1. When a file is uploaded via a form, the plugin intercepts the public URL.
2. The URL is replaced with a secure endpoint (e.g., /secure-file/?file=...&token=...).
3. A unique session-based token is generated, valid for 10 minutes.
4. When someone tries to access the file, the plugin verifies the token.
5. Access is granted only if the token is valid and from the same session.
6. If the token is missing, expired, or from a different session, access is denied.

= Use Cases =

* **Document Submissions**: Protect sensitive documents uploaded through forms.
* **Member-Only Downloads**: Ensure files are only accessible to authorized users.
* **Form Attachments**: Secure files attached to contact or application forms.

== Installation ==

1. Upload the `secure-file-session` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. That's it! The plugin works automatically with no configuration needed.

== Frequently Asked Questions ==

= Will this plugin affect my media library or theme images? =

No, the plugin is designed to only protect files uploaded through forms. Your regular media files used in the theme (like logos, featured images, etc.) will continue to work normally.

= Does this work with Elementor forms? =

Yes, the plugin supports Elementor forms out of the box, as well as JetEngine and JetFormBuilder.

= How long are the secure links valid? =

By default, each secure link is valid for 10 minutes from the time it's generated. After that, the link expires and can no longer be used to access the file.

= Can I change the expiration time? =

Currently, the 10-minute expiration is hardcoded. A future version may add settings to customize this.

== Changelog ==

= 1.0.0 =
* Initial release

== Upgrade Notice ==

= 1.0.0 =
Initial release, no upgrade needed. 