/**
 * Admin JavaScript for Secure File Session plugin
 * Modern UI Implementation
 */
(function($) {
    'use strict';
    
    // Initialize when document is ready
    $(document).ready(function() {
        // Tab Functionality with smooth transitions
        $('.sfs-admin-tabs .nav-tab-wrapper a').on('click', function(e) {
            e.preventDefault();
            
            // Get the tab ID from href
            var targetTab = $(this).attr('href');
            
            // Add active class to clicked tab, remove from others
            $(this).addClass('nav-tab-active').siblings().removeClass('nav-tab-active');
            
            // Fade out current tabs, then fade in the selected tab
            $('.tab-pane.active').fadeOut(200, function() {
                $(this).removeClass('active');
                $(targetTab).addClass('active').fadeIn(200);
            });
            
            // Update URL hash for direct linking
            window.location.hash = targetTab;
        });
        
        // Check for hash in URL to activate correct tab on page load
        if (window.location.hash) {
            var tab = window.location.hash;
            $('.sfs-admin-tabs .nav-tab-wrapper a[href="' + tab + '"]').trigger('click');
        } else {
            // Default: Make sure first tab is visible
            $('.sfs-admin-tabs .tab-pane:first').addClass('active').show();
            $('.sfs-admin-tabs .nav-tab-wrapper a:first').addClass('nav-tab-active');
        }
        
        // Update URL on tab change
        function updateQueryParam(key, value) {
            var url = window.location.href;
            var re = new RegExp("([?&])" + key + "=.*?(&|$)", "i");
            var separator = url.indexOf('?') !== -1 ? "&" : "?";
            
            if (url.match(re)) {
                window.history.replaceState(null, null, url.replace(re, '$1' + key + "=" + value + '$2'));
            } else {
                window.history.replaceState(null, null, url + separator + key + "=" + value);
            }
        }
        
        // Intercept tab links with query parameters
        $('.sfs-admin-tabs .nav-tab-wrapper a').on('click', function() {
            var tab = $(this).attr('href').replace('#', '');
            updateQueryParam('tab', tab);
        });
        
        // Handle the tab parameter in URL
        var urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('tab')) {
            var tabName = urlParams.get('tab');
            $('.sfs-admin-tabs .nav-tab-wrapper a[href="#' + tabName + '"]').trigger('click');
        }
        
        // Token Expiration Input Handling with live feedback
        $('#token_expiration').on('input', function() {
            var seconds = $(this).val();
            var minutes = (seconds / 60).toFixed(1);
            var hours = (seconds / 3600).toFixed(2);
            
            $('#expiration_minutes').text(minutes);
            $('#expiration_hours').text(hours);
            
            // Provide visual feedback based on value
            var $feedback = $('#expiration_feedback');
            if (!$feedback.length) {
                $feedback = $('<span id="expiration_feedback"></span>').insertAfter($(this));
            }
            
            if (seconds < 60) {
                $feedback.text('Very short').css('color', '#f44336');
            } else if (seconds < 300) {
                $feedback.text('Short').css('color', '#ff9800');
            } else if (seconds < 3600) {
                $feedback.text('Reasonable').css('color', '#4caf50');
            } else if (seconds < 86400) {
                $feedback.text('Long').css('color', '#2196f3');
            } else {
                $feedback.text('Very long').css('color', '#9c27b0');
            }
        });
        
        // Trigger on load to set initial feedback
        $('#token_expiration').trigger('input');
        
        // Debug Mode Toggle Confirmation with enhanced UI
        $('.debug-mode-toggle').on('change', function() {
            if ($(this).is(':checked')) {
                if (!confirm('⚠️ Warning: Debug mode can expose sensitive information. Do not enable this on production sites. Continue?')) {
                    $(this).prop('checked', false);
                } else {
                    // Show warning banner
                    var $warning = $('<div class="security-notice debug-warning"><strong>Debug Mode Active</strong>: Security information may be exposed. Disable when not needed.</div>');
                    $(this).closest('tr').after($('<tr><td colspan="2"></td></tr>').find('td').append($warning).end());
                }
            } else {
                // Remove warning banner
                $('.debug-warning').closest('tr').remove();
            }
        });
        
        // Show debug warning on page load if enabled
        if ($('.debug-mode-toggle').is(':checked')) {
            var $warning = $('<div class="security-notice debug-warning"><strong>Debug Mode Active</strong>: Security information may be exposed. Disable when not needed.</div>');
            $('.debug-mode-toggle').closest('tr').after($('<tr><td colspan="2"></td></tr>').find('td').append($warning).end());
        }
        
        // Collapsible diagnostic sections
        $('.sfs-diagnostic-item-header').on('click', function() {
            var $details = $(this).next('.sfs-diagnostic-item-details');
            $details.slideToggle(200);
            $(this).toggleClass('expanded');
        });
        
        // Hide details sections by default
        $('.sfs-diagnostic-item-details').hide();
        
        // Smooth scroll to anchor links
        $('a[href^="#"]').not('.nav-tab').on('click', function(e) {
            if ($(this.hash).length) {
                e.preventDefault();
                $('html, body').animate({
                    scrollTop: $(this.hash).offset().top - 50
                }, 300);
            }
        });
        
        // Enhanced form submission with visual feedback
        $('form.sfs-settings-form').on('submit', function() {
            var $form = $(this);
            var $submit = $form.find('input[type="submit"]');
            
            // Add spinner and disable button
            $submit.prop('disabled', true)
                .addClass('saving')
                .val('Saving...');
                
            // Re-enable after delay (actual save handled by WordPress)
            setTimeout(function() {
                $submit.prop('disabled', false)
                    .removeClass('saving')
                    .val('Save Changes');
                    
                // Show success message that fades out
                var $message = $('<div class="notice notice-success inline"><p>Settings saved successfully!</p></div>');
                $form.before($message);
                
                setTimeout(function() {
                    $message.fadeOut(500, function() {
                        $(this).remove();
                    });
                }, 3000);
            }, 800);
            
            // Let the form submit normally
            return true;
        });
    });
})(jQuery); 