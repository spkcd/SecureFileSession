/**
 * Secure File Session - Bulk Manager JS
 * Modern UI Implementation
 */
jQuery(document).ready(function($) {
    // Initialize datepickers with enhanced options
    $('.sfs-datepicker').datepicker({
        dateFormat: 'yy-mm-dd',
        changeMonth: true,
        changeYear: true,
        showAnim: 'fadeIn',
        yearRange: '-10:+1',
        beforeShow: function(input, inst) {
            // Position the datepicker relative to the input
            inst.dpDiv.css({
                marginTop: '10px'
            });
        }
    });

    // Select all checkbox with visual feedback
    $('#sfs-select-all').on('change', function() {
        const isChecked = $(this).prop('checked');
        $('.sfs-file-checkbox').prop('checked', isChecked);
        
        // Apply styling to selected rows
        if (isChecked) {
            $('.sfs-file-checkbox').closest('tr').addClass('selected-row');
        } else {
            $('.sfs-file-checkbox').closest('tr').removeClass('selected-row');
        }
        
        updateSelectedCount();
    });
    
    // Individual checkbox selection with visual feedback
    $('.sfs-file-checkbox').on('change', function() {
        const isChecked = $(this).prop('checked');
        
        // Apply styling to selected row
        if (isChecked) {
            $(this).closest('tr').addClass('selected-row');
        } else {
            $(this).closest('tr').removeClass('selected-row');
            // Uncheck "select all" if any checkbox is unchecked
            $('#sfs-select-all').prop('checked', false);
        }
        
        updateSelectedCount();
    });

    // Track selected count
    function updateSelectedCount() {
        const selectedCount = $('.sfs-file-checkbox:checked').length;
        const totalCount = $('.sfs-file-checkbox').length;
        
        // Show selected count
        $('.sfs-selected-count').remove();
        if (selectedCount > 0) {
            const $counter = $('<span class="sfs-selected-count">' + selectedCount + ' of ' + totalCount + ' files selected</span>');
            $('.sfs-bulk-actions-controls').prepend($counter);
        }
        
        // Enable/disable bulk action buttons
        $('.sfs-bulk-action').prop('disabled', selectedCount === 0);
    }
    
    // Initialize selected count
    updateSelectedCount();

    // Individual file actions with animations
    $('.sfs-file-action').on('click', function() {
        const fileId = $(this).data('file-id');
        const action = $(this).data('action');
        const $row = $(this).closest('tr');
        
        if (!fileId || !action) {
            return;
        }

        // Confirm action
        if (!confirm(sfs_bulk_manager.messages['confirm_' + action])) {
            return;
        }

        // Add loading state to the row
        $row.addClass('is-processing');
        
        // Disable all buttons in the row
        $row.find('.button').prop('disabled', true);

        updateFileSecurity([fileId], action);
    });

    // Bulk actions with enhanced UX
    $('.sfs-bulk-action').on('click', function() {
        const action = $(this).data('action');
        const selectedFiles = getSelectedFiles();
        
        if (!action || selectedFiles.length === 0) {
            showMessage('error', 'Please select at least one file.', true);
            return;
        }

        // Confirm action with count
        if (!confirm(sfs_bulk_manager.messages['confirm_' + action] + ' for ' + selectedFiles.length + ' selected files?')) {
            return;
        }

        // Add loading state to selected rows
        $('.sfs-file-checkbox:checked').closest('tr').addClass('is-processing');
        
        // Disable all action buttons during processing
        $('.sfs-bulk-action, .sfs-file-action').prop('disabled', true);

        updateFileSecurity(selectedFiles, action);
    });

    /**
     * Get selected file IDs
     */
    function getSelectedFiles() {
        const selectedFiles = [];
        
        $('.sfs-file-checkbox:checked').each(function() {
            selectedFiles.push($(this).val());
        });
        
        return selectedFiles;
    }

    /**
     * Update file security settings via AJAX
     */
    function updateFileSecurity(fileIds, action) {
        // Show loading state
        showLoading(true);
        
        // Visual feedback for processing
        $('#sfs-bulk-manager').addClass('processing-changes');
        
        // Make AJAX request
        $.ajax({
            url: sfs_bulk_manager.ajax_url,
            type: 'POST',
            data: {
                action: 'sfs_update_file_security',
                nonce: sfs_bulk_manager.nonce,
                files: fileIds,
                action_type: action
            },
            success: function(response) {
                showLoading(false);
                
                if (response.success) {
                    // Success feedback
                    showMessage('success', response.data.message, true);
                    
                    // Get count for better messaging
                    const fileCount = fileIds.length;
                    const fileWord = fileCount === 1 ? 'file' : 'files';
                    
                    // Show additional button to undo or refresh
                    appendActionButton(response.data.message, fileCount + ' ' + fileWord + ' updated.');
                    
                    // Refresh the page after 1.5 seconds
                    setTimeout(function() {
                        location.reload();
                    }, 1500);
                } else {
                    // Error handling
                    showMessage('error', response.data.message || sfs_bulk_manager.messages.error, true);
                    
                    // Remove processing states
                    $('.is-processing').removeClass('is-processing');
                    $('.sfs-bulk-action, .sfs-file-action').prop('disabled', false);
                    $('#sfs-bulk-manager').removeClass('processing-changes');
                }
            },
            error: function() {
                showLoading(false);
                showMessage('error', sfs_bulk_manager.messages.error, true);
                
                // Remove processing states
                $('.is-processing').removeClass('is-processing');
                $('.sfs-bulk-action, .sfs-file-action').prop('disabled', false);
                $('#sfs-bulk-manager').removeClass('processing-changes');
            }
        });
    }

    /**
     * Append action button after operations
     */
    function appendActionButton(title, message) {
        const $actionArea = $('#sfs-bulk-action-result');
        
        if (!$actionArea.find('.action-buttons').length) {
            const $buttons = $('<div class="action-buttons"></div>');
            const $refreshBtn = $('<button type="button" class="button action-refresh">Refresh Now</button>');
            
            $refreshBtn.on('click', function() {
                location.reload();
            });
            
            $buttons.append($refreshBtn);
            $actionArea.append($buttons);
        }
    }

    /**
     * Show/hide loading indicator
     */
    function showLoading(show) {
        // Add loading class to container
        if (show) {
            $('#sfs-bulk-manager').addClass('is-loading');
        } else {
            $('#sfs-bulk-manager').removeClass('is-loading');
        }
    }

    /**
     * Show message with enhanced styling
     */
    function showMessage(type, message, autoHide) {
        const $result = $('#sfs-bulk-action-result');
        
        // Set message type and content
        $result.removeClass('notice-success notice-error')
               .addClass('notice-' + type)
               .html('<p>' + message + '</p>')
               .hide()
               .fadeIn(300);
        
        // Auto-hide message after 5 seconds if requested
        if (autoHide) {
            setTimeout(function() {
                $result.fadeOut(500);
            }, 5000);
        }
    }
    
    // Filter toggle functionality
    const $filterToggle = $('<button type="button" class="button filter-toggle">Show Advanced Filters</button>');
    $('.sfs-filters').before($filterToggle);
    
    // Hide filters by default for cleaner UI
    const $advancedFilters = $('.sfs-filters');
    $advancedFilters.hide();
    
    $filterToggle.on('click', function() {
        $advancedFilters.slideToggle(300);
        $(this).text(function(i, text) {
            return text === 'Show Advanced Filters' ? 'Hide Advanced Filters' : 'Show Advanced Filters';
        });
    });
    
    // Add hover effects for thumbnails
    $('.sfs-file-thumbnail').on('mouseenter', function() {
        $(this).css('transform', 'scale(1.1)');
    }).on('mouseleave', function() {
        $(this).css('transform', 'scale(1)');
    });
    
    // Add style to make the file rows clickable for better UX
    $('.sfs-files-table tbody tr').css('cursor', 'pointer');
    
    // Row click selects the checkbox
    $('.sfs-files-table tbody tr').on('click', function(e) {
        // Don't trigger if clicking on a button, link or checkbox directly
        if ($(e.target).is('a, button, input') || $(e.target).closest('a, button, .sfs-file-actions').length) {
            return;
        }
        
        const $checkbox = $(this).find('.sfs-file-checkbox');
        $checkbox.prop('checked', !$checkbox.prop('checked')).trigger('change');
    });
}); 