/**
 * SecureGuard UI Manager
 * Handles notifications, modals, toasts, and other UI interactions
 * Version: 1.0.0
 */

(function() {
    'use strict';

    // UI Manager Class
    class UIManager {
        constructor() {
            this.notifications = [];
            this.toastContainer = null;
            this.modalContainer = null;
            this.isInitialized = false;
        }

        // Initialize UI components
        init() {
            if (this.isInitialized) return;
            
            this.createToastContainer();
            this.createModalContainer();
            this.setupEventListeners();
            
            this.isInitialized = true;
            console.log('SecureGuard UI Manager initialized');
        }

        // Create toast notification container
        createToastContainer() {
            if (document.getElementById('toast-container')) return;
            
            this.toastContainer = document.createElement('div');
            this.toastContainer.id = 'toast-container';
            this.toastContainer.className = 'toast-container';
            document.body.appendChild(this.toastContainer);
        }

        // Create modal container
        createModalContainer() {
            if (document.getElementById('modal-container')) return;
            
            this.modalContainer = document.createElement('div');
            this.modalContainer.id = 'modal-container';
            this.modalContainer.className = 'modal-overlay';
            this.modalContainer.innerHTML = '';
            document.body.appendChild(this.modalContainer);
        }

        // Setup global event listeners
        setupEventListeners() {
            // Close modal on background click
            document.addEventListener('click', (e) => {
                if (e.target.classList.contains('modal-overlay') && e.target.id === 'modal-container') {
                    this.closeModal();
                }
            });

            // Close modal on escape key
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    this.closeModal();
                }
            });

            // Close toast on click
            document.addEventListener('click', (e) => {
                const toast = e.target.closest('.toast');
                if (toast && !e.target.closest('.toast-action')) {
                    this.removeToast(toast);
                }
            });
        }

        // Show notification
        showNotification(type, title, message, duration = 5000) {
            // Create toast element
            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            
            const icon = this.getNotificationIcon(type);
            
            toast.innerHTML = `
                <div class="toast-icon">
                    <i class="fas ${icon}"></i>
                </div>
                <div class="toast-content">
                    <div class="toast-title">${title}</div>
                    <div class="toast-message">${message}</div>
                <button class="toast-close">
                    <i class="fas fa-times"></i>
                </button>
            `;

            // Add to container
            this.toastContainer.appendChild(toast);
            
            // Add notification to list
            this.notifications.push({
                id: Date.now(),
                type,
                title,
                message,
                timestamp: new Date()
            });

            // Trigger animation
            setTimeout(() => toast.classList.add('show'), 10);

            // Auto remove after duration
            if (duration > 0) {
                setTimeout(() => this.removeToast(toast), duration);
            }

            // Play sound for important notifications
            if (type === 'error' || type === 'warning') {
                this.playNotificationSound(type);
            }

            return toast;
        }

        // Remove toast
        removeToast(toast) {
            if (!toast) return;
            
            toast.classList.remove('show');
            toast.classList.add('hide');
            
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }

        // Get notification icon
        getNotificationIcon(type) {
            const icons = {
                success: 'fa-check-circle',
                error: 'fa-times-circle',
                warning: 'fa-exclamation-triangle',
                info: 'fa-info-circle'
            };
            return icons[type] || icons.info;
        }

        // Play notification sound
        playNotificationSound(type) {
            try {
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                const gainNode = audioContext.createGain();
                
                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                // Different frequencies for different types
                const freq = type === 'error' ? 440 : type === 'warning' ? 523 : 600;
                
                oscillator.frequency.value = freq;
                oscillator.type = 'sine';
                gainNode.gain.value = 0.1;
                
                oscillator.start();
                oscillator.stop(audioContext.currentTime + 0.15);
            } catch (e) {
                // Audio not supported
            }
        }

        // Show modal
        showModal(options) {
            const {
                title = '',
                content = '',
                buttons = [],
                size = 'medium', // small, medium, large
                closable = true,
                onClose = null
            } = options;

            // Create modal content
            const modalContent = document.createElement('div');
            modalContent.className = `modal modal-${size}`;
            
            let buttonsHtml = '';
            if (buttons.length > 0) {
                buttonsHtml = '<div class="modal-buttons">';
                buttons.forEach(btn => {
                    buttonsHtml += `
                        <button class="modal-btn modal-btn-${btn.type || 'default'}" 
                                data-action="${btn.action || ''}"
                                ${btn.disabled ? 'disabled' : ''}>
                            ${btn.text}
                        </button>
                    `;
                });
                buttonsHtml += '</div>';
            }

            modalContent.innerHTML = `
                ${closable ? '<button class="modal-close-btn"><i class="fas fa-times"></i></button>' : ''}
                ${title ? `<div class="modal-header"><h3>${title}</h3></div>` : ''}
                <div class="modal-body">${content}</div>
                ${buttonsHtml ? buttonsHtml : ''}
            `;

            // Clear and show modal container
            this.modalContainer.innerHTML = '';
            this.modalContainer.appendChild(modalContent);
            this.modalContainer.classList.add('active');

            // Add event listeners
            if (closable) {
                modalContent.querySelector('.modal-close-btn')?.addEventListener('click', () => {
                    this.closeModal(onClose);
                });
            }

            // Button event listeners
            modalContent.querySelectorAll('.modal-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const action = e.target.dataset.action;
                    if (action && options.onAction) {
                        options.onAction(action);
                    }
                });
            });

            return modalContent;
        }

        // Close modal
        closeModal(callback = null) {
            this.modalContainer.classList.remove('active');
            
            setTimeout(() => {
                this.modalContainer.innerHTML = '';
                if (callback) callback();
            }, 300);
        }

        // Show confirm dialog
        confirm(options) {
            return new Promise((resolve) => {
                this.showModal({
                    title: options.title || 'Confirm',
                    content: options.message || 'Are you sure?',
                    size: 'small',
                    buttons: [
                        { text: 'Cancel', type: 'default', action: 'cancel' },
                        { text: options.confirmText || 'Confirm', type: 'primary', action: 'confirm' }
                    ],
                    onAction: (action) => {
                        this.closeModal();
                        resolve(action === 'confirm');
                    }
                });
            });
        }

        // Show alert dialog
        alert(options) {
            return new Promise((resolve) => {
                this.showModal({
                    title: options.title || 'Alert',
                    content: options.message || '',
                    size: 'small',
                    buttons: [
                        { text: 'OK', type: 'primary', action: 'ok' }
                    ],
                    onAction: () => {
                        this.closeModal();
                        resolve(true);
                    }
                });
            });
        }

        // Show loading overlay
        showLoading(message = 'Loading...') {
            const loading = document.createElement('div');
            loading.id = 'global-loading';
            loading.className = 'loading-overlay';
            loading.innerHTML = `
                <div class="loading-spinner"></div>
                <p>${message}</p>
            `;
            document.body.appendChild(loading);
            
            setTimeout(() => loading.classList.add('active'), 10);
            return loading;
        }

        // Hide loading overlay
        hideLoading() {
            const loading = document.getElementById('global-loading');
            if (loading) {
                loading.classList.remove('active');
                setTimeout(() => loading.remove(), 300);
            }
        }

        // Show scan modal
        showScanModal(scanType = 'quick') {
            const modalContent = document.createElement('div');
            modalContent.className = 'modal scan-modal';
            modalContent.innerHTML = `
                <div class="scan-modal-header">
                    <i class="fas fa-shield-virus scan-icon"></i>
                    <h2>${this.getScanTypeName(scanType)}</h2>
                </div>
                <div class="scan-progress-container">
                    <div class="scan-progress-bar">
                        <div class="scan-progress-fill" id="scan-progress-fill"></div>
                    <div class="scan-progress-text">
                        <span id="scan-percent">0%</span>
                        <span id="scan-files">0 files scanned</span>
                    </div>
                <div class="scan-status" id="scan-status">Initializing scan...</div>
                <div class="scan-details">
                    <div class="scan-detail">
                        <span class="label">Threats Found:</span>
                        <span class="value" id="scan-threats">0</span>
                    </div>
                    <div class="scan-detail class="label">">
                        <spanTime Elapsed:</span>
                        <span class="value" id="scan-time">0:00</span>
                    </div>
                <button class="modal-btn modal-btn-danger" id="scan-cancel-btn">Cancel Scan</button>
            `;

            this.modalContainer.innerHTML = '';
            this.modalContainer.appendChild(modalContent);
            this.modalContainer.classList.add('active');

            return {
                updateProgress: (percent, files) => {
                    const fill = document.getElementById('scan-progress-fill');
                    const percentEl = document.getElementById('scan-percent');
                    const filesEl = document.getElementById('scan-files');
                    
                    if (fill) fill.style.width = percent + '%';
                    if (percentEl) percentEl.textContent = Math.round(percent) + '%';
                    if (filesEl) filesEl.textContent = files.toLocaleString() + ' files scanned';
                },
                updateStatus: (status) => {
                    const statusEl = document.getElementById('scan-status');
                    if (statusEl) statusEl.textContent = status;
                },
                updateThreats: (count) => {
                    const threatsEl = document.getElementById('scan-threats');
                    if (threatsEl) threatsEl.textContent = count;
                },
                updateTime: (seconds) => {
                    const timeEl = document.getElementById('scan-time');
                    if (timeEl) {
                        const mins = Math.floor(seconds / 60);
                        const secs = seconds % 60;
                        timeEl.textContent = mins + ':' + secs.toString().padStart(2, '0');
                    }
                },
                onCancel: (callback) => {
                    document.getElementById('scan-cancel-btn')?.addEventListener('click', callback);
                },
                close: () => this.closeModal()
            };
        }

        // Get scan type display name
        getScanTypeName(type) {
            const names = {
                quick: 'Quick Scan',
                full: 'Full System Scan',
                custom: 'Custom Scan',
                memory: 'Memory Scan',
                boot: 'Boot-time Scan'
            };
            return names[type] || 'Scan';
        }

        // Update page title
        setPageTitle(title) {
            document.title = `${title} - SecureGuard`;
            
            const titleElement = document.querySelector('.page-title span');
            if (titleElement) {
                titleElement.textContent = title;
            }
        }

        // Show connection status
        updateConnectionStatus(connected) {
            const statusEl = document.querySelector('.connection-status');
            if (statusEl) {
                statusEl.className = `connection-status ${connected ? 'connected' : 'disconnected'}`;
                statusEl.textContent = connected ? 'Connected' : 'Offline';
            }

            // Also update any live indicators
            const liveDots = document.querySelectorAll('.live-dot');
            liveDots.forEach(dot => {
                dot.style.background = connected ? '#10b981' : '#f59e0b';
            });
        }

        // Animate counter
        animateCounter(element, target, duration = 1500) {
            if (!element) return;
            
            const start = 0;
            const startTime = performance.now();
            
            const updateCounter = (currentTime) => {
                const elapsed = currentTime - startTime;
                const progress = Math.min(elapsed / duration, 1);
                
                // Ease out
                const easeOut = 1 - Math.pow(1 - progress, 3);
                const current = Math.floor(start + (target - start) * easeOut);
                
                element.textContent = current.toLocaleString();
                
                if (progress < 1) {
                    requestAnimationFrame(updateCounter);
                } else {
                    element.textContent = target.toLocaleString();
                }
            };
            
            requestAnimationFrame(updateCounter);
        }

        // Format bytes
        formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // Format time ago
        formatTimeAgo(date) {
            const now = new Date();
            const past = new Date(date);
            const diffMs = now - past;
            const diffMins = Math.floor(diffMs / 60000);
            const diffHours = Math.floor(diffMs / 3600000);
            const diffDays = Math.floor(diffMs / 86400000);

            if (diffMins < 1) return 'Just now';
            if (diffMins < 60) return `${diffMins} min${diffMins > 1 ? 's' : ''} ago`;
            if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
            if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
            
            return past.toLocaleDateString();
        }
    }

    // Create global instance
    window.SecureGuardUI = new UIManager();

    // Auto-initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => window.SecureGuardUI.init());
    } else {
        window.SecureGuardUI.init();
    }

})();
