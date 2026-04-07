/**
 * SecureGuard WebSocket Manager
 * Handles real-time communication with the backend
 * Version: 1.0.0
 */

(function() {
    'use strict';

    // WebSocket Configuration
    const WS_CONFIG = {
        reconnectInterval: 5000,
        maxReconnectAttempts: 10,
        heartbeatInterval: 30000
    };

    // WebSocket Manager Class
    class WebSocketManager {
        constructor() {
            this.ws = null;
            this.isConnected = false;
            this.reconnectAttempts = 0;
            this.heartbeatTimer = null;
            this.listeners = {};
            this.messageQueue = [];
            this.url = null;
        }

        // Initialize WebSocket connection
        connect(url) {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                console.log('WebSocket already connected');
                return;
            }

            this.url = url || this.getWebSocketUrl();
            
            try {
                this.ws = new WebSocket(this.url);
                this.setupEventHandlers();
            } catch (error) {
                console.error('WebSocket connection error:', error);
                this.scheduleReconnect();
            }
        }

        // Get WebSocket URL based on current host
        getWebSocketUrl() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const host = window.location.host || 'localhost:8765';
            return `${protocol}//${host}/ws`;
        }

        // Setup WebSocket event handlers
        setupEventHandlers() {
            this.ws.onopen = (e) => this.handleOpen(e);
            this.ws.onclose = (e) => this.handleClose(e);
            this.ws.onerror = (e) => this.handleError(e);
            this.ws.onmessage = (e) => this.handleMessage(e);
        }

        // Handle WebSocket open
        handleOpen(event) {
            console.log('WebSocket connected');
            this.isConnected = true;
            this.reconnectAttempts = 0;
            
            // Start heartbeat
            this.startHeartbeat();
            
            // Send queued messages
            this.flushMessageQueue();
            
            // Emit connection event
            this.emit('connected', event);
            
            // Update UI connection status
            this.updateConnectionStatus(true);
        }

        // Handle WebSocket close
        handleClose(event) {
            console.log('WebSocket disconnected:', event.code, event.reason);
            this.isConnected = false;
            
            // Stop heartbeat
            this.stopHeartbeat();
            
            // Emit disconnection event
            this.emit('disconnected', { code: event.code, reason: event.reason });
            
            // Update UI connection status
            this.updateConnectionStatus(false);
            
            // Schedule reconnection
            this.scheduleReconnect();
        }

        // Handle WebSocket error
        handleError(error) {
            console.error('WebSocket error:', error);
            this.emit('error', error);
        }

        // Handle incoming messages
        handleMessage(event) {
            try {
                const data = JSON.parse(event.data);
                console.log('WebSocket message:', data.type);
                
                // Handle different message types
                switch (data.type) {
                    case 'threat_detected':
                        this.handleThreatDetected(data.payload);
                        break;
                    case 'scan_progress':
                        this.handleScanProgress(data.payload);
                        break;
                    case 'system_alert':
                        this.handleSystemAlert(data.payload);
                        break;
                    case 'heartbeat':
                        // Heartbeat response, connection is alive
                        break;
                    default:
                        this.emit('message', data);
                }
                
                // Emit generic message event
                this.emit(data.type, data.payload);
                
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        }

        // Handle threat detected event
        handleThreatDetected(payload) {
            this.emit('threat', payload);
            
            // Show notification
            if (window.SecureGuardUI) {
                window.SecureGuardUI.showNotification(
                    'error',
                    'Threat Detected!',
                    `${payload.threatName} - ${payload.action}`
                );
            }
            
            // Play alert sound
            this.playAlertSound();
        }

        // Handle scan progress event
        handleScanProgress(payload) {
            this.emit('scanProgress', payload);
            
            // Update scan UI if on scan page
            const scanProgress = document.getElementById('scan-progress');
            if (scanProgress) {
                scanProgress.style.width = `${payload.progress}%`;
            }
        }

        // Handle system alert event
        handleSystemAlert(payload) {
            this.emit('alert', payload);
            
            // Show notification based on severity
            if (window.SecureGuardUI) {
                const type = payload.severity === 'critical' ? 'error' : 
                            payload.severity === 'warning' ? 'warning' : 'info';
                window.SecureGuardUI.showNotification(type, payload.title, payload.message);
            }
        }

        // Play alert sound
        playAlertSound() {
            // Create audio context for notification sound
            try {
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                const gainNode = audioContext.createGain();
                
                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                oscillator.frequency.value = 800;
                oscillator.type = 'sine';
                gainNode.gain.value = 0.1;
                
                oscillator.start();
                oscillator.stop(audioContext.currentTime + 0.2);
            } catch (e) {
                // Audio not supported, ignore
            }
        }

        // Send message through WebSocket
        send(type, payload) {
            const message = JSON.stringify({ type, payload, timestamp: Date.now() });
            
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(message);
            } else {
                // Queue message for later
                this.messageQueue.push(message);
            }
        }

        // Flush queued messages
        flushMessageQueue() {
            while (this.messageQueue.length > 0) {
                const message = this.messageQueue.shift();
                this.ws.send(message);
            }
        }

        // Schedule reconnection
        scheduleReconnect() {
            if (this.reconnectAttempts >= WS_CONFIG.maxReconnectAttempts) {
                console.log('Max reconnection attempts reached');
                this.emit('reconnectFailed', { attempts: this.reconnectAttempts });
                return;
            }

            this.reconnectAttempts++;
            const delay = WS_CONFIG.reconnectInterval * Math.min(this.reconnectAttempts, 5);
            
            console.log(`Scheduling reconnection attempt ${this.reconnectAttempts} in ${delay}ms`);
            
            setTimeout(() => {
                if (!this.isConnected) {
                    this.connect(this.url);
                }
            }, delay);
        }

        // Start heartbeat
        startHeartbeat() {
            this.heartbeatTimer = setInterval(() => {
                this.send('heartbeat', { timestamp: Date.now() });
            }, WS_CONFIG.heartbeatInterval);
        }

        // Stop heartbeat
        stopHeartbeat() {
            if (this.heartbeatTimer) {
                clearInterval(this.heartbeatTimer);
                this.heartbeatTimer = null;
            }
        }

        // Update connection status in UI
        updateConnectionStatus(connected) {
            const statusIndicator = document.querySelector('.connection-status');
            if (statusIndicator) {
                if (connected) {
                    statusIndicator.classList.add('connected');
                    statusIndicator.classList.remove('disconnected');
                    statusIndicator.textContent = 'Connected';
                } else {
                    statusIndicator.classList.add('disconnected');
                    statusIndicator.classList.remove('connected');
                    statusIndicator.textContent = 'Reconnecting...';
                }
            }
            
            // Update any live indicators
            const liveDots = document.querySelectorAll('.live-dot');
            liveDots.forEach(dot => {
                dot.style.background = connected ? 'var(--secondary)' : 'var(--warning)';
            });
        }

        // Register event listener
        on(event, callback) {
            if (!this.listeners[event]) {
                this.listeners[event] = [];
            }
            this.listeners[event].push(callback);
        }

        // Remove event listener
        off(event, callback) {
            if (this.listeners[event]) {
                this.listeners[event] = this.listeners[event].filter(cb => cb !== callback);
            }
        }

        // Emit event to listeners
        emit(event, data) {
            if (this.listeners[event]) {
                this.listeners[event].forEach(callback => {
                    try {
                        callback(data);
                    } catch (error) {
                        console.error(`Error in ${event} listener:`, error);
                    }
                });
            }
        }

        // Disconnect WebSocket
        disconnect() {
            this.stopHeartbeat();
            if (this.ws) {
                this.ws.close(1000, 'Client disconnect');
                this.ws = null;
            }
            this.isConnected = false;
        }

        // Get connection status
        getConnectionStatus() {
            return this.isConnected;
        }
    }

    // Create global instance
    window.SecureGuardWS = new WebSocketManager();

    // Auto-connect when API is available
    document.addEventListener('DOMContentLoaded', function() {
        // Try to connect after a short delay
        setTimeout(() => {
            if (window.SecureGuardAPI && window.SecureGuardAPI.isConnected) {
                // Try WebSocket connection
                // Note: This requires WebSocket endpoint to be available
                // window.SecureGuardWS.connect();
            }
        }, 2000);
    });

})();

