/**
 * SecureGuard Charts Module
 * Provides chart rendering and visualization utilities
 * Uses Canvas API for lightweight charts without external dependencies
 * Version: 1.0.0
 */

(function() {
    'use strict';

    // Chart colors
    const CHART_COLORS = {
        primary: '#3b82f6',
        secondary: '#10b981',
        danger: '#ef4444',
        warning: '#f59e0b',
        info: '#06b6d4',
        purple: '#8b5cf6',
        background: 'rgba(59, 130, 246, 0.1)',
        grid: 'rgba(255, 255, 255, 0.05)',
        text: '#94a3b8'
    };

    // Chart types
    const CHART_TYPES = {
        LINE: 'line',
        BAR: 'bar',
        DOUGHNUT: 'doughnut',
        GAUGE: 'gauge',
        RADAR: 'radar'
    };

    // Base Chart Class
    class BaseChart {
        constructor(canvas, options = {}) {
            this.canvas = canvas;
            this.ctx = canvas.getContext('2d');
            this.options = {
                width: options.width || canvas.parentElement?.clientWidth || 300,
                height: options.height || 200,
                padding: options.padding || 40,
                ...options
            };
            this.data = [];
            this.labels = [];
            
            // Set canvas size
            canvas.width = this.options.width;
            canvas.height = this.options.height;
        }

        clear() {
            this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        }

        draw() {
            // Override in subclasses
        }

        update(data, labels) {
            this.data = data;
            this.labels = labels;
            this.draw();
        }
    }

    // Line Chart Class
    class LineChart extends BaseChart {
        constructor(canvas, options = {}) {
            super(canvas, {
                smooth: true,
                showPoints: true,
                showArea: true,
                showGrid: true,
                ...options
            });
        }

        draw() {
            this.clear();
            
            if (!this.data || this.data.length === 0) return;

            const { width, height, padding, smooth, showPoints, showArea, showGrid } = this.options;
            const chartWidth = width - padding * 2;
            const chartHeight = height - padding * 2;

            // Find max value
            const maxValue = Math.max(...this.data, 1) * 1.1;
            const minValue = 0;

            // Draw grid
            if (showGrid) {
                this.ctx.strokeStyle = CHART_COLORS.grid;
                this.ctx.lineWidth = 1;
                
                for (let i = 0; i <= 4; i++) {
                    const y = padding + (chartHeight / 4) * i;
                    this.ctx.beginPath();
                    this.ctx.moveTo(padding, y);
                    this.ctx.lineTo(width - padding, y);
                    this.ctx.stroke();
                }
            }

            // Calculate points
            const points = this.data.map((value, index) => ({
                x: padding + (chartWidth / (this.data.length - 1)) * index,
                y: padding + chartHeight - ((value - minValue) / (maxValue - minValue)) * chartHeight
            }));

            // Draw area
            if (showArea) {
                this.ctx.beginPath();
                this.ctx.moveTo(points[0].x, padding + chartHeight);
                points.forEach(point => this.ctx.lineTo(point.x, point.y));
                this.ctx.lineTo(points[points.length - 1].x, padding + chartHeight);
                this.ctx.closePath();
                
                const gradient = this.ctx.createLinearGradient(0, padding, 0, height - padding);
                gradient.addColorStop(0, 'rgba(59, 130, 246, 0.3)');
                gradient.addColorStop(1, 'rgba(59, 130, 246, 0)');
                this.ctx.fillStyle = gradient;
                this.ctx.fill();
            }

            // Draw line
            this.ctx.beginPath();
            this.ctx.strokeStyle = CHART_COLORS.primary;
            this.ctx.lineWidth = 2;
            this.ctx.lineCap = 'round';
            this.ctx.lineJoin = 'round';

            if (smooth) {
                points.forEach((point, index) => {
                    if (index === 0) {
                        this.ctx.moveTo(point.x, point.y);
                    } else {
                        const prev = points[index - 1];
                        const cpX = (prev.x + point.x) / 2;
                        this.ctx.bezierCurveTo(cpX, prev.y, cpX, point.y, point.x, point.y);
                    }
                });
            } else {
                points.forEach((point, index) => {
                    if (index === 0) {
                        this.ctx.moveTo(point.x, point.y);
                    } else {
                        this.ctx.lineTo(point.x, point.y);
                    }
                });
            }
            this.ctx.stroke();

            // Draw points
            if (showPoints) {
                points.forEach(point => {
                    this.ctx.beginPath();
                    this.ctx.arc(point.x, point.y, 4, 0, Math.PI * 2);
                    this.ctx.fillStyle = CHART_COLORS.primary;
                    this.ctx.fill();
                    this.ctx.strokeStyle = '#0f172a';
                    this.ctx.lineWidth = 2;
                    this.ctx.stroke();
                });
            }

            // Draw labels
            this.ctx.fillStyle = CHART_COLORS.text;
            this.ctx.font = '11px Plus Jakarta Sans, sans-serif';
            this.ctx.textAlign = 'center';

            const labelInterval = Math.ceil(this.labels.length / 6);
            this.labels.forEach((label, index) => {
                if (index % labelInterval === 0 || index === this.labels.length - 1) {
                    const x = padding + (chartWidth / (this.data.length - 1)) * index;
                    this.ctx.fillText(label, x, height - 10);
                }
            });
        }
    }

    // Bar Chart Class
    class BarChart extends BaseChart {
        constructor(canvas, options = {}) {
            super(canvas, {
                showGrid: true,
                barWidth: 0.6,
                ...options
            });
        }

        draw() {
            this.clear();
            
            if (!this.data || this.data.length === 0) return;

            const { width, height, padding, showGrid, barWidth } = this.options;
            const chartWidth = width - padding * 2;
            const chartHeight = height - padding * 2;

            // Find max value
            const maxValue = Math.max(...this.data, 1) * 1.1;

            // Draw grid
            if (showGrid) {
                this.ctx.strokeStyle = CHART_COLORS.grid;
                this.ctx.lineWidth = 1;
                
                for (let i = 0; i <= 4; i++) {
                    const y = padding + (chartHeight / 4) * i;
                    this.ctx.beginPath();
                    this.ctx.moveTo(padding, y);
                    this.ctx.lineTo(width - padding, y);
                    this.ctx.stroke();
                }
            }

            // Draw bars
            const barTotalWidth = chartWidth / this.data.length;
            const barActualWidth = barTotalWidth * barWidth;
            const barGap = barTotalWidth * (1 - barWidth) / 2;

            this.data.forEach((value, index) => {
                const barHeight = (value / maxValue) * chartHeight;
                const x = padding + barGap + barTotalWidth * index;
                const y = padding + chartHeight - barHeight;

                // Create gradient
                const gradient = this.ctx.createLinearGradient(x, y + barHeight, x, y);
                gradient.addColorStop(0, CHART_COLORS.primary);
                gradient.addColorStop(1, CHART_COLORS.secondary);

                this.ctx.fillStyle = gradient;
                this.ctx.beginPath();
                this.ctx.roundRect(x, y, barActualWidth, barHeight, 4);
                this.ctx.fill();
            });

            // Draw labels
            this.ctx.fillStyle = CHART_COLORS.text;
            this.ctx.font = '10px Plus Jakarta Sans, sans-serif';
            this.ctx.textAlign = 'center';

            this.labels.forEach((label, index) => {
                const x = padding + barGap + barTotalWidth * index + barActualWidth / 2;
                this.ctx.fillText(label, x, height - 10);
            });
        }
    }

    // Doughnut Chart Class
    class DoughnutChart extends BaseChart {
        constructor(canvas, options = {}) {
            super(canvas, {
                cutout: 0.7,
                showLegend: true,
                colors: [CHART_COLORS.primary, CHART_COLORS.secondary, CHART_COLORS.warning, CHART_COLORS.danger, CHART_COLORS.purple],
                ...options
            });
        }

        draw() {
            this.clear();
            
            if (!this.data || this.data.length === 0) return;

            const { width, height, cutout, colors } = this.options;
            const centerX = width / 2;
            const centerY = height / 2;
            const radius = Math.min(width, height) / 2 - 20;
            const innerRadius = radius * cutout;

            // Calculate total
            const total = this.data.reduce((sum, val) => sum + val, 0);

            // Draw segments
            let startAngle = -Math.PI / 2;
            
            this.data.forEach((value, index) => {
                const sliceAngle = (value / total) * Math.PI * 2;
                const endAngle = startAngle + sliceAngle;

                this.ctx.beginPath();
                this.ctx.arc(centerX, centerY, radius, startAngle, endAngle);
                this.ctx.arc(centerX, centerY, innerRadius, endAngle, startAngle, true);
                this.ctx.closePath();
                this.ctx.fillStyle = colors[index % colors.length];
                this.ctx.fill();

                startAngle = endAngle;
            });

            // Draw center text
            if (this.options.centerText) {
                this.ctx.fillStyle = '#ffffff';
                this.ctx.font = 'bold 24px Plus Jakarta Sans, sans-serif';
                this.ctx.textAlign = 'center';
                this.ctx.textBaseline = 'middle';
                this.ctx.fillText(this.options.centerText, centerX, centerY - 10);
                
                this.ctx.font = '12px Plus Jakarta Sans, sans-serif';
                this.ctx.fillStyle = CHART_COLORS.text;
                this.ctx.fillText(this.options.centerLabel || '', centerX, centerY + 15);
            }
        }
    }

    // Gauge Chart Class
    class GaugeChart extends BaseChart {
        constructor(canvas, options = {}) {
            super(canvas, {
                min: 0,
                max: 100,
                startAngle: -Math.PI * 0.75,
                endAngle: Math.PI * 0.75,
                ...options
            });
        }

        draw() {
            this.clear();
            
            const { width, height, min, max, startAngle, endAngle } = this.options;
            const centerX = width / 2;
            const centerY = height - 20;
            const radius = Math.min(width, height) - 60;

            // Calculate angles
            const value = Math.min(Math.max(this.data[0] || 0, min), max);
            const valueAngle = startAngle + ((value - min) / (max - min)) * (endAngle - startAngle);

            // Draw background arc
            this.ctx.beginPath();
            this.ctx.arc(centerX, centerY, radius, startAngle, endAngle);
            this.ctx.strokeStyle = CHART_COLORS.grid;
            this.ctx.lineWidth = 20;
            this.ctx.lineCap = 'round';
            this.ctx.stroke();

            // Draw value arc
            this.ctx.beginPath();
            this.ctx.arc(centerX, centerY, radius, startAngle, valueAngle);
            
            // Color based on value
            let color = CHART_COLORS.secondary;
            if (value < 30) color = CHART_COLORS.danger;
            else if (value < 60) color = CHART_COLORS.warning;
            
            this.ctx.strokeStyle = color;
            this.ctx.lineWidth = 20;
            this.ctx.stroke();

            // Draw value text
            this.ctx.fillStyle = '#ffffff';
            this.ctx.font = 'bold 32px Plus Jakarta Sans, sans-serif';
            this.ctx.textAlign = 'center';
            this.ctx.textBaseline = 'middle';
            this.ctx.fillText(Math.round(value), centerX, centerY - 30);

            // Draw label
            this.ctx.font = '14px Plus Jakarta Sans, sans-serif';
            this.ctx.fillStyle = CHART_COLORS.text;
            this.ctx.fillText(this.options.label || '', centerX, centerY + 10);
        }
    }

    // Chart Manager
    class ChartManager {
        constructor() {
            this.charts = {};
            this.chartDefaults = {
                LineChart,
                BarChart,
                DoughnutChart,
                GaugeChart
            };
        }

        // Create a new chart
        create(type, canvasId, options = {}) {
            const canvas = document.getElementById(canvasId);
            if (!canvas) {
                console.error('Canvas not found: ' + canvasId);
                return null;
            }

            const ChartClass = this.chartDefaults[type] || LineChart;
            const chart = new ChartClass(canvas, options);
            
            this.charts[canvasId] = chart;
            return chart;
        }

        // Get existing chart
        get(canvasId) {
            return this.charts[canvasId];
        }

        // Update chart data
        update(canvasId, data, labels) {
            const chart = this.charts[canvasId];
            if (chart) {
                chart.update(data, labels);
            }
        }

        // Remove chart
        remove(canvasId) {
            if (this.charts[canvasId]) {
                delete this.charts[canvasId];
            }
        }
    }

    // Predefined chart templates
    const ChartTemplates = {
        // CPU Usage Chart
        cpuUsage(canvasId) {
            const canvas = document.getElementById(canvasId);
            if (!canvas) return null;
            
            const chart = new LineChart(canvas, {
                width: 300,
                height: 120,
                smooth: true,
                showArea: true,
                showPoints: false
            });
            
            // Generate sample data
            const data = Array.from({ length: 20 }, () => Math.random() * 60 + 20);
            const labels = Array.from({ length: 20 }, (_, i) => i + 's');
            
            chart.update(data, labels);
            return chart;
        },

        // RAM Usage Chart
        ramUsage(canvasId) {
            const canvas = document.getElementById(canvasId);
            if (!canvas) return null;
            
            const chart = new LineChart(canvas, {
                width: 300,
                height: 120,
                smooth: true,
                showArea: true,
                showPoints: false
            });
            
            const data = Array.from({ length: 20 }, () => Math.random() * 40 + 40);
            const labels = Array.from({ length: 20 }, (_, i) => i + 's');
            
            chart.update(data, labels);
            return chart;
        },

        // Disk Usage Chart
        diskUsage(canvasId) {
            const canvas = document.getElementById(canvasId);
            if (!canvas) return null;
            
            const chart = new DoughnutChart(canvas, {
                width: 200,
                height: 200,
                centerText: '65%',
                centerLabel: 'Used'
            });
            
            chart.update([65, 35], ['Used', 'Free']);
            return chart;
        },

        // Security Score Gauge
        securityScore(canvasId, score) {
            const canvas = document.getElementById(canvasId);
            if (!canvas) return null;
            
            const chart = new GaugeChart(canvas, {
                width: 200,
                height: 150,
                label: 'Security Score'
            });
            
            chart.update([score || 85], []);
            return chart;
        },

        // Threat Distribution Chart
        threatDistribution(canvasId) {
            const canvas = document.getElementById(canvasId);
            if (!canvas) return null;
            
            const chart = new DoughnutChart(canvas, {
                width: 200,
                height: 200
            });
            
            chart.update([45, 25, 15, 10, 5], ['Malware', 'Ransomware', 'Phishing', 'Adware', 'Other']);
            return chart;
        }
    };

    // Export to global
    window.SecureGuardCharts = {
        LineChart,
        BarChart,
        DoughnutChart,
        GaugeChart,
        ChartManager,
        ChartTemplates,
        CHART_TYPES,
        CHART_COLORS
    };

})();
