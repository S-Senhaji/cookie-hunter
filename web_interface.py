#!/usr/bin/env python3
"""
CookieHunter Web Interface
"""

from flask import Flask, render_template, request, jsonify
import json
import os
from cookie_hunter import CookieHunter
from datetime import datetime

app = Flask(__name__)

# Create templates directory and template
os.makedirs('templates', exist_ok=True)

# Create HTML template with simplified JavaScript
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CookieHunter - Cookie Security Analysis</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
            min-height: 100vh;
            color: #ffffff;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #1a1a1a;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #dc143c 0%, #8b0000 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .form-section {
            padding: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #ffffff;
        }
        .form-group input, .form-group textarea, .form-group select {
            width: 100%;
            padding: 10px;
            border: 1px solid #dc143c;
            border-radius: 5px;
            background: #2d2d2d;
            color: #ffffff;
            box-sizing: border-box;
        }
        .btn {
            background: linear-gradient(135deg, #dc143c 0%, #8b0000 100%);
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            box-shadow: 0 4px 15px rgba(220, 20, 60, 0.3);
            transition: all 0.3s ease;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(220, 20, 60, 0.4);
        }
        .results-section {
            padding: 30px;
            display: none;
        }
        .loading {
            text-align: center;
            padding: 20px;
            display: none;
        }
        .summary {
            background: #2d2d2d;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
            border: 1px solid #dc143c;
        }
        .cookie-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: #2d2d2d;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }
        .cookie-table th, .cookie-table td {
            padding: 15px 12px;
            text-align: left;
            border-bottom: 1px solid #444;
            vertical-align: middle;
        }
        .cookie-table th {
            background: linear-gradient(135deg, #dc143c 0%, #8b0000 100%);
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 14px;
            letter-spacing: 1px;
        }
        .cookie-table tr:hover {
            background: #3d3d3d;
            transform: scale(1.01);
            transition: all 0.2s ease;
        }
        .cookie-table tr:nth-child(even) {
            background: #333333;
        }
        .cookie-table tr:nth-child(even):hover {
            background: #3d3d3d;
        }
        .cookie-name {
            font-weight: bold;
            color: #dc143c;
            font-family: 'Courier New', monospace;
        }
        .cookie-value {
            font-family: 'Courier New', monospace;
            color: #cccccc;
            max-width: 150px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            display: inline-block;
        }
        .cookie-value:hover {
            white-space: normal;
            word-break: break-all;
            position: relative;
            z-index: 10;
            background: #3d3d3d;
            padding: 5px;
            border-radius: 3px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.5);
        }
        .status-icon {
            font-size: 16px;
            font-weight: bold;
        }
        .status-secure {
            color: #4CAF50;
        }
        .status-insecure {
            color: #f44336;
        }
        .status-warning {
            color: #ff9800;
        }
        .warning-count-badge {
            display: inline-block;
            background: #dc143c;
            color: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            min-width: 20px;
            text-align: center;
        }
        .warning-count-badge.zero {
            background: #4CAF50;
        }
        .security-status-clickable {
            cursor: pointer;
            padding: 5px 10px;
            border-radius: 5px;
            transition: all 0.3s ease;
        }
        .security-status-clickable:hover {
            transform: scale(1.05);
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        }
        .cookie-details-modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.8);
        }
        .modal-content {
            background: #2d2d2d;
            margin: 5% auto;
            padding: 20px;
            border-radius: 10px;
            width: 80%;
            max-width: 600px;
            border: 2px solid #dc143c;
            position: relative;
        }
        .modal-header {
            color: #dc143c;
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 15px;
            text-align: center;
        }
        .close-modal {
            position: absolute;
            top: 10px;
            right: 15px;
            color: #dc143c;
            font-size: 24px;
            font-weight: bold;
            cursor: pointer;
        }
        .close-modal:hover {
            color: #ff6b6b;
        }
        .cookie-detail-item {
            background: #3d3d3d;
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            border-left: 3px solid #dc143c;
        }
        .table-container {
            margin-top: 30px;
            background: #2d2d2d;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #dc143c;
        }
        .table-header {
            color: #dc143c;
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 15px;
            text-align: center;
        }
        .error {
            color: #ff6b6b;
            background: #2d2d2d;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #ff6b6b;
        }
        .warning-item {
            background: #2d2d2d;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #ff6b6b;
        }
        .warning-critical {
            border-left-color: #ff4444;
            background: #3d2d2d;
        }
        .warning-error {
            border-left-color: #ff6b6b;
            background: #3d2d2d;
        }
        .warning-warning {
            border-left-color: #ffaa00;
            background: #3d2d2d;
        }
        .warning-icon {
            font-size: 18px;
            margin-right: 10px;
        }
        .warning-title {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .warning-message {
            color: #cccccc;
            margin-bottom: 5px;
        }
        .warning-remediation {
            color: #88cc88;
            font-style: italic;
            font-size: 14px;
        }
        .warnings-section {
            margin-top: 30px;
            background: #2d2d2d;
            padding: 20px;
            border-radius: 5px;
            border: 1px solid #dc143c;
        }
        .warnings-header {
            color: #dc143c;
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 15px;
            text-align: center;
        }
        .warning-count {
            display: inline-block;
            background: #dc143c;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 12px;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔴 REDHOOD CookieHunter</h1>
            <p>Advanced HTTP Cookie Security Analysis Tool</p>
        </div>
        
        <div class="form-section">
            <form id="cookieForm">
                <div class="form-group">
                    <label for="url">URL to Analyze:</label>
                    <input type="text" id="url" name="url" placeholder="https://example.com" required>
                </div>
                
                <div class="form-group">
                    <label for="method">HTTP Method:</label>
                    <select id="method" name="method">
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="headers">Custom Headers (optional):</label>
                    <textarea id="headers" name="headers" rows="3" placeholder="User-Agent: CookieHunter/1.0&#10;Accept: application/json"></textarea>
                </div>
                
                <div class="form-group">
                    <button type="submit" class="btn">Analyze Cookies</button>
                </div>
            </form>
        </div>
        
        <div class="results-section" id="results">
            <div class="loading" id="loading">
                <h3>Analyzing cookies...</h3>
            </div>
            <div id="content"></div>
        </div>
    </div>

    <script>
        document.getElementById('cookieForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const url = formData.get('url');
            const method = formData.get('method');
            const headers = formData.get('headers');
            
            const data = {
                urls: [url],
                method: method,
                data: '',
                headers: headers || ''
            };
            
            document.getElementById('results').style.display = 'block';
            document.getElementById('loading').style.display = 'block';
            document.getElementById('content').innerHTML = '';
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (result.error) {
                    document.getElementById('content').innerHTML = '<div class="error">Error: ' + result.error + '</div>';
                } else {
                    let html = '<div class="summary">';
                    html += '<h3>Analysis Results</h3>';
                    html += '<p><strong>URL:</strong> ' + result.url + '</p>';
                    html += '<p><strong>Total Cookies:</strong> ' + result.summary.total_cookies + '</p>';
                    html += '<p><strong>Total Warnings:</strong> ' + result.summary.total_warnings + '</p>';
                    html += '<p><strong>Critical Issues:</strong> ' + result.summary.critical_warnings + '</p>';
                    html += '<p><strong>Errors:</strong> ' + result.summary.error_warnings + '</p>';
                    html += '<p><strong>Warnings:</strong> ' + result.summary.warning_warnings + '</p>';
                    html += '</div>';
                    
                    if (result.cookies && result.cookies.length > 0) {
                        html += '<div class="table-container">';
                        html += '<div class="table-header">🍪 Cookie Analysis Results</div>';
                        html += '<table class="cookie-table">';
                        html += '<tr><th>Cookie Name</th><th>Value</th><th>HttpOnly</th><th>Secure</th><th>SameSite</th><th>Path</th><th>Expires</th><th>Security Status</th></tr>';
                        
                        for (let cookie of result.cookies) {
                            let warningCount = cookie.warnings ? cookie.warnings.length : 0;
                            let securityStatus = '';
                            let cookieIndex = result.cookies.indexOf(cookie);
                            
                            if (warningCount === 0) {
                                securityStatus = '<span class="status-icon status-secure">✅ Secure</span>';
                            } else {
                                let statusClass = warningCount <= 2 ? 'status-warning' : 'status-insecure';
                                let statusIcon = warningCount <= 2 ? '⚠️' : '❌';
                                securityStatus = '<span class="security-status-clickable status-icon ' + statusClass + '" onclick="showCookieDetails(' + cookieIndex + ')">' + statusIcon + ' ' + warningCount + ' Issues</span>';
                            }
                            
                            html += '<tr>';
                            html += '<td><span class="cookie-name">' + cookie.name + '</span></td>';
                            html += '<td><span class="cookie-value" title="' + (cookie.value || '') + '">' + (cookie.value ? cookie.value.substring(0, 20) + (cookie.value.length > 20 ? '...' : '') : '') + '</span></td>';
                            html += '<td>' + (cookie.httponly ? '<span class="status-icon status-secure">✅</span>' : '<span class="status-icon status-insecure">❌</span>') + '</td>';
                            html += '<td>' + (cookie.secure ? '<span class="status-icon status-secure">✅</span>' : '<span class="status-icon status-insecure">❌</span>') + '</td>';
                            html += '<td>' + (cookie.samesite || 'None') + '</td>';
                            html += '<td>' + (cookie.path || '/') + '</td>';
                            html += '<td>' + (cookie.expires || 'Session') + '</td>';
                            html += '<td>' + securityStatus + '</td>';
                            html += '</tr>';
                        }
                        html += '</table>';
                        html += '</div>';
                        
                        if (result.warnings && result.warnings.length > 0) {
                            // Group warnings by severity
                            let criticalWarnings = result.warnings.filter(w => w.severity === 'critical');
                            let errorWarnings = result.warnings.filter(w => w.severity === 'error');
                            let warningWarnings = result.warnings.filter(w => w.severity === 'warning');
                            
                            html += '<div class="warnings-section">';
                            html += '<div class="warnings-header">';
                            html += '🔴 Security Warnings <span class="warning-count">' + result.warnings.length + '</span>';
                            html += '</div>';
                            
                            // Display Critical warnings
                            if (criticalWarnings.length > 0) {
                                html += '<h4 style="color: #ff4444; margin-top: 20px;">🔥 Critical Issues (' + criticalWarnings.length + ')</h4>';
                                for (let warning of criticalWarnings) {
                                    html += '<div class="warning-item warning-critical">';
                                    html += '<div class="warning-title">🔥 ' + warning.message.split(': ')[1] + '</div>';
                                    html += '<div class="warning-message">Cookie: ' + warning.message.split(': ')[0] + '</div>';
                                    if (warning.remediation) {
                                        html += '<div class="warning-remediation">💡 Solution: ' + warning.remediation + '</div>';
                                    }
                                    html += '</div>';
                                }
                            }
                            
                            // Display Error warnings
                            if (errorWarnings.length > 0) {
                                html += '<h4 style="color: #ff6b6b; margin-top: 20px;">❌ Errors (' + errorWarnings.length + ')</h4>';
                                for (let warning of errorWarnings) {
                                    html += '<div class="warning-item warning-error">';
                                    html += '<div class="warning-title">❌ ' + warning.message.split(': ')[1] + '</div>';
                                    html += '<div class="warning-message">Cookie: ' + warning.message.split(': ')[0] + '</div>';
                                    if (warning.remediation) {
                                        html += '<div class="warning-remediation">💡 Solution: ' + warning.remediation + '</div>';
                                    }
                                    html += '</div>';
                                }
                            }
                            
                            // Display Warning warnings
                            if (warningWarnings.length > 0) {
                                html += '<h4 style="color: #ffaa00; margin-top: 20px;">⚠️ Warnings (' + warningWarnings.length + ')</h4>';
                                for (let warning of warningWarnings) {
                                    html += '<div class="warning-item warning-warning">';
                                    html += '<div class="warning-title">⚠️ ' + warning.message.split(': ')[1] + '</div>';
                                    html += '<div class="warning-message">Cookie: ' + warning.message.split(': ')[0] + '</div>';
                                    if (warning.remediation) {
                                        html += '<div class="warning-remediation">💡 Solution: ' + warning.remediation + '</div>';
                                    }
                                    html += '</div>';
                                }
                            }
                            
                            html += '</div>';
                        }
                    } else {
                        html += '<p>No cookies found.</p>';
                    }
                    
                    // Add modal for cookie details
                    html += '<div id="cookieDetailsModal" class="cookie-details-modal">';
                    html += '<div class="modal-content">';
                    html += '<span class="close-modal" onclick="closeCookieDetails()">&times;</span>';
                    html += '<div class="modal-header">🍪 Cookie Security Details</div>';
                    html += '<div id="modalContent"></div>';
                    html += '</div>';
                    html += '</div>';
                    
                    // Store cookies data for modal
                    window.cookiesData = result.cookies;
                    
                    document.getElementById('content').innerHTML = html;
                }
                
            } catch (error) {
                document.getElementById('content').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            } finally {
                document.getElementById('loading').style.display = 'none';
            }
        });
        
        // Modal functions
        function showCookieDetails(cookieIndex) {
            const cookie = window.cookiesData[cookieIndex];
            const modal = document.getElementById('cookieDetailsModal');
            const modalContent = document.getElementById('modalContent');
            
            let detailsHtml = '<div style="margin-bottom: 20px;">';
            detailsHtml += '<h3 style="color: #dc143c;">🍪 Cookie: ' + cookie.name + '</h3>';
            detailsHtml += '<p><strong>Value:</strong> <span style="font-family: monospace; background: #3d3d3d; padding: 5px; border-radius: 3px; word-break: break-all;">' + (cookie.value || 'N/A') + '</span></p>';
            detailsHtml += '<p><strong>HttpOnly:</strong> ' + (cookie.httponly ? '✅ Yes' : '❌ No') + '</p>';
            detailsHtml += '<p><strong>Secure:</strong> ' + (cookie.secure ? '✅ Yes' : '❌ No') + '</p>';
            detailsHtml += '<p><strong>SameSite:</strong> ' + (cookie.samesite || 'None') + '</p>';
            detailsHtml += '<p><strong>Path:</strong> ' + (cookie.path || '/') + '</p>';
            detailsHtml += '<p><strong>Expires:</strong> ' + (cookie.expires || 'Session') + '</p>';
            detailsHtml += '</div>';
            
            if (cookie.warnings && cookie.warnings.length > 0) {
                detailsHtml += '<h4 style="color: #ff6b6b; margin-top: 20px;">🔴 Security Issues Found:</h4>';
                
                // Group warnings by severity
                const criticalWarnings = cookie.warnings.filter(w => w.severity === 'critical');
                const errorWarnings = cookie.warnings.filter(w => w.severity === 'error');
                const warningWarnings = cookie.warnings.filter(w => w.severity === 'warning');
                
                if (criticalWarnings.length > 0) {
                    detailsHtml += '<h5 style="color: #ff4444;">🔥 Critical Issues (' + criticalWarnings.length + '):</h5>';
                    criticalWarnings.forEach(warning => {
                        detailsHtml += '<div class="cookie-detail-item">';
                        detailsHtml += '<div style="color: #ff4444; font-weight: bold;">🔥 ' + warning.message + '</div>';
                        if (warning.remediation) {
                            detailsHtml += '<div style="color: #88cc88; margin-top: 5px;">💡 Solution: ' + warning.remediation + '</div>';
                        }
                        detailsHtml += '</div>';
                    });
                }
                
                if (errorWarnings.length > 0) {
                    detailsHtml += '<h5 style="color: #ff6b6b;">❌ Errors (' + errorWarnings.length + '):</h5>';
                    errorWarnings.forEach(warning => {
                        detailsHtml += '<div class="cookie-detail-item">';
                        detailsHtml += '<div style="color: #ff6b6b; font-weight: bold;">❌ ' + warning.message + '</div>';
                        if (warning.remediation) {
                            detailsHtml += '<div style="color: #88cc88; margin-top: 5px;">💡 Solution: ' + warning.remediation + '</div>';
                        }
                        detailsHtml += '</div>';
                    });
                }
                
                if (warningWarnings.length > 0) {
                    detailsHtml += '<h5 style="color: #ffaa00;">⚠️ Warnings (' + warningWarnings.length + '):</h5>';
                    warningWarnings.forEach(warning => {
                        detailsHtml += '<div class="cookie-detail-item">';
                        detailsHtml += '<div style="color: #ffaa00; font-weight: bold;">⚠️ ' + warning.message + '</div>';
                        if (warning.remediation) {
                            detailsHtml += '<div style="color: #88cc88; margin-top: 5px;">💡 Solution: ' + warning.remediation + '</div>';
                        }
                        detailsHtml += '</div>';
                    });
                }
            } else {
                detailsHtml += '<div style="color: #4CAF50; font-weight: bold; text-align: center; padding: 20px;">✅ This cookie is secure!</div>';
            }
            
            modalContent.innerHTML = detailsHtml;
            modal.style.display = 'block';
        }
        
        function closeCookieDetails() {
            document.getElementById('cookieDetailsModal').style.display = 'none';
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('cookieDetailsModal');
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        }
    </script>
</body>
</html>
"""

# Write template to file
with open('templates/index.html', 'w', encoding='utf-8') as f:
    f.write(html_template)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        
        # Parse headers
        headers = None
        if data.get('headers'):
            headers = []
            for line in data['headers'].strip().split('\n'):
                if ':' in line:
                    headers.append(line.strip())
        
        # Run analysis
        hunter = CookieHunter()
        
        # Create temporary file for JSON output
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_file = f.name
        
        try:
            hunter.analyze_cookies(
                url=data['urls'][0],
                method=data['method'],
                custom_headers=headers,
                data=None,
                output_file=temp_file,
                json_output=True
            )
            
            # Read results
            with open(temp_file, 'r', encoding='utf-8') as f:
                result = json.load(f)
            
            return jsonify(result)
            
        finally:
            # Clean up temp file
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🔴 CookieHunter Web Interface")
    print("Starting server on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000) 