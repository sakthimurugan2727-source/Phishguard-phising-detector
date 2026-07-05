// Phishing Detection Logic Ported to JavaScript

function checkURL(url) {
    let score = 0;
    let reasons = [];

    // 1. IP address in URL
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
    if (ipRegex.test(url)) {
        score += 3;
        reasons.push("IP address found in URL instead of a domain name.");
    }

    // 2. "@" symbol in URL
    if (url.includes("@")) {
        score += 3;
        reasons.push("'@' symbol found in URL (often used to obscure the actual destination).");
    }

    // 3. Use of URL shorteners
    try {
        // Need to ensure protocol exists to parse domain correctly
        let urlToParse = url;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            urlToParse = 'http://' + url;
        }
        
        const parsedUrl = new URL(urlToParse);
        const domain = parsedUrl.hostname;
        
        const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly'];
        if (shorteners.some(shortener => domain.includes(shortener))) {
            score += 2;
            reasons.push("URL shortener service detected.");
        }

        // 7. Multiple subdomains
        if ((domain.match(/\./g) || []).length > 3) {
            score += 2;
            reasons.push("Unusual number of subdomains detected.");
        }

    } catch (e) {
        // Invalid URL format
    }

    // 4. Suspicious keywords in URL
    const suspiciousKeywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'paypal', 'signin', 'confirm', 'free', 'bonus'];
    const urlLower = url.toLowerCase();
    
    suspiciousKeywords.forEach(keyword => {
        if (urlLower.includes(keyword)) {
            score += 1;
            reasons.push(`Suspicious keyword '${keyword}' found in URL.`);
        }
    });
            
    // 5. Length of URL
    if (url.length > 75) {
        score += 1;
        reasons.push("URL is unusually long (>75 characters).");
    }
        
    // 6. Check for HTTP instead of HTTPS
    if (url.startsWith("http://")) {
        score += 1;
        reasons.push("Connection is not secure (HTTP instead of HTTPS).");
    }

    return { score, reasons };
}

function checkEmail(text) {
    let score = 0;
    let reasons = [];
    
    const textLower = text.toLowerCase();
    
    // 1. Urgency / Threat
    const urgentKeywords = ['urgent', 'immediate action required', 'account suspended', 'will be closed', 'final warning', 'action needed', 'act immediately'];
    urgentKeywords.forEach(keyword => {
        if (textLower.includes(keyword)) {
            score += 2;
            reasons.push(`Sense of urgency/threat detected: '${keyword}'.`);
        }
    });
            
    // 2. Too good to be true / Rewards
    const rewardKeywords = ['winner', 'lottery', 'claim your prize', 'you have won', 'exclusive offer', 'gift card', 'free money'];
    rewardKeywords.forEach(keyword => {
        if (textLower.includes(keyword)) {
            score += 2;
            reasons.push(`Suspicious reward offer detected: '${keyword}'.`);
        }
    });

    // 3. Requests for personal info / action
    const actionKeywords = ['click here', 'click the link', 'verify your account', 'login to confirm', 'update your billing', 'password reset', 'verify identity'];
    actionKeywords.forEach(keyword => {
        if (textLower.includes(keyword)) {
            score += 2;
            reasons.push(`Call to action often used in phishing: '${keyword}'.`);
        }
    });

    // 4. General suspicious terms
    const generalSuspicious = ['dear customer', 'dear user', 'kindly', 'attached invoice', 'bank details', 'ssn', 'social security'];
    generalSuspicious.forEach(keyword => {
        if (textLower.includes(keyword)) {
            score += 1;
            reasons.push(`Common phishing phrase or sensitive info request detected: '${keyword}'.`);
        }
    });

    return { score, reasons };
}

// UI Interaction Logic
document.addEventListener('DOMContentLoaded', () => {
    
    // Elements
    const tabBtns = document.querySelectorAll('.tab-btn');
    const inputAreas = document.querySelectorAll('.input-area');
    
    const urlInput = document.getElementById('url-input');
    const emailInput = document.getElementById('email-input');
    const analyzeUrlBtn = document.getElementById('analyze-url-btn');
    const analyzeEmailBtn = document.getElementById('analyze-email-btn');
    
    const resultsArea = document.getElementById('results-area');
    const statusIcon = document.getElementById('status-icon');
    const statusTitle = document.getElementById('status-title');
    const statusDesc = document.getElementById('status-desc');
    const indicatorsList = document.getElementById('indicators-list');
    const indicatorsSection = document.getElementById('indicators-section');
    
    // Tab Switching
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active classes
            tabBtns.forEach(b => b.classList.remove('active'));
            inputAreas.forEach(a => a.classList.remove('active'));
            
            // Add active to clicked tab
            btn.classList.add('active');
            const targetId = btn.getAttribute('data-tab') + '-area';
            document.getElementById(targetId).classList.add('active');
            
            // Hide results when switching tabs
            resultsArea.classList.remove('active');
        });
    });
    
    // Display Results function
    function showResults(result) {
        const { score, reasons } = result;
        
        // Remove all status classes
        resultsArea.classList.remove('status-safe', 'status-low', 'status-medium', 'status-high');
        
        // Update UI based on score
        if (score === 0) {
            resultsArea.classList.add('status-safe');
            statusIcon.innerHTML = '<i class="ph-fill ph-check-circle"></i>';
            statusTitle.textContent = 'Safe';
            statusDesc.textContent = 'No obvious phishing indicators found.';
            indicatorsSection.style.display = 'none';
        } else {
            indicatorsSection.style.display = 'block';
            
            if (score < 3) {
                resultsArea.classList.add('status-low');
                statusIcon.innerHTML = '<i class="ph-fill ph-warning"></i>';
                statusTitle.textContent = 'Suspicious (Low Risk)';
                statusDesc.textContent = 'A few potential red flags detected. Proceed with caution.';
            } else if (score < 6) {
                resultsArea.classList.add('status-medium');
                statusIcon.innerHTML = '<i class="ph-fill ph-warning-circle"></i>';
                statusTitle.textContent = 'Suspicious (Medium Risk)';
                statusDesc.textContent = 'Multiple phishing indicators found. Highly recommended to avoid.';
            } else {
                resultsArea.classList.add('status-high');
                statusIcon.innerHTML = '<i class="ph-fill ph-shield-warning"></i>';
                statusTitle.textContent = 'Highly Suspicious (High Risk)';
                statusDesc.textContent = 'Strong evidence of a phishing attempt. Do not interact with this.';
            }
            
            // Render reasons
            indicatorsList.innerHTML = '';
            reasons.forEach(reason => {
                const li = document.createElement('li');
                // Determine icon based on severity (simplification: we map it based on string content for UI)
                let iconClass = 'ph-warning';
                let liClass = 'indicator-warning';
                
                if (score >= 6 || reason.includes('IP address') || reason.includes('High Risk')) {
                     iconClass = 'ph-warning-octagon';
                     liClass = 'indicator-danger';
                }
                
                li.className = liClass;
                li.innerHTML = `<i class="ph ${iconClass}"></i> <span>${reason}</span>`;
                indicatorsList.appendChild(li);
            });
        }
        
        // Show results
        resultsArea.classList.add('active');
    }
    
    // Event Listeners for Analysis
    analyzeUrlBtn.addEventListener('click', () => {
        const url = urlInput.value.trim();
        if (url) {
            const result = checkURL(url);
            showResults(result);
        } else {
            alert('Please enter a valid URL.');
        }
    });
    
    // Handle Enter key for URL
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            analyzeUrlBtn.click();
        }
    });
    
    analyzeEmailBtn.addEventListener('click', () => {
        const email = emailInput.value.trim();
        if (email) {
            const result = checkEmail(email);
            showResults(result);
        } else {
            alert('Please paste email text to analyze.');
        }
    });
});
