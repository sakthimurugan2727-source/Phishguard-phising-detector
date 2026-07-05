# PhishGuard — Phishing Detection System

PhishGuard is a clean, modern, client-side web application designed to help users identify potential phishing attempts. By analyzing URLs and email contents against common heuristics and red flags, PhishGuard provides real-time risk assessments to help secure your digital footprint.

## Features

- **URL Analysis**: Scans input links for common phishing heuristics, including:
  - Presence of IP addresses instead of domain names.
  - `@` symbols used to obscure destinations.
  - The use of URL shorteners (e.g., `bit.ly`, `tinyurl.com`).
  - Excessive subdomains.
  - Suspicious keywords (e.g., `login`, `verify`, `paypal`).
  - Excessive URL length.
  - Insecure protocol use (HTTP instead of HTTPS).
- **Email Content Analysis**: Evaluates email text for indicators of fraud, including:
  - Sense of urgency or threats (e.g., "account suspended", "urgent action required").
  - Too-good-to-be-true rewards or lottery offers.
  - Prominent calls to action (e.g., "click here to verify").
  - Sensitive information requests or generic greetings.
- **Risk Assessment Levels**: Displays clear results with dynamic risk levels (Safe, Low Risk, Medium Risk, High Risk) accompanied by actionable breakdown points explaining why the content was flagged.
- **Beautiful User Interface**: Built using modern design principles, responsive layout, rich typography (Inter), and clear icons (Phosphor Icons).

## Tech Stack

The application is purely frontend-based and built using the following technologies:

- **HTML5**: Semantic web markup.
- **CSS3**: Vanilla CSS utilizing modern properties (CSS custom properties/variables, Flexbox, CSS Grid) for a premium glassmorphic interface.
- **JavaScript (ES6+)**: Client-side analysis logic implementing regular expressions and string matching heuristics.
- **Phosphor Icons**: Library of icons for visual indicators.
- **Google Fonts (Inter)**: High-quality typography.

## Getting Started

Since this is a client-side web application, no server-side installation or dependencies are required.

### Running the App Locally

1. Clone or download this repository.
2. Navigate to the project folder:
   ```bash
   cd phishing_web
   ```
3. Open the `index.html` file in your preferred web browser.
   
## Disclaimer

PhishGuard is a heuristic analysis tool designed for educational and preliminary screening purposes. While it highlights common indicators of phishing, it is not a substitute for robust email security filters or official domain verification systems. Always exercise caution when sharing sensitive information.
