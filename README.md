# Security Agent
A local-first desktop security agent for detecting hardcoded secrets
and insecure configuration within developer project directories.

## Component 1
Real-Time Configuration & Secret Scanner

The scanner continuously monitors configured project directories and
detects potential exposed credentials using:

- Provider-specific regular expressions
- Generic secret detection
- Context analysis
- Shannon entropy analysis
- Confidence scoring
- Finding fingerprinting
- Duplicate suppression