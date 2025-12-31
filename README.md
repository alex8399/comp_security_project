# SSL Stripping Attack Tool (Educational Purpose Only)

> **Disclaimer:** This code and documentation are for educational purposes only. SSL Stripping is illegal if used on networks without explicit permission. This project demonstrates how insecure HTTP connections and improper HTTPS enforcement can be exploited to compromise user security.

## Overview
SSL Stripping is an attack technique that forces a victim to communicate with a website over **unencrypted HTTP** instead of **secure HTTPS**, without the victim noticing. 
While the victim believes they are using a secure connection, the attacker intercepts and relays traffic, maintaining a secure HTTPS connection only between themselves and the legitimate server.

By removing or modifying HTTPS redirects, the attacker prevents the victim’s browser from upgrading the connection to HTTPS.
This allows the attacker to **read**, **modify**, or **inject** content into the victim’s web traffic, including login credentials, cookies, and sensitive data.

SSL Stripping is commonly used as part of a **Man-in-the-Middle (MITM)** attack and is often combined with techniques such as 
ARP spoofing or DNS spoofing to position the attacker between the victim and the target website.

---

## Preconditions
For SSL Stripping to work successfully, the following conditions must be met:

1. **Man-in-the-Middle Position:**  
   The attacker must be able to intercept and forward traffic between the victim and the server.  
   This is typically achieved using techniques such as ARP spoofing or rogue access points.

2. **Initial HTTP Connection or Redirect:**  
   The victim must initially access the website over HTTP or rely on an HTTP-to-HTTPS redirect.  
   If the site is accessed directly via HTTPS, SSL stripping is not possible.

3. **No HSTS (HTTP Strict Transport Security):**  
   The target website must not enforce HSTS.  
   HSTS forces browsers to always use HTTPS and prevents downgrade attacks.

4. **User Does Not Verify HTTPS Indicators:**  
   The victim must not notice missing HTTPS indicators such as:
   - the lock icon,
   - the `https://` prefix,
   - browser security warnings.

5. **No HTTPS Preloading:**  
   Websites included in browser HTTPS preload lists cannot be downgraded to HTTP, making SSL stripping ineffective against them.

---

