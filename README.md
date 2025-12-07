# DNS Spoofing Attack Tool (Educational Purpose Only)

> **Disclaimer:** This code and documentation are for educational purposes only. 
> DNS Spoofing (DNS Cache Poisoning) is illegal if used on networks without explicit permission. 
> This project demonstrates how DNS trust can be abused and helps understand core network security vulnerabilities.

## Overview
This tool performs a DNS Spoofing (DNS Cache Poisoning) attack by sending forged DNS responses to a target. 
The goal is to trick a **Client** or **DNS Resolver** into accepting a fake DNS record, causing the victim to be redirected to an **attacker-controlled IP address** instead of the legitimate server.  
Once the spoofed entry is cached, all future requests for the targeted domain will resolve to the attacker’s machine until the cache expires.

---

## Preconditions
For DNS spoofing to work successfully, the following conditions must be met:

1. **Unauthenticated DNS (No DNSSEC):**  
   The DNS resolver must not validate DNSSEC signatures. Without DNSSEC, DNS responses are not cryptographically verified and can be forged.

2. **Plaintext DNS Traffic:**  
   The victim must be using standard DNS over UDP port 53.  
   *Encrypted DNS (DoH/DoT) prevents this attack.*

3. **Ability to Send or Inject Forged DNS Responses:**  
   The attacker must be able to deliver spoofed packets that appear to come from an authoritative DNS server.  
   This is typically possible when the attacker is:
   * on the same LAN,  
   * performing ARP spoofing, or  
   * on a network that allows IP spoofing.

4. **Caching Resolver in Use:**  
   The target must rely on a DNS resolver that caches responses. A poisoned entry in the cache will impact all clients that query that resolver.

5. **Weak or Predictable DNS Entropy:**  
   Successful spoofing requires guessing DNS transaction IDs and source ports.  
   Resolvers with weak randomization are significantly more vulnerable.

---

