---
title: "Diamond Model in the Life of a CTI Analyst"
classes: wide
header:
  teaser: /assets/images/cyber-threat-intelligence/Diamond-Model/diamond_model_intrusion_analysis_adversary_diagram_034e4dcd23.jpg

ribbon: yellow
description: "The Diamond Model isn’t just another buzzword; it’s a practical tool that empowers CTI analysts"
categories:
  - Cyber Threat Intelligence
---

Hello Analysts around the world!

Imagine that you're a cyber threat intelligence (CTI) analyst sipping your third cup of coffee for the day, staring at a suspicious log entry. It’s a breadcrumb, just one piece of a larger puzzle. But how do you transform this fragment into actionable intelligence?

In this blog, we’ll take a tour of the Diamond Model—what it is, how it works, and why it’s indispensable in the life of a CTI analyst. Along the way, we’ll pepper in some real-world scenarios to keep things digestible .

### What is the Diamond Model?

![[/assets/images/cyber-threat-intelligence/Diamond-Model/diamond_model_intrusion_analysis_adversary_diagram_034e4dcd23.jpg]]
Reference: https://www.recordedfuture.com/blog/diamond-model-intrusion-analysis

The Diamond Model of Intrusion Analysis, introduced by Sergio Caltagirone, Andrew Pendergast, and Christopher Betz in 2013, is a framework for analyzing and understanding cyber threats. It’s built around four core vertices:

1. **Adversary:** The threat actor or group behind the activity.
2. **Infrastructure:** The systems, tools, and infrastructure used to carry out the attack.
3. **Victim:** The target(s) of the attack.
4. **Capability:** The techniques, exploits, and malware leveraged in the attack.

At the center of the model lies the event, tying everything together. The relationships between these vertices help analysts uncover the who, what, why, and how of a cyber incident.

### The Diamond Model in Action: A Day in the Life

Again Imagine that You receive an alert about a new phishing campaign targeting your organization. Here’s how you might use the Diamond Model to dissect it.

#### Step 1: Identify the Victim

The alert reveals the phishing emails are being sent to employees in the finance department. Congratulations, you’ve pinned down your **Victim** vertex. The attackers are clearly interested in sensitive financial data, possibly planning a Business Email Compromise (BEC).

#### Step 2: Investigate the Infrastructure

Next, you analyze the email headers and discover the attackers used a spoofed domain and a bulletproof hosting provider. Your **Infrastructure** vertex is coming into focus. A quick OSINT search reveals the IP address associated with this hosting provider has been linked to previous phishing campaigns.

#### Step 3: Uncover the Capability

The phishing email includes a malicious link leading to a fake login page—a credential-stealing tactic. With this, you’ve identified the **Capability** vertex. Further analysis shows the phishing kit is a known variant, providing more clues about the attacker’s technical proficiency.

#### Step 4: Profile the Adversary

Pulling the threads together, you compare the TTPs (tactics, techniques, and procedures) to past incidents. The spoofed domain, bulletproof hosting, and phishing kit all point to a known adversary group. Meet your **Adversary** vertex.

### Why CTI Analysts Love the Diamond Model

The Diamond Model isn’t just another buzzword; it’s a practical tool that empowers CTI analysts to:

1. **Simplify Complexity:** Cyber incidents can feel like tangled webs. The Diamond Model helps you break them into digestible pieces.
2. **Enhance Attribution:** By mapping relationships, you can better identify adversaries and their patterns.
3. **Enable Collaboration:** Sharing intelligence framed within the Diamond Model helps teams and organizations speak the same analytical language.
4. **Prioritize Actions:** Understanding the relationships between vertices aids in focusing on the most critical areas, like mitigating infrastructure or monitoring specific adversaries.

### Real-World Example: WannaCry

Let’s take a famous case: the WannaCry ransomware attack of 2017.

- **Adversary:** Likely the Lazarus Group, a North Korean threat actor.
- **Infrastructure:** Fast-flux hosting networks and hard-coded command-and-control (C2) servers.
- **Victim:** Organizations worldwide, from hospitals to logistics companies.
- **Capability:** A wormable ransomware leveraging the EternalBlue exploit.

Using the Diamond Model, analysts pieced together these elements to understand the attack, mitigate its impact, and prepare for similar threats.

### Pro Tips for Using the Diamond Model

1. **Stay Curious:** Threat landscapes evolve rapidly. Don’t just look at the immediate event; explore the relationships and historical context.
2. **Leverage Threat Intel Platforms:** Tools like MISP or ThreatConnect can help you visualize and correlate Diamond Model elements.
3. **Document Everything:** Build a library of past analyses. Patterns emerge over time, and your future self will thank you.

### Final Thoughts

In the ever-challenging world of cyber threat intelligence, the Diamond Model is more than a framework; it’s a mindset. By breaking down threats into manageable components and examining their relationships, CTI analysts can uncover hidden connections, anticipate adversary actions, and safeguard their organizations with precision.

So the next time you’re knee-deep in threat data, grab your proverbial Diamond Model toolkit. It’s not just a framework—it’s your best friend in the fight against cyber adversaries.
