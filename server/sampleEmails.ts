/**
 * MailTrace AI - Authoritative Forensic Email Investigation Scenarios
 * ====================================================================
 * High-fidelity email specimens containing multi-hop RFC 5322 Received headers,
 * authentic authentication tags (SPF, DKIM, DMARC), and full forensic evidence chains.
 */

export interface SampleEmailScenario {
  id: string;
  name: string;
  scenarioTag: string;
  threatType: string;
  expectedRisk: number;
  description: string;
  rawEml: string;
}

export const SAMPLE_SCENARIOS: SampleEmailScenario[] = [
  {
    id: 'scenario-4-fake-invoice',
    name: 'Executive Wire Transfer & Fake Invoice BEC Attack',
    scenarioTag: 'BEC / Wire Fraud',
    threatType: 'BEC_FRAUD',
    expectedRisk: 94,
    description: 'Multi-hop BEC wire transfer fraud originating from an offshore bulletproof server routing through an intermediate VPS to internal enterprise mail exchangers.',
    rawEml: `Received: by mail-inbound.enterprise-defense.com (Postfix, from userid 1001)
\tid 4V9xL021kMz8901; Tue, 17 Sep 2026 08:42:15 +0000
Received: from mx1.secure-mailgateway.net (mx1.secure-mailgateway.net [198.51.100.25])
\tby inbound-mx.enterprise.com (Postfix) with ESMTPS id 4V9xK718bFz1234
\tfor <cfo@enterprise-corp.com>; Tue, 17 Sep 2026 08:42:12 +0000
Received: from vps-115.hosteurope.de (vps-115.hosteurope.de [194.26.29.115])
\tby mx1.secure-mailgateway.net (CloudDefense Gateway) with ESMTPS id 992817264
\tusing TLSv1.3 with cipher TLS_AES_256_GCM_SHA384; Tue, 17 Sep 2026 08:42:08 +0000
Received: from vps-node-91.bulletproof-host.ru (vps-node-91.bulletproof-host.ru [185.220.101.42])
\tby vps-115.hosteurope.de with ESMTP id 8829104; Tue, 17 Sep 2026 08:41:55 +0000
Authentication-Results: mx1.secure-mailgateway.net;
\tdkim=fail (signature verification failed) header.d=supplier-accounting-portal.com;
\tspf=softfail (mx1.secure-mailgateway.net: domain of billing@supplier-accounting-portal.com does not designate 185.220.101.42 as permitted sender) smtp.mailfrom=billing@supplier-accounting-portal.com;
\tdmarc=fail (p=reject sp=reject) header.from=supplier-accounting-portal.com
Received-SPF: softfail (mx1.secure-mailgateway.net: domain of billing@supplier-accounting-portal.com does not designate 185.220.101.42 as permitted sender) client-ip=185.220.101.42;
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=supplier-accounting-portal.com;
\ts=selector1; t=1726562515;
\th=From:To:Subject:Date:Message-ID:MIME-Version:Content-Type;
\tbh=z4rM+uQJb2YQ/N13xKq3xK9L2xV+3wA=;
\tb=FakeSignatureHeaderVerificationFailure000000000000000000000=
From: "Billing Dept - QuickTech Supplies" <billing@supplier-accounting-portal.com>
To: "Chief Financial Officer" <cfo@enterprise-corp.com>
Reply-To: <payment-audit@offshore-escrow-routing.com>
Subject: URGENT: Revised Wire Settlement Instructions for Invoice #QT-889412
Date: Tue, 17 Sep 2026 08:41:50 +0000
Message-ID: <20260917084150.8829104@vps-node-91.bulletproof-host.ru>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html>
<body>
<p>Dear Finance Team,</p>
<p>Please note that our settlement banking details have been temporarily adjusted due to our annual audit.</p>
<p>Kindly remit the pending invoice payment of <strong>$148,500.00 USD</strong> immediately using the banking coordinates provided below to avoid supply chain interruption.</p>
<p><strong>Beneficiary Bank:</strong> Offshore Maritime Union Bank<br>
<strong>IBAN:</strong> CH930000000018522010142<br>
<strong>Routing Code:</strong> OMUBCH22XXX</p>
<p>Thank you for your prompt cooperation.</p>
<p>Regards,<br>Accounts Receivable Directorate</p>
</body>
</html>`
  },
  {
    id: 'scenario-1-credential-harvesting',
    name: 'Office 365 Session Hijack & Credential Harvester',
    scenarioTag: 'Phishing / Harvest',
    threatType: 'CREDENTIAL_HARVEST',
    expectedRisk: 88,
    description: 'Spear-phishing lure impersonating Microsoft IT security alert with malicious token harvesting URL routing through compromised Singapore broadband infrastructure.',
    rawEml: `Received: by mail-inbound.enterprise.com (Postfix) id 5A8109923;
\tTue, 17 Sep 2026 09:12:30 +0000
Received: from mail-ed1-f52.google.com (mail-ed1-f52.google.com [209.85.208.52])
\tby mx.enterprise.com (Postfix) with ESMTPS id 4T18bFz1234
\tfor <analyst@enterprise-corp.com>; Tue, 17 Sep 2026 09:12:28 +0000
Received: from mail194.em.discountwalas.com (mail194.em.discountwalas.com [167.114.144.194])
\tby mail-ed1-f52.google.com with ESMTPS id 771629; Tue, 17 Sep 2026 09:12:15 +0000
Authentication-Results: mx.enterprise.com;
\tdkim=pass header.d=discountwalas.com;
\tspf=pass (mx.enterprise.com: domain of alert@discountwalas.com designates 167.114.144.194 as permitted sender) client-ip=167.114.144.194;
\tdmarc=pass (p=none) header.from=discountwalas.com
Received-SPF: pass client-ip=167.114.144.194;
From: "Microsoft 365 Security Team" <security-notification@discountwalas.com>
To: <analyst@enterprise-corp.com>
Reply-To: <attacker-drop@novogara.com>
Subject: Action Required: Your M365 Password Expires in 24 Hours
Date: Tue, 17 Sep 2026 09:12:10 +0000
Message-ID: <alert-991823@mail194.em.discountwalas.com>
Content-Type: text/html; charset=UTF-8

<html>
<body>
<h3>Security Notification: Password Expiration Notice</h3>
<p>Your corporate Microsoft 365 workstation credentials will expire today. To retain access to your mailbox, please re-authenticate immediately:</p>
<p><a href="https://auth-m365-session-verify.cloud/login?id=88192">Keep Current Password & Validate Session</a></p>
<p>Microsoft Cyber Defense Center</p>
</body>
</html>`
  },
  {
    id: 'scenario-2-executive-bec',
    name: 'Executive Impersonation / CEO Wire Fraud',
    scenarioTag: 'CEO BEC Impersonation',
    threatType: 'BEC_IMPERSONATION',
    expectedRisk: 92,
    description: 'Executive impersonation utilizing a Novogara cloud relay targeting corporate treasury with spoofed display name headers.',
    rawEml: `Received: by internal-mail.corp.com (Postfix) id 981726351;
\tTue, 17 Sep 2026 10:05:44 +0000
Received: from mail-nam01on0055.outbound.protection.outlook.com (mail-nam01on0055.outbound.protection.outlook.com [40.107.240.55])
\tby inbound-mx.corp.com (Postfix) with ESMTPS id 8172635; Tue, 17 Sep 2026 10:05:40 +0000
Received: from out-mta.paypa1-security.com (out-mta.paypa1-security.com [91.240.118.88])
\tby mail-nam01on0055.outbound.protection.outlook.com with ESMTP id 9918276; Tue, 17 Sep 2026 10:05:25 +0000
Authentication-Results: inbound-mx.corp.com;
\tspf=fail client-ip=91.240.118.88;
\tdkim=none;
\tdmarc=fail (p=reject) header.from=corp.com
From: "David Sterling (CEO)" <david.sterling@paypa1-security.com>
To: "Sarah Jenkins (Treasury)" <s.jenkins@corp.com>
Subject: Confidential Acquisition Settlement
Date: Tue, 17 Sep 2026 10:05:20 +0000
Message-ID: <exec-ceo-9918@out-mta.paypa1-security.com>
Content-Type: text/plain; charset=UTF-8

Sarah,

I am currently in an executive committee meeting and cannot take calls. We are finalizing an urgent NDA transaction.
Please process an expedited payment of $82,400 to the legal retainers account before 12:00 PM EST.

I will send the counter-signed documentation once out of the briefing.

David Sterling
Chief Executive Officer`
  },
  {
    id: 'scenario-3-quishing-qr',
    name: 'Quishing / 2FA QR Code Bypass Attack',
    scenarioTag: 'Quishing (QR Code)',
    threatType: 'QUISHING',
    expectedRisk: 86,
    description: 'Quishing campaign leveraging embedded QR codes to bypass traditional email gateway URL scanners, routed via Amazon SES and Seychelles infrastructure.',
    rawEml: `Received: by mail-inbound.enterprise.com (Postfix) id 77618293;
\tTue, 17 Sep 2026 11:30:15 +0000
Received: from a27-41.smtp-out.us-west-2.amazonses.com (a27-41.smtp-out.us-west-2.amazonses.com [54.240.27.41])
\tby mx.enterprise.com with ESMTPS id 66281726; Tue, 17 Sep 2026 11:30:10 +0000
Received: from bulletproof-mta.seychelles-cloud.io (bulletproof-mta.seychelles-cloud.io [154.16.192.44])
\tby a27-41.smtp-out.us-west-2.amazonses.com with ESMTP id 55192847; Tue, 17 Sep 2026 11:29:55 +0000
From: "IT Service Desk Authenticator" <authenticator@amazon-ses-delivery.com>
To: <employee@enterprise-corp.com>
Subject: Action Required: Mandatory Microsoft Authenticator QR Sync
Date: Tue, 17 Sep 2026 11:29:50 +0000
Message-ID: <qr-ses-881928@a27-41.smtp-out.us-west-2.amazonses.com>
Content-Type: text/html; charset=UTF-8

<html>
<body>
<h2>Mandatory MFA Upgrade Required</h2>
<p>Due to recent security policy changes, all corporate users must scan the QR code below using their mobile authenticator application to synchronize 2FA tokens:</p>
<p><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=" alt="2FA Verification QR Code" width="180" height="180" /></p>
<p>Failure to calibrate your token within 12 hours will temporarily suspend single sign-on privileges.</p>
</body>
</html>`
  },
  {
    id: 'scenario-5-legitimate-newsletter',
    name: 'Verified Legitimate Enterprise Security Bulletin',
    scenarioTag: 'Legitimate / Clean',
    threatType: 'LEGITIMATE',
    expectedRisk: 4,
    description: 'Clean legitimate corporate advisory with 100% valid SPF, DKIM, and DMARC passing through Google Workspace infrastructure.',
    rawEml: `Received: by mail-inbound.enterprise.com (Postfix) id 11928374;
\tTue, 17 Sep 2026 12:00:20 +0000
Received: from mx2.secure-mailgateway.net (mx2.secure-mailgateway.net [198.51.100.18])
\tby inbound-mx.enterprise.com with ESMTPS id 22918274; Tue, 17 Sep 2026 12:00:15 +0000
Received: from mail-pj1-f54.google.com (mail-pj1-f54.google.com [209.85.216.54])
\tby mx2.secure-mailgateway.net with ESMTPS id 33918274; Tue, 17 Sep 2026 12:00:10 +0000
Authentication-Results: mx2.secure-mailgateway.net;
\tdkim=pass header.d=security-bulletin.org;
\tspf=pass (mx2.secure-mailgateway.net: domain of advisory@security-bulletin.org designates 209.85.216.54 as permitted sender) client-ip=209.85.216.54;
\tdmarc=pass (p=reject) header.from=security-bulletin.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=security-bulletin.org;
\ts=google; t=1726574410;
\th=From:To:Subject:Date:Message-ID:MIME-Version:Content-Type;
\tbh=ABCDEF1234567890+=;
\tb=ValidCryptographicSignatureVerifiedSuccessfully11111111111=
From: "Cybersecurity Alert Center" <advisory@security-bulletin.org>
To: <security-team@enterprise-corp.com>
Subject: Weekly Vulnerability Digest & Patch Summary
Date: Tue, 17 Sep 2026 12:00:05 +0000
Message-ID: <digest-20260917@security-bulletin.org>
Content-Type: text/plain; charset=UTF-8

Team,

Please review the attached patch summaries for critical CVEs resolved this cycle.
All core enterprise perimeter systems have successfully received automatic updates.

Security Operations Team`
  },
  {
    id: 'scenario-6-localhost-dev-specimen',
    name: 'Localhost / Internal Development Specimen (Non-Mappable)',
    scenarioTag: 'Loopback / LAN Only',
    threatType: 'INTERNAL_LAN',
    expectedRisk: 10,
    description: 'Internal development specimen containing only loopback (127.0.0.1) and RFC 1918 private LAN hops. Validates that loopback infrastructure is not plotted on the public geo-trace map while fully presenting forensic timeline hops.',
    rawEml: `Received: by mail.localdomain (Postfix, from userid 1000)
\tid 3x918274a; Tue, 17 Sep 2026 12:30:40 +0000
Received: from dev-workstation.internal (dev-workstation.internal [192.168.1.105])
\tby mail.localdomain (Postfix) with ESMTPA id 2b817264; Tue, 17 Sep 2026 12:30:35 +0000
Received: from localhost (localhost [127.0.0.1])
\tby dev-workstation.internal (Postfix) with ESMTP id 1a716253; Tue, 17 Sep 2026 12:30:30 +0000
From: "Local Test Agent" <test@localhost>
To: <developer@localhost>
Subject: Automated CI/CD Notification Test
Date: Tue, 17 Sep 2026 12:30:25 +0000
Message-ID: <ci-build-88192@localhost>
Content-Type: text/plain; charset=UTF-8

Automated build test completed successfully in local staging environment.`
  }
];
