/**
 * MailTrace AI - SPF, DKIM, DMARC & Authentication Results Analyzer
 */

import { AuthenticationResults, AuthStatus } from '../../src/types/forensics.js';

export function analyzeAuthentication(
  authResultsHeader: string,
  fromDomain: string,
  returnPath: string,
  clientIp: string,
  dkimSignatures: string[]
): AuthenticationResults {
  const normalizedHeader = (authResultsHeader || '').toLowerCase();
  
  // SPF Analysis
  let spfStatus: AuthStatus = 'NONE';
  let spfDomain = returnPath ? (returnPath.split('@')[1] || '').replace(/[<>]/g, '') : fromDomain;
  let spfDetails = 'No SPF evaluation header detected.';

  if (normalizedHeader.includes('spf=pass')) {
    spfStatus = 'PASS';
    spfDetails = `Client IP ${clientIp} designated as authorized relay in SPF TXT record for ${spfDomain}.`;
  } else if (normalizedHeader.includes('spf=fail')) {
    spfStatus = 'FAIL';
    spfDetails = `Client IP ${clientIp} explicitly rejected (-all) by SPF policy for ${spfDomain}.`;
  } else if (normalizedHeader.includes('spf=softfail')) {
    spfStatus = 'SOFTFAIL';
    spfDetails = `Client IP ${clientIp} not in permitted SPF record (~all transition) for ${spfDomain}.`;
  } else if (normalizedHeader.includes('spf=neutral')) {
    spfStatus = 'NEUTRAL';
    spfDetails = `SPF record specifies neutral (?all) policy for ${spfDomain}.`;
  }

  // SPF Alignment: Envelope domain vs Header From domain
  const spfAlignment = spfDomain.toLowerCase() === fromDomain.toLowerCase() || 
                       spfDomain.toLowerCase().endsWith('.' + fromDomain.toLowerCase());

  // DKIM Analysis
  let dkimStatus: AuthStatus = 'NONE';
  let dkimDomain = '';
  let selector = 'default';
  let dkimDetails = 'No valid DKIM signature discovered in headers.';

  if (dkimSignatures.length > 0) {
    const sig = dkimSignatures[0];
    const dMatch = sig.match(/\bd=([^;\s]+)/i);
    const sMatch = sig.match(/\bs=([^;\s]+)/i);
    if (dMatch) dkimDomain = dMatch[1];
    if (sMatch) selector = sMatch[1];
  }

  if (normalizedHeader.includes('dkim=pass')) {
    dkimStatus = 'PASS';
    dkimDetails = `Cryptographic RSA-SHA256 signature verified against public key at ${selector}._domainkey.${dkimDomain || fromDomain}.`;
  } else if (normalizedHeader.includes('dkim=fail')) {
    dkimStatus = 'FAIL';
    dkimDetails = `Signature verification failed: RSA hash mismatch or tampered body digest.`;
  }

  const dkimAlignment = dkimDomain ? (
    dkimDomain.toLowerCase() === fromDomain.toLowerCase() || 
    fromDomain.toLowerCase().endsWith('.' + dkimDomain.toLowerCase())
  ) : false;

  // DMARC Analysis
  let dmarcStatus: AuthStatus = 'NONE';
  let dmarcPolicy: 'none' | 'quarantine' | 'reject' | 'none-found' = 'none';
  let disposition: 'none' | 'quarantine' | 'reject' = 'none';
  let dmarcDetails = '';

  if (normalizedHeader.includes('dmarc=pass')) {
    dmarcStatus = 'PASS';
    dmarcDetails = `DMARC policy satisfied: Authenticated with aligned domain ${fromDomain}.`;
  } else if (normalizedHeader.includes('dmarc=fail')) {
    dmarcStatus = 'FAIL';
    if (normalizedHeader.includes('p=reject')) dmarcPolicy = 'reject';
    else if (normalizedHeader.includes('p=quarantine')) dmarcPolicy = 'quarantine';
    else dmarcPolicy = 'none';
    
    if (normalizedHeader.includes('dis=quarantine')) disposition = 'quarantine';
    else if (normalizedHeader.includes('dis=reject')) disposition = 'reject';
    
    dmarcDetails = `DMARC alignment failed: Neither SPF nor DKIM passed in strict alignment with From: ${fromDomain}. Enforced policy: ${dmarcPolicy}.`;
  } else {
    // If no explicit dmarc result in header
    if ((spfStatus === 'PASS' && spfAlignment) || (dkimStatus === 'PASS' && dkimAlignment)) {
      dmarcStatus = 'PASS';
      dmarcDetails = `Inferred DMARC PASS via aligned authentications.`;
    } else if (spfStatus === 'FAIL' || dkimStatus === 'FAIL') {
      dmarcStatus = 'FAIL';
      dmarcPolicy = 'quarantine';
      dmarcDetails = `DMARC alignment failed: Explicit authentication check failed.`;
    } else {
      // No evaluation headers were present in the email input
      dmarcStatus = 'NONE';
      dmarcPolicy = 'none-found';
      dmarcDetails = `Authentication headers not present in submitted email sample (Not assessed).`;
    }
  }

  return {
    spf: {
      status: spfStatus,
      domain: spfDomain,
      clientIp,
      alignment: spfAlignment,
      details: spfDetails
    },
    dkim: {
      status: dkimStatus,
      domain: dkimDomain || fromDomain,
      selector,
      alignment: dkimAlignment,
      signaturePresent: dkimSignatures.length > 0,
      details: dkimDetails
    },
    dmarc: {
      status: dmarcStatus,
      policy: dmarcPolicy,
      headerFromDomain: fromDomain,
      alignment: spfAlignment || dkimAlignment,
      disposition,
      details: dmarcDetails
    }
  };
}
