/**
 * MailTrace AI - RFC 822/5322 Header and MIME Parser
 */

export interface ParsedMimePart {
  contentType: string;
  filename?: string;
  contentDisposition?: string;
  encoding?: string;
  data: string;
  sizeBytes: number;
}

export interface ParsedEmailRaw {
  headers: Record<string, string>;
  allHeaders: Record<string, string[]>;
  receivedHeaders: string[];
  authResultsHeaders: string[];
  receivedSpfHeaders: string[];
  dkimSignatures: string[];
  arcSeals: string[];
  arcAuthResults: string[];
  xOriginatingIp?: string;
  subject: string;
  from: string;
  fromName: string;
  fromDomain: string;
  to: string[];
  cc: string[];
  replyTo: string;
  returnPath: string;
  messageId: string;
  date: string;
  userAgent?: string;
  xMailer?: string;
  authResultsHeader?: string;
  bodyText: string;
  bodyHtml: string;
  attachments: ParsedMimePart[];
  rawHeaders: string;
}

export function parseRawEmail(raw: string): ParsedEmailRaw {
  if (!raw || typeof raw !== 'string') {
    return {
      headers: {},
      allHeaders: {},
      receivedHeaders: [],
      authResultsHeaders: [],
      receivedSpfHeaders: [],
      dkimSignatures: [],
      arcSeals: [],
      arcAuthResults: [],
      subject: '(No Subject)',
      from: '',
      fromName: '',
      fromDomain: '',
      to: [],
      cc: [],
      replyTo: '',
      returnPath: '',
      messageId: '',
      date: new Date().toUTCString(),
      authResultsHeader: '',
      bodyText: '',
      bodyHtml: '',
      attachments: [],
      rawHeaders: ''
    };
  }

  // Normalize line endings
  const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  
  // Separate headers and body by standard double newline
  const headerBodySplit = normalized.indexOf('\n\n');
  let headerBlock = '';
  let bodyBlock = '';
  
  if (headerBodySplit !== -1) {
    headerBlock = normalized.substring(0, headerBodySplit);
    bodyBlock = normalized.substring(headerBodySplit + 2);
  } else {
    // If no empty line found, check if first lines are headers
    const lines = normalized.split('\n');
    let lastHeaderIdx = -1;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^[A-Za-z0-9_-]+:/.test(line) || ((line.startsWith(' ') || line.startsWith('\t')) && lastHeaderIdx === i - 1)) {
        lastHeaderIdx = i;
      } else if (lastHeaderIdx !== -1) {
        break;
      }
    }

    if (lastHeaderIdx !== -1) {
      headerBlock = lines.slice(0, lastHeaderIdx + 1).join('\n');
      bodyBlock = lines.slice(lastHeaderIdx + 1).join('\n');
    } else {
      headerBlock = '';
      bodyBlock = normalized;
    }
  }

  // Unfold headers (RFC 5322 line continuation: lines starting with space or tab belong to the previous header)
  const unfoldedLines: string[] = [];
  const rawLines = headerBlock.split('\n');
  for (const line of rawLines) {
    if ((line.startsWith(' ') || line.startsWith('\t')) && unfoldedLines.length > 0) {
      unfoldedLines[unfoldedLines.length - 1] += ' ' + line.trim();
    } else if (line.trim().length > 0) {
      unfoldedLines.push(line);
    }
  }

  const headers: Record<string, string> = {};
  const allHeaders: Record<string, string[]> = {};
  const receivedHeaders: string[] = [];
  const authResultsHeaders: string[] = [];
  const receivedSpfHeaders: string[] = [];
  const dkimSignatures: string[] = [];
  const arcSeals: string[] = [];
  const arcAuthResults: string[] = [];
  let xOriginatingIp: string | undefined = undefined;

  for (const line of unfoldedLines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      const key = line.substring(0, colonIdx).trim().toLowerCase();
      const value = line.substring(colonIdx + 1).trim();
      
      // Defend against prototype pollution attacks
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }

      if (!allHeaders[key]) {
        allHeaders[key] = [];
      }
      allHeaders[key].push(value);

      if (key === 'received') {
        receivedHeaders.push(value);
      } else if (key === 'authentication-results') {
        authResultsHeaders.push(value);
      } else if (key === 'received-spf') {
        receivedSpfHeaders.push(value);
      } else if (key === 'dkim-signature') {
        dkimSignatures.push(value);
      } else if (key === 'arc-seal') {
        arcSeals.push(value);
      } else if (key === 'arc-authentication-results') {
        arcAuthResults.push(value);
      } else if (key === 'x-originating-ip' || key === 'x-sender-ip' || key === 'x-client-ip') {
        if (!xOriginatingIp) {
          xOriginatingIp = value.replace(/[\[\]]/g, '').trim();
        }
      }
      
      if (!headers[key]) {
        headers[key] = value;
      }
    }
  }

  // Parse From
  const rawFrom = headers['from'] || '';
  let fromName = '';
  let fromEmail = '';
  const fromMatch = rawFrom.match(/^(?:"?([^"]*)"?\s)?<?([^>]+)>?$/);
  if (fromMatch) {
    fromName = (fromMatch[1] || '').trim();
    fromEmail = (fromMatch[2] || '').trim();
  } else {
    fromEmail = rawFrom.trim();
  }
  
  if (!fromEmail && rawFrom.includes('@')) {
    const emailMatch = rawFrom.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
    if (emailMatch) fromEmail = emailMatch[0];
  }
  
  const fromDomain = fromEmail.includes('@') ? fromEmail.split('@')[1].toLowerCase() : '';

  // Parse To
  const rawTo = headers['to'] || '';
  const toList = rawTo.split(',').map(s => s.trim()).filter(Boolean);

  // Parse Cc
  const rawCc = headers['cc'] || '';
  const ccList = rawCc.split(',').map(s => s.trim()).filter(Boolean);

  // Parse Reply-To
  const replyTo = headers['reply-to'] || '';
  const returnPath = headers['return-path'] || '';
  const messageId = headers['message-id'] || '';
  const date = headers['date'] || new Date().toUTCString();
  const userAgent = headers['user-agent'] || '';
  const xMailer = headers['x-mailer'] || '';
  
  // Combine all authentication headers into composite authentication results string
  const authResultsHeader = [
    ...authResultsHeaders,
    ...arcAuthResults,
    ...receivedSpfHeaders.map(s => (s.toLowerCase().startsWith('spf=') ? s : `spf=${s}`)),
    headers['dkim-status'] ? `dkim=${headers['dkim-status']}` : ''
  ].filter(Boolean).join('; ');

  // Extract body and attachments
  const attachments: ParsedMimePart[] = [];
  let bodyText = '';
  let bodyHtml = '';

  const contentType = headers['content-type'] || '';
  const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;\s]+))/i);

  if (boundaryMatch && (boundaryMatch[1] || boundaryMatch[2])) {
    const boundary = boundaryMatch[1] || boundaryMatch[2];
    const parts = bodyBlock.split(new RegExp(`--${boundary}(?:--)?`));
    
    for (const part of parts) {
      const trimmedPart = part.trim();
      if (!trimmedPart || trimmedPart === '--') continue;
      
      const partSplit = trimmedPart.indexOf('\n\n');
      if (partSplit !== -1) {
        const partHeaders = trimmedPart.substring(0, partSplit);
        const partBody = trimmedPart.substring(partSplit + 2);
        
        const partContentType = (partHeaders.match(/content-type:\s*([^;\n]+)/i)?.[1] || 'text/plain').toLowerCase();
        const filenameMatch = partHeaders.match(/filename=(?:"([^"]+)"|([^\s;]+))/i) || 
                              partHeaders.match(/name=(?:"([^"]+)"|([^\s;]+))/i);
        const filename = filenameMatch ? (filenameMatch[1] || filenameMatch[2]) : undefined;
        const isAttachment = partHeaders.toLowerCase().includes('content-disposition:') || !!filename;
        
        if (filename || (isAttachment && !partContentType.includes('text/html') && !partContentType.includes('text/plain'))) {
          attachments.push({
            contentType: partContentType,
            filename: filename || 'attachment.bin',
            contentDisposition: 'attachment',
            data: partBody.trim(),
            sizeBytes: Math.round(partBody.length * 0.75) // estimate base64
          });
        } else if (partContentType.includes('text/html')) {
          bodyHtml += '\n' + partBody;
        } else if (partContentType.includes('text/plain')) {
          bodyText += '\n' + partBody;
        }
      }
    }
  } else {
    // Single part
    if (contentType.includes('text/html') || bodyBlock.includes('<html') || bodyBlock.includes('<body')) {
      bodyHtml = bodyBlock;
      // Strip tags for text preview
      bodyText = bodyBlock.replace(/<[^>]*>?/gm, ' ').replace(/\s+/g, ' ').trim();
    } else {
      bodyText = bodyBlock;
    }
  }

  return {
    headers,
    allHeaders,
    receivedHeaders,
    authResultsHeaders,
    receivedSpfHeaders,
    dkimSignatures,
    arcSeals,
    arcAuthResults,
    xOriginatingIp,
    subject: headers['subject'] || '(No Subject)',
    from: rawFrom,
    fromName: fromName || fromEmail,
    fromDomain,
    to: toList,
    cc: ccList,
    replyTo,
    returnPath,
    messageId,
    date,
    userAgent,
    xMailer,
    authResultsHeader,
    bodyText: bodyText.trim(),
    bodyHtml: bodyHtml.trim(),
    attachments,
    rawHeaders: headerBlock
  };
}
