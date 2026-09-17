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
  receivedHeaders: string[];
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
  dkimSignatures: string[];
  bodyText: string;
  bodyHtml: string;
  attachments: ParsedMimePart[];
  rawHeaders: string;
}

export function parseRawEmail(raw: string): ParsedEmailRaw {
  // Normalize line endings
  const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  
  // Separate headers and body
  const headerBodySplit = normalized.indexOf('\n\n');
  let headerBlock = '';
  let bodyBlock = '';
  
  if (headerBodySplit !== -1) {
    headerBlock = normalized.substring(0, headerBodySplit);
    bodyBlock = normalized.substring(headerBodySplit + 2);
  } else {
    headerBlock = normalized;
    bodyBlock = '';
  }

  // Unfold headers (RFC 5322 line continuation: lines starting with space or tab)
  const unfoldedLines: string[] = [];
  const rawLines = headerBlock.split('\n');
  for (const line of rawLines) {
    if ((line.startsWith(' ') || line.startsWith('\t')) && unfoldedLines.length > 0) {
      unfoldedLines[unfoldedLines.length - 1] += ' ' + line.trim();
    } else {
      unfoldedLines.push(line);
    }
  }

  const headers: Record<string, string> = {};
  const receivedHeaders: string[] = [];
  const dkimSignatures: string[] = [];

  for (const line of unfoldedLines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      const key = line.substring(0, colonIdx).trim().toLowerCase();
      const value = line.substring(colonIdx + 1).trim();
      
      if (key === 'received') {
        receivedHeaders.push(value);
      } else if (key === 'dkim-signature') {
        dkimSignatures.push(value);
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
  const authResultsHeader = [
    headers['authentication-results'],
    headers['arc-authentication-results'],
    headers['received-spf'] ? `spf=${headers['received-spf']}` : '',
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
    receivedHeaders,
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
    dkimSignatures,
    bodyText: bodyText.trim(),
    bodyHtml: bodyHtml.trim(),
    attachments,
    rawHeaders: headerBlock
  };
}
