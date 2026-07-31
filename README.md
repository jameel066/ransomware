# ransomware
 Scans ALL user files under 5 MB (excludes .lnk and itself)     2. Stages copies to temp folder     3. AES-256 encrypts all staged files into one payload, Base64, split into parts     4. Emails each part via Gmail SMTP (TLS 1.2+)     5. ONLY IF all emails succeed: deletes originals + registry MRU +        recreates files with ASCII zero/one pattern
