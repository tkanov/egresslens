export interface PortInfo {
  service: string
  description: string
}

const PORTS: Record<number, PortInfo> = {
  20: { service: "FTP", description: "FTP data" },
  21: { service: "FTP", description: "FTP control" },
  22: { service: "SSH", description: "Secure shell" },
  25: { service: "SMTP", description: "Mail transfer" },
  53: { service: "DNS", description: "Domain name service" },
  80: { service: "HTTP", description: "Web traffic" },
  110: { service: "POP3", description: "Mail retrieval" },
  143: { service: "IMAP", description: "Mail access" },
  443: { service: "HTTPS", description: "Encrypted web traffic" },
  465: { service: "SMTPS", description: "Encrypted SMTP" },
  587: { service: "SMTP", description: "Mail submission" },
  993: { service: "IMAPS", description: "Encrypted IMAP" },
  995: { service: "POP3S", description: "Encrypted POP3" },
  3306: { service: "MySQL", description: "MySQL database" },
  5432: { service: "PostgreSQL", description: "PostgreSQL database" },
  6379: { service: "Redis", description: "Redis database" },
}

export function getPortInfo(port: number): PortInfo | null {
  return PORTS[port] ?? null
}
