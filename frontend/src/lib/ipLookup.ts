type LookupProvider = "whois" | "ip-api"

export function openIpLookup(ip: string, provider: LookupProvider = "whois") {
  const encodedIp = encodeURIComponent(ip)
  const url =
    provider === "ip-api"
      ? `https://ip-api.com/#${encodedIp}`
      : `https://whois.domaintools.com/${encodedIp}`

  window.open(url, "_blank", "noopener,noreferrer")
}
