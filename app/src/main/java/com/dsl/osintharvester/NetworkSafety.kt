package com.dsl.osintharvester

import okhttp3.Dns
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Network restrictions for user-entered targets.
 *
 * The app deliberately supports HTTPS on the standard port only and refuses
 * non-public address space. OkHttp receives the checked IP addresses directly
 * from this DNS implementation, preventing a second unchecked DNS lookup.
 */
internal object NetworkSafety {
    fun parseTarget(input: String): HttpUrl? {
        val trimmed = input.trim()
        if (trimmed.isEmpty() || trimmed.any(Char::isWhitespace)) return null

        val candidate = if (trimmed.contains("://")) trimmed else "https://$trimmed"
        val url = candidate.toHttpUrlOrNull() ?: return null

        if (url.scheme != "https" || url.port != 443) return null
        if (url.username.isNotEmpty() || url.password.isNotEmpty()) return null
        if (url.host.equals("localhost", ignoreCase = true) ||
            url.host.endsWith(".localhost", ignoreCase = true) ||
            url.host.endsWith(".local", ignoreCase = true) ||
            url.host.endsWith(".internal", ignoreCase = true) ||
            url.host.endsWith(".lan", ignoreCase = true) ||
            url.host.endsWith(".home.arpa", ignoreCase = true) ||
            url.host.endsWith(".test", ignoreCase = true) ||
            url.host.endsWith(".example", ignoreCase = true) ||
            url.host.endsWith(".invalid", ignoreCase = true) ||
            url.host.endsWith(".onion", ignoreCase = true) ||
            url.host.endsWith(".arpa", ignoreCase = true)
        ) return null

        return url
    }

    /** Remove credentials from URLs sent to third-party intelligence providers. */
    fun withoutSensitiveComponents(url: HttpUrl): HttpUrl =
        url.newBuilder().query(null).fragment(null).username("").password("").build()

    internal fun isPublicInternetAddress(address: InetAddress): Boolean {
        if (address.isAnyLocalAddress ||
            address.isLoopbackAddress ||
            address.isLinkLocalAddress ||
            address.isSiteLocalAddress ||
            address.isMulticastAddress
        ) return false

        val bytes = address.address
        if (bytes.size == 4) return !isBlockedIpv4(bytes)

        if (address is Inet6Address && bytes.size == 16) {
            // IPv4-mapped IPv6 addresses must pass the IPv4 policy as well.
            val mappedPrefix = ByteArray(10) + byteArrayOf(0xff.toByte(), 0xff.toByte())
            if (bytes.copyOfRange(0, 12).contentEquals(mappedPrefix)) {
                return !isBlockedIpv4(bytes.copyOfRange(12, 16))
            }

            // Only globally allocated unicast space (2000::/3) is allowed.
            // This fails closed for special-use, transition, and reserved IPv6 space.
            val first = bytes[0].toInt() and 0xff
            if (first !in 0x20..0x3f) return false

            // Reject IPv4-compatible IPv6 addresses and special-use IPv6 ranges.
            if (hasPrefix(bytes, ByteArray(12), 96)) return false
            if (hasPrefix(bytes, byteArrayOf(0xfc.toByte()), 7)) return false // ULA fc00::/7
            if (hasPrefix(bytes, byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte()), 32)) return false // docs
            if (hasPrefix(bytes, byteArrayOf(0x3f, 0xff.toByte(), 0x00), 20)) return false // IPv6 documentation
            if (hasPrefix(bytes, byteArrayOf(0x20, 0x01, 0x00, 0x00), 32)) return false // Teredo
            if (hasPrefix(bytes, byteArrayOf(0x20, 0x02), 16)) return false // 6to4
            if (hasPrefix(
                    bytes,
                    byteArrayOf(0x00, 0x64, 0xff.toByte(), 0x9b.toByte()) + ByteArray(8),
                    96
                )) return false // NAT64
            if (hasPrefix(bytes, byteArrayOf(0x00, 0x64, 0xff.toByte(), 0x9b.toByte(), 0x00, 0x01), 48)) return false
            return true
        }

        return false
    }

    private fun isBlockedIpv4(bytes: ByteArray): Boolean {
        val a = bytes[0].toInt() and 0xff
        val b = bytes[1].toInt() and 0xff
        val c = bytes[2].toInt() and 0xff

        return when {
            a == 0 -> true                         // "this" network / unspecified
            a == 10 -> true                        // RFC1918
            a == 100 && b in 64..127 -> true       // carrier-grade NAT
            a == 127 -> true                       // loopback
            a == 169 && b == 254 -> true           // link-local / cloud metadata
            a == 172 && b in 16..31 -> true        // RFC1918
            a == 192 && b == 0 && c == 0 -> true   // IETF special purpose
            a == 192 && b == 0 && c == 2 -> true   // TEST-NET-1
            a == 192 && b == 88 && c == 99 -> true // deprecated 6to4 relay
            a == 192 && b == 168 -> true           // RFC1918
            a == 198 && b in 18..19 -> true        // benchmarking
            a == 198 && b == 51 && c == 100 -> true // TEST-NET-2
            a == 203 && b == 0 && c == 113 -> true // TEST-NET-3
            a >= 224 -> true                       // multicast / reserved / broadcast
            else -> false
        }
    }

    private fun hasPrefix(address: ByteArray, prefix: ByteArray, prefixBits: Int): Boolean {
        if (prefixBits < 0 || prefixBits > address.size * 8 ||
            prefix.size < (prefixBits + 7) / 8
        ) return false

        val fullBytes = prefixBits / 8
        val remainingBits = prefixBits % 8

        for (index in 0 until fullBytes) {
            if (address[index] != prefix[index]) return false
        }

        if (remainingBits == 0) return true
        val mask = (0xff shl (8 - remainingBits)) and 0xff
        return ((address[fullBytes].toInt() and 0xff) and mask) ==
            ((prefix[fullBytes].toInt() and 0xff) and mask)
    }
}

/**
 * Resolves names once per request and rejects the entire answer if any address
 * is non-public. OkHttp connects to the returned checked addresses rather than
 * resolving the hostname again after validation.
 */
internal class PublicInternetDns(
    private val delegate: Dns = Dns.SYSTEM
) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        if (hostname.isBlank() ||
            hostname.equals("localhost", ignoreCase = true) ||
            hostname.endsWith(".localhost", ignoreCase = true) ||
            hostname.endsWith(".local", ignoreCase = true) ||
            hostname.endsWith(".internal", ignoreCase = true) ||
            hostname.endsWith(".lan", ignoreCase = true) ||
            hostname.endsWith(".home.arpa", ignoreCase = true) ||
            hostname.endsWith(".test", ignoreCase = true) ||
            hostname.endsWith(".example", ignoreCase = true) ||
            hostname.endsWith(".invalid", ignoreCase = true) ||
            hostname.endsWith(".onion", ignoreCase = true) ||
            hostname.endsWith(".arpa", ignoreCase = true)
        ) {
            throw UnknownHostException("Only public Internet hosts are allowed")
        }

        val addresses = delegate.lookup(hostname)
        if (addresses.isEmpty() || addresses.any { !NetworkSafety.isPublicInternetAddress(it) }) {
            throw UnknownHostException("Target resolves to a non-public or reserved address")
        }
        return addresses
    }
}
