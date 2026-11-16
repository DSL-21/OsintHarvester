package com.dsl.osintharvester

import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class NetworkSafetyTest {
    @Test
    fun acceptsOnlyHttpsOnTheDefaultPort() {
        assertNotNull(NetworkSafety.parseTarget("example.com"))
        assertNotNull(NetworkSafety.parseTarget("https://example.com/path"))
        assertNull(NetworkSafety.parseTarget("http://example.com"))
        assertNull(NetworkSafety.parseTarget("ftp://example.com"))
        assertNull(NetworkSafety.parseTarget("https://example.com:8443"))
        assertNull(NetworkSafety.parseTarget("https://user:pass@example.com"))
    }

    @Test
    fun rejectsLocalAndPrivateTargetNames() {
        assertNull(NetworkSafety.parseTarget("localhost"))
        assertNull(NetworkSafety.parseTarget("router.local"))
        assertNull(NetworkSafety.parseTarget("host.internal"))
        assertNull(NetworkSafety.parseTarget("nas.lan"))
    }

    @Test
    fun blocksPrivateAndSpecialUseIpv4Ranges() {
        val blocked = listOf(
            "0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1",
            "169.254.169.254", "172.16.0.1", "192.168.1.1",
            "192.0.2.1", "198.18.0.1", "203.0.113.1", "224.0.0.1"
        )
        blocked.forEach {
            assertFalse("$it must be blocked", NetworkSafety.isPublicInternetAddress(InetAddress.getByName(it)))
        }
    }

    @Test
    fun acceptsRepresentativePublicIpv4() {
        assertTrue(NetworkSafety.isPublicInternetAddress(InetAddress.getByName("1.1.1.1")))
        assertTrue(NetworkSafety.isPublicInternetAddress(InetAddress.getByName("8.8.8.8")))
    }

    @Test
    fun blocksLocalAndSpecialUseIpv6Ranges() {
        val blocked = listOf(
            "::", "::1", "fe80::1", "fc00::1", "fd12:3456::1",
            "2001:db8::1", "2001:0000::1", "2002::1", "ff02::1"
        )
        blocked.forEach {
            assertFalse("$it must be blocked", NetworkSafety.isPublicInternetAddress(InetAddress.getByName(it)))
        }
    }

    @Test
    fun acceptsRepresentativeGlobalIpv6() {
        assertTrue(NetworkSafety.isPublicInternetAddress(InetAddress.getByName("2001:4860:4860::8888")))
        assertTrue(NetworkSafety.isPublicInternetAddress(InetAddress.getByName("2606:4700:4700::1111")))
    }

    @Test
    fun rejectsReservedIpv6SpaceOutsideGlobalUnicast() {
        assertFalse(NetworkSafety.isPublicInternetAddress(InetAddress.getByName("100::1")))
        assertFalse(NetworkSafety.isPublicInternetAddress(InetAddress.getByName("3fff::1")))
    }

    @Test
    fun redactsCommonSecretAssignmentsAndBearerTokens() {
        val bearer = "Authorization: Bearer abc.def.ghi"
        val redactedBearer = SensitiveTextRedactor.redact(bearer)
        assertFalse(redactedBearer.contains("abc.def.ghi"))
        assertTrue(redactedBearer.contains("[REDACTED]"))

        val json = """{"api_key":"top-secret-value","password":"my-password"}"""
        val redactedJson = SensitiveTextRedactor.redact(json)
        assertFalse(redactedJson.contains("top-secret-value"))
        assertFalse(redactedJson.contains("my-password"))
        assertTrue(redactedJson.contains("[REDACTED]"))
    }

    @Test
    fun stripsQueryAndFragmentBeforeThirdPartyLookup() {
        val input = "https://example.com/profile?token=private#section".toHttpUrl()
        val safe = NetworkSafety.withoutSensitiveComponents(input)
        assertEquals("https://example.com/profile", safe.toString())
    }
}
