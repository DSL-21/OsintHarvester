package com.dsl.osintharvester

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainIntelligenceTest {
    @Test
    fun parsesDnsAnswersAndDnssecFlag() {
        val result = DomainIntelligence.parseDnsResponse(
            """{"Status":0,"AD":true,"Answer":[{"name":"example.com.","type":1,"TTL":300,"data":"93.184.216.34"},{"name":"example.com.","type":16,"TTL":60,"data":"\"v=spf1 -all\""}]}"""
        )

        assertNotNull(result)
        assertEquals(0, result!!.status)
        assertTrue(result.authenticatedData)
        assertEquals(2, result.answers.size)
        assertEquals("93.184.216.34", result.answers[0].data)
        assertEquals("TXT", DomainIntelligence.recordTypeName(result.answers[1].type))
    }

    @Test
    fun returnsDnsErrorStatusWithoutInventingAnswers() {
        val result = DomainIntelligence.parseDnsResponse("""{"Status":3,"Answer":[]}""")
        assertNotNull(result)
        assertEquals(3, result!!.status)
        assertTrue(result.answers.isEmpty())
    }

    @Test
    fun rejectsMalformedDnsPayload() {
        assertNull(DomainIntelligence.parseDnsResponse("not-json"))
        assertNull(DomainIntelligence.parseDnsResponse("""{"Answer":[]}"""))
    }

    @Test
    fun resolvesTheLongestIanaRdapSuffixMatch() {
        val bootstrap = """
            {
              "services": [
                [["uk"], ["https://rdap.uk.example/"]],
                [["co.uk"], ["https://rdap.co.uk.example/"]],
                [["com"], ["https://rdap.com.example/"]]
              ]
            }
        """.trimIndent()

        assertEquals(
            "https://rdap.co.uk.example/",
            DomainIntelligence.findRdapBaseUrl(bootstrap, "www.example.co.uk")
        )
        assertEquals(
            "https://rdap.com.example/",
            DomainIntelligence.findRdapBaseUrl(bootstrap, "example.com")
        )
    }

    @Test
    fun rejectsInsecureOrMalformedRdapBootstrapEntries() {
        val bootstrap = """
            {"services":[
              [["com"],["http://rdap.example/"]],
              [["net"],["https://user:pass@rdap.example/"]],
              [["org"],["https://rdap.example:8443/"]]
            ]}
        """.trimIndent()

        assertNull(DomainIntelligence.findRdapBaseUrl(bootstrap, "example.com"))
        assertNull(DomainIntelligence.findRdapBaseUrl(bootstrap, "example.net"))
        assertNull(DomainIntelligence.findRdapBaseUrl(bootstrap, "example.org"))
    }

    @Test
    fun buildsBoundedParentDomainCandidates() {
        assertEquals(
            listOf("mail.dev.example.co.uk", "dev.example.co.uk", "example.co.uk", "co.uk"),
            DomainIntelligence.registrationCandidates("mail.dev.example.co.uk")
        )
        assertTrue(DomainIntelligence.registrationCandidates("127.0.0.1").isEmpty())
        assertFalse(DomainIntelligence.isDomainName("localhost"))
        assertTrue(DomainIntelligence.isDomainName("example.com"))
    }

    @Test
    fun extractsRdapRegistrarEventsAndNameservers() {
        val json = """
            {
              "ldhName":"example.com",
              "handle":"D123",
              "status":["active"],
              "events":[
                {"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"},
                {"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}
              ],
              "entities":[{
                "handle":"REGISTRAR-1",
                "roles":["registrar"],
                "vcardArray":["vcard",[
                  ["version",{},"text","4.0"],
                  ["fn",{},"text","Example Registrar"]
                ]]
              }],
              "nameservers":[{"ldhName":"ns1.example.com"},{"ldhName":"ns2.example.com"}]
            }
        """.trimIndent()

        val result = DomainIntelligence.parseRdapSummary(json)
        assertNotNull(result)
        assertEquals("example.com", result!!.name)
        assertEquals("D123", result.handle)
        assertEquals("Example Registrar", result.registrar)
        assertEquals(2, result.events.size)
        assertEquals(2, result.nameservers.size)
    }
}
