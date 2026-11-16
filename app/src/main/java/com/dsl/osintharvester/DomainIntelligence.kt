package com.dsl.osintharvester

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

internal data class DnsAnswer(
    val name: String,
    val type: Int,
    val ttl: Long,
    val data: String
)

internal data class DnsLookupResult(
    val status: Int,
    val authenticatedData: Boolean,
    val answers: List<DnsAnswer>
)

internal data class RdapEvent(
    val action: String,
    val date: String
)

internal data class RdapSummary(
    val name: String,
    val handle: String?,
    val registrar: String?,
    val status: List<String>,
    val events: List<RdapEvent>,
    val nameservers: List<String>
)

/**
 * Small, stateless parsers for public DNS-over-HTTPS and IANA RDAP data.
 * Network requests, limits, and cancellation remain owned by MainActivity.
 */
internal object DomainIntelligence {
    private val domainLabel = Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

    fun isDomainName(input: String): Boolean {
        val value = input.trim().trimEnd('.').lowercase()
        if (value.length !in 1..253 || value.contains(':')) return false
        if (value.matches(Regex("""\d{1,3}(?:\.\d{1,3}){3}"""))) return false
        val labels = value.split('.')
        return labels.size >= 2 && labels.all { it.length <= 63 && domainLabel.matches(it) }
    }

    /**
     * Returns the full host followed by parent-domain candidates, capped at four.
     * This handles common subdomain input without bundling or persisting a public suffix list.
     */
    fun registrationCandidates(input: String): List<String> {
        val domain = input.trim().trimEnd('.').lowercase()
        if (!isDomainName(domain)) return emptyList()
        val labels = domain.split('.')
        val lastStart = (labels.size - 2).coerceAtLeast(0)
        return (0..minOf(lastStart, 3)).map { index ->
            labels.drop(index).joinToString(".")
        }
    }

    fun parseDnsResponse(json: String): DnsLookupResult? {
        return try {
        val root = JsonParser.parseString(json).takeIf { it.isJsonObject }?.asJsonObject
            ?: return null
        val status = root.get("Status")?.asInt ?: return null
        val authenticated = root.get("AD")?.asBoolean ?: false
        val answers = root.getAsJsonArray("Answer")
            ?.mapNotNull { element ->
                if (!element.isJsonObject) return@mapNotNull null
                val answer = element.asJsonObject
                val name = answer.get("name")?.asString ?: return@mapNotNull null
                val type = answer.get("type")?.asInt ?: return@mapNotNull null
                val ttl = answer.get("TTL")?.asLong ?: 0L
                val data = answer.get("data")?.asString ?: return@mapNotNull null
                DnsAnswer(name, type, ttl, data)
            }
            ?.take(64)
            .orEmpty()
        DnsLookupResult(status, authenticated, answers)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Implements the domain-label suffix match used by RFC 9224.
     * Only HTTPS, standard-port RDAP base URLs from the IANA bootstrap file are accepted.
     */
    fun findRdapBaseUrl(bootstrapJson: String, inputDomain: String): String? {
        val domain = inputDomain.trim().trimEnd('.').lowercase()
        if (!isDomainName(domain)) return null

        val root = runCatching {
            JsonParser.parseString(bootstrapJson).asJsonObject
        }.getOrNull() ?: return null
        val services = root.getAsJsonArray("services") ?: return null
        val domainLabels = domain.split('.')
        var bestMatchLength = -1
        var bestUrl: String? = null

        for (serviceElement in services) {
            if (!serviceElement.isJsonArray) continue
            val service = serviceElement.asJsonArray
            if (service.size() < 2 || !service[0].isJsonArray || !service[1].isJsonArray) continue

            val entries = service[0].asJsonArray
            val urls = service[1].asJsonArray
            for (entry in entries) {
                if (!entry.isJsonPrimitive) continue
                val suffix = entry.asString.trim().trim('.').lowercase()
                if (suffix.isBlank()) continue
                val suffixLabels = suffix.split('.')
                if (suffixLabels.size > domainLabels.size) continue
                if (domainLabels.takeLast(suffixLabels.size) != suffixLabels) continue
                if (suffixLabels.size < bestMatchLength) continue

                val candidate = urls.firstNotNullOfOrNull { element ->
                    if (!element.isJsonPrimitive) return@firstNotNullOfOrNull null
                    val raw = element.asString
                    val url = raw.toHttpUrlOrNull() ?: return@firstNotNullOfOrNull null
                    if (url.scheme != "https" || url.port != 443 ||
                        url.username.isNotEmpty() || url.password.isNotEmpty() ||
                        url.query != null || url.fragment != null
                    ) null else url.toString().let { if (it.endsWith('/')) it else "$it/" }
                } ?: continue

                if (suffixLabels.size > bestMatchLength || bestUrl == null) {
                    bestMatchLength = suffixLabels.size
                    bestUrl = candidate
                }
            }
        }
        return bestUrl
    }

    fun parseRdapSummary(json: String): RdapSummary? {
        return try {
        val root = JsonParser.parseString(json).takeIf { it.isJsonObject }?.asJsonObject
            ?: return null

        val name = root.stringValue("ldhName") ?: root.stringValue("unicodeName").orEmpty()
        val handle = root.stringValue("handle")
        val statuses = root.getAsJsonArray("status")
            ?.mapNotNull { if (it.isJsonPrimitive) it.asString else null }
            ?.take(20)
            .orEmpty()

        val events = root.getAsJsonArray("events")
            ?.mapNotNull { event ->
                if (!event.isJsonObject) return@mapNotNull null
                val action = event.asJsonObject.stringValue("eventAction") ?: return@mapNotNull null
                val date = event.asJsonObject.stringValue("eventDate") ?: return@mapNotNull null
                RdapEvent(action.take(80), date.take(80))
            }
            ?.take(20)
            .orEmpty()

        val nameservers = root.getAsJsonArray("nameservers")
            ?.mapNotNull { server ->
                if (!server.isJsonObject) return@mapNotNull null
                server.asJsonObject.stringValue("ldhName")
                    ?: server.asJsonObject.stringValue("unicodeName")
            }
            ?.distinct()
            ?.take(20)
            .orEmpty()

        val registrar = root.getAsJsonArray("entities")
            ?.mapNotNull { entity -> if (entity.isJsonObject) entity.asJsonObject else null }
            ?.firstNotNullOfOrNull { entity ->
                val roles = entity.getAsJsonArray("roles")
                    ?.mapNotNull { if (it.isJsonPrimitive) it.asString else null }
                    .orEmpty()
                if (roles.none { it.equals("registrar", ignoreCase = true) }) return@firstNotNullOfOrNull null
                entity.vcardName() ?: entity.stringValue("handle")
            }

        if (name.isBlank() && handle == null && registrar == null &&
            statuses.isEmpty() && events.isEmpty() && nameservers.isEmpty()
        ) return null

        RdapSummary(name, handle, registrar, statuses, events, nameservers)
        } catch (_: Exception) {
            null
        }
    }

    fun recordTypeName(type: Int): String = when (type) {
        1 -> "A"
        2 -> "NS"
        5 -> "CNAME"
        6 -> "SOA"
        15 -> "MX"
        16 -> "TXT"
        28 -> "AAAA"
        43 -> "DS"
        48 -> "DNSKEY"
        257 -> "CAA"
        else -> "TYPE$type"
    }

    private fun JsonObject.stringValue(name: String): String? {
        val value = get(name) ?: return null
        return if (value.isJsonPrimitive && !value.asJsonPrimitive.isBoolean &&
            !value.asJsonPrimitive.isNumber
        ) value.asString else null
    }

    private fun JsonObject.vcardName(): String? {
        val vcard = getAsJsonArray("vcardArray") ?: return null
        if (vcard.size() < 2 || !vcard[1].isJsonArray) return null
        val fields: JsonArray = vcard[1].asJsonArray
        for (fieldElement in fields) {
            if (!fieldElement.isJsonArray) continue
            val field = fieldElement.asJsonArray
            if (field.size() < 4 || !field[0].isJsonPrimitive) continue
            val property = field[0].asString
            if (!property.equals("fn", true) && !property.equals("org", true)) continue
            val value: JsonElement = field[3]
            val text = when {
                value.isJsonPrimitive -> value.asString
                value.isJsonArray -> value.asJsonArray.joinToString(" ") {
                    if (it.isJsonPrimitive) it.asString else ""
                }
                else -> ""
            }.trim()
            if (text.isNotBlank()) return text.take(180)
        }
        return null
    }
}
