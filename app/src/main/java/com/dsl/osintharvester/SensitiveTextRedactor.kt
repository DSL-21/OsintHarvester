package com.dsl.osintharvester

/**
 * Best-effort masking for common secret assignments, bearer credentials,
 * and recognizable API-key formats before extracted text is shown in the UI.
 *
 * This is a display safeguard, not a complete secret scanner.
 */
internal object SensitiveTextRedactor {
    private val bearerPattern =
        Regex("""(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+""")

    private val assignmentPattern = Regex(
        """(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|token|client[_-]?secret|private[_-]?key|secret|password|passwd|authorization|cookie|session|signature|sig)\b["']?\s*[:=]\s*["']?([^,\s&;"']+)"""
    )

    private val recognizableKeyPatterns = listOf(
        Regex("""AIza[0-9A-Za-z_-]{35}"""),
        Regex("""sk-[A-Za-z0-9]{32,128}"""),
        Regex("""pk_live_[A-Za-z0-9]{24,}""")
    )

    fun redact(value: String): String {
        var safe = value
            .replace(bearerPattern, "Bearer [REDACTED]")
            .replace(assignmentPattern) { match ->
                "${match.groupValues[1]}=[REDACTED]"
            }

        recognizableKeyPatterns.forEach { pattern ->
            safe = safe.replace(pattern, "[REDACTED API KEY]")
        }
        return safe
    }
}
