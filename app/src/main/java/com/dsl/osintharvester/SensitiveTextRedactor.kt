package com.dsl.osintharvester

/**
 * Best-effort masking for common secret assignments and bearer credentials
 * before any extracted text is shown in the UI.
 */
internal object SensitiveTextRedactor {
    private val bearerPattern =
        Regex("""(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+""")

    private val assignmentPattern = Regex(
        """(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret|password|passwd|authorization)\b["']?\s*[:=]\s*["']?([^,\s&;"']+)"""
    )

    fun redact(value: String): String =
        value
            .replace(bearerPattern, "Bearer [REDACTED]")
            .replace(assignmentPattern) { match ->
                "${match.groupValues[1]}=[REDACTED]"
            }
}
