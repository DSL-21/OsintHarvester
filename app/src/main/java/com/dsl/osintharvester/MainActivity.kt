package com.dsl.osintharvester

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.SeekBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import org.jsoup.Jsoup
import java.security.cert.X509Certificate
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.util.concurrent.ConcurrentHashMap
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.ResponseBody
import java.util.regex.Pattern

class MainActivity : AppCompatActivity() {

    /* UI komponenty */
    private lateinit var urlInput: EditText
    private lateinit var scanButton: Button
    private lateinit var cancelButton: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var statusText: TextView
    private lateinit var resultsContainer: LinearLayout

    /* Základní checkboxy */
    private lateinit var emailsCk: CheckBox
    private lateinit var phonesCk: CheckBox
    private lateinit var socialCk: CheckBox
    private lateinit var metaCk: CheckBox
    private lateinit var commentsCk: CheckBox
    private lateinit var headersCk: CheckBox

    /* Pokročilé OSINT checkboxy */
    private lateinit var subdomainsCk: CheckBox
    private lateinit var deepCrawlCk: CheckBox
    private lateinit var waybackCk: CheckBox
    private lateinit var reverseIpCk: CheckBox
    private lateinit var dnsRecordsCk: CheckBox
    private lateinit var rdapCk: CheckBox
    private lateinit var fileDetectCk: CheckBox

    /* Bezpečnostní checkboxy */
    private lateinit var apiKeysCk: CheckBox
    private lateinit var errorCk: CheckBox
    private lateinit var sslCk: CheckBox
    private lateinit var directoriesCk: CheckBox
    private lateinit var robotsTxtCk: CheckBox

    /* UI pro hloubku skenování */
    private lateinit var depthSeekBar: SeekBar
    private lateinit var depthLabel: TextView

    /* Síť a data */
    private val client = OkHttpClient.Builder()
        // Do not let a system proxy bypass DNS validation for the requested target.
        .proxy(java.net.Proxy.NO_PROXY)
        .dns(PublicInternetDns())
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(12, TimeUnit.SECONDS)
        .writeTimeout(8, TimeUnit.SECONDS)
        .callTimeout(20, TimeUnit.SECONDS)
        .followRedirects(false)
        .followSslRedirects(false)
        .retryOnConnectionFailure(false)
        .build()
    private val gson = Gson()
    private val activityScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var scanJob: Job? = null
    private val activeCalls = ConcurrentHashMap.newKeySet<Call>()
    private var activeOptions = ScanOptions()
    private var visibleResultCount = 0

    /* Crawling nastavení */
    private var MAX_DEPTH = 1

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        applySystemBarInsets()
        initViews()

        scanButton.setOnClickListener {
            val entered = urlInput.text.toString().trim()
            val target = NetworkSafety.parseTarget(entered)
            if (target == null) {
                statusText.text = getString(R.string.target_invalid_input)
                return@setOnClickListener
            }
            startCompleteScan(target.toString())
        }

        cancelButton.setOnClickListener {
            scanJob?.cancel()
            cancelActiveCalls()
        }
    }

    override fun onDestroy() {
        scanJob?.cancel()
        cancelActiveCalls()
        activityScope.cancel()
        super.onDestroy()
    }

    /**
     * Keeps the dashboard clear of status/navigation bars and camera cutouts
     * on edge-to-edge Android versions.
     */
    private fun applySystemBarInsets() {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = Color.TRANSPARENT
        window.navigationBarColor = Color.TRANSPARENT
        WindowInsetsControllerCompat(window, window.decorView).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = false
        }

        val root = findViewById<View>(R.id.root_container)
        val left = root.paddingLeft
        val top = root.paddingTop
        val right = root.paddingRight
        val bottom = root.paddingBottom

        ViewCompat.setOnApplyWindowInsetsListener(root) { view, windowInsets ->
            val safeInsets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            view.setPadding(
                left + safeInsets.left,
                top + safeInsets.top,
                right + safeInsets.right,
                bottom + safeInsets.bottom
            )
            windowInsets
        }
        ViewCompat.requestApplyInsets(root)
    }

        /**
     * Inicializuje všechny UI komponenty z XML layoutu.
     */
    private fun initViews() {
        urlInput = findViewById(R.id.url_input)
        scanButton = findViewById(R.id.scan_button)
        cancelButton = findViewById(R.id.cancel_button)
        progressBar = findViewById(R.id.progress_bar)
        statusText = findViewById(R.id.status_text)
        resultsContainer = findViewById(R.id.results_container)

        emailsCk = findViewById(R.id.emails_check)
        phonesCk = findViewById(R.id.phones_check)
        socialCk = findViewById(R.id.social_check)
        metaCk = findViewById(R.id.meta_tags_check)
        commentsCk = findViewById(R.id.comments_check)
        headersCk = findViewById(R.id.http_headers_check)

        subdomainsCk = findViewById(R.id.subdomains_check)
        deepCrawlCk = findViewById(R.id.deep_crawl_check)
        waybackCk = findViewById(R.id.wayback_check)
        reverseIpCk = findViewById(R.id.reverse_ip_check)
        dnsRecordsCk = findViewById(R.id.dns_records_check)
        rdapCk = findViewById(R.id.whois_check)

        fileDetectCk = findViewById(R.id.file_detect_check)

        apiKeysCk = findViewById(R.id.api_keys_check)
        errorCk = findViewById(R.id.error_check)
        sslCk = findViewById(R.id.ssl_check)
        directoriesCk = findViewById(R.id.directories_check)
        robotsTxtCk = findViewById(R.id.robots_txt_check)

        depthSeekBar = findViewById(R.id.depth_seekbar)
        depthLabel = findViewById(R.id.depth_label)

        depthSeekBar.max = DEPTH_LIMIT - 1
        depthSeekBar.progress = 0
        depthLabel.text = getString(R.string.crawl_depth, depthSeekBar.progress + 1)

        depthSeekBar.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
                MAX_DEPTH = progress + 1
                depthLabel.text = getString(R.string.crawl_depth, MAX_DEPTH)
            }
            override fun onStartTrackingTouch(seekBar: SeekBar?) {}
            override fun onStopTrackingTouch(seekBar: SeekBar?) {}
        })
    }

    /**
     * Spustí kompletní asynchronní sken na zadané URL.
     */
    private fun startCompleteScan(startUrl: String) {
        val target = NetworkSafety.parseTarget(startUrl)
        if (target == null) {
            statusText.text = getString(R.string.target_invalid)
            return
        }
        if (scanJob?.isActive == true) return

        val options = ScanOptions(
            emails = emailsCk.isChecked,
            phones = phonesCk.isChecked,
            social = socialCk.isChecked,
            meta = metaCk.isChecked,
            comments = commentsCk.isChecked,
            headers = headersCk.isChecked,
            subdomains = subdomainsCk.isChecked,
            deepCrawl = deepCrawlCk.isChecked,
            wayback = waybackCk.isChecked,
            reverseIp = reverseIpCk.isChecked,
            dnsRecords = dnsRecordsCk.isChecked,
            rdap = rdapCk.isChecked,
            fileDetect = fileDetectCk.isChecked,
            apiKeys = apiKeysCk.isChecked,
            errors = errorCk.isChecked,
            ssl = sslCk.isChecked,
            publicPaths = directoriesCk.isChecked,
            robots = robotsTxtCk.isChecked,
            maxDepth = MAX_DEPTH.coerceIn(1, DEPTH_LIMIT)
        )
        if (!options.anySelected()) {
            statusText.text = getString(R.string.select_scan_option)
            return
        }

        activeOptions = options
        visibleResultCount = 0
        progressBar.visibility = View.VISIBLE
        scanButton.isEnabled = false
        cancelButton.visibility = View.VISIBLE
        resultsContainer.removeAllViews()
        statusText.text = getString(R.string.scan_starting)

        val job = activityScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    supervisorScope {
                        val moduleScope = this
                        val semaphore = Semaphore(MAX_PARALLEL_MODULES)
                        val moduleJobs = mutableListOf<Deferred<Unit>>()

                        fun scheduleModule(label: String, action: suspend () -> Unit) {
                            moduleJobs += moduleScope.async {
                                semaphore.withPermit {
                                    try {
                                        action()
                                    } catch (cancelled: CancellationException) {
                                        throw cancelled
                                    } catch (error: Exception) {
                                        addResult(getString(R.string.module_error, label, error.javaClass.simpleName))
                                    }
                                }
                            }
                        }

                        if (anyBasicChecked(options) || options.deepCrawl) {
                            scheduleModule("Web scraping") {
                                crawlPage(target.toString(), 0, mutableSetOf(), target)
                            }
                        }
                        if (options.ssl) {
                            scheduleModule("TLS analysis") { analyzeSslCertificate(target.toString()) }
                        }
                        if (options.dnsRecords) {
                            scheduleModule("DNS intelligence") { getDnsRecords(target.toString()) }
                        }
                        if (options.rdap) {
                            scheduleModule("RDAP lookup") { getRdapInfo(target.toString()) }
                        }
                        if (options.subdomains) {
                            scheduleModule("Subdomain discovery") { getSubdomains(target.toString()) }
                        }
                        if (options.reverseIp) {
                            scheduleModule("Reverse-IP lookup") { getReverseIp(target.toString()) }
                        }
                        if (options.wayback) {
                            scheduleModule("Wayback lookup") { getWaybackMachine(target.toString()) }
                        }
                        if (options.publicPaths) {
                            scheduleModule("Public metadata paths") { testCommonDirectories(target.toString()) }
                        }
                        if (options.robots) {
                            scheduleModule("robots.txt") { checkRobotsTxt(target.toString()) }
                        }
                        if (options.fileDetect) {
                            scheduleModule("Public metadata files") { detectHiddenFiles(target.toString()) }
                        }

                        updateStatus(getString(R.string.scan_running_summary, moduleJobs.size, MAX_PARALLEL_MODULES))
                        moduleJobs.awaitAll()
                    }
                }
                updateStatus(getString(R.string.scan_completed))
            } catch (cancelled: CancellationException) {
                updateStatus(getString(R.string.scan_cancelled))
            } catch (error: Exception) {
                addResult(getString(R.string.scan_error, error.javaClass.simpleName))
                updateStatus(getString(R.string.scan_failed))
            } finally {
                withContext(NonCancellable) { finishScan() }
            }
        }
        scanJob = job
        job.invokeOnCompletion { cause ->
            if (cause is CancellationException) cancelActiveCalls()
        }
    }

    private fun cancelActiveCalls() {
        activeCalls.forEach { call -> call.cancel() }
        activeCalls.clear()
    }

    private fun anyBasicChecked(options: ScanOptions): Boolean =
        options.emails || options.phones || options.social || options.meta ||
            options.comments || options.headers || options.apiKeys || options.errors

    private suspend fun updateStatus(text: String) {
        withContext(Dispatchers.Main) { statusText.text = text }
    }

    private suspend fun finishScan() {
        withContext(Dispatchers.Main) {
            if (resultsContainer.childCount == 0) {
                resultsContainer.addView(createTextView(getString(R.string.no_results)))
            }
            progressBar.visibility = View.GONE
            scanButton.isEnabled = true
            cancelButton.visibility = View.GONE
        }
    }

    private suspend fun addResult(text: String, isTitle: Boolean = false) {
        withContext(Dispatchers.Main) {
            if (visibleResultCount >= MAX_VISIBLE_RESULTS) return@withContext
            val safeText = SensitiveTextRedactor.redact(text).take(MAX_RESULT_TEXT_LENGTH)
            resultsContainer.addView(createTextView(safeText, isTitle))
            visibleResultCount++
        }
    }

    private fun createTextView(text: String, isTitle: Boolean = false): TextView {
        val textView = TextView(this)
        val density = resources.displayMetrics.density
        fun dp(value: Int): Int = (value * density).toInt()

        textView.text = text
        textView.includeFontPadding = false
        textView.setTextColor(
            resources.getColor(
                if (isTitle) R.color.accent_cyan else R.color.text_secondary,
                theme
            )
        )
        textView.typeface = if (isTitle) {
            Typeface.create("sans-serif-medium", Typeface.BOLD)
        } else {
            Typeface.create("sans-serif", Typeface.NORMAL)
        }
        textView.textSize = if (isTitle) 12f else 13f
        textView.letterSpacing = if (isTitle) 0.06f else 0f
        textView.setLineSpacing(dp(3).toFloat(), 1f)
        textView.setPadding(0, dp(if (isTitle) 12 else 6), 0, dp(6))
        textView.setTextIsSelectable(true)
        return textView
    }

    /* ========== ZÁKLADNÍ CRAWLING ========== */
    private suspend fun crawlPage(
        url: String,
        depth: Int,
        visited: MutableSet<String>,
        scanOrigin: HttpUrl
    ) {
        if (visited.size >= MAX_PAGES || depth > activeOptions.maxDepth) return

        val parsed = NetworkSafety.parseTarget(url) ?: return
        val safeUrl = NetworkSafety.withoutSensitiveComponents(parsed)
        val key = safeUrl.toString()
        if (!visited.add(key)) return

        val downloaded = download(key) ?: return
        val html = downloaded.first
        val headers = downloaded.second
        val document = Jsoup.parse(html, key)
        val text = document.text()

        if (activeOptions.emails) addEmails(html, text)
        if (activeOptions.phones) addPhones(text)
        if (activeOptions.social) addSocial(document)
        if (activeOptions.meta) addMeta(document)
        if (activeOptions.comments) addComments(html)
        if (activeOptions.headers) addHeaders(headers, html)
        if (activeOptions.apiKeys) addApiKeys(html)
        if (activeOptions.errors) addErrors(text)

        if (activeOptions.deepCrawl && depth < activeOptions.maxDepth && visited.size < MAX_PAGES) {
            val links = document.select("a[href]").mapNotNull { element ->
                val candidate = safeUrl.resolve(element.attr("href")) ?: return@mapNotNull null
                val sameOrigin = candidate.scheme == scanOrigin.scheme &&
                    candidate.host == scanOrigin.host && candidate.port == scanOrigin.port
                if (sameOrigin) NetworkSafety.withoutSensitiveComponents(candidate).toString() else null
            }.distinct().take(MAX_LINKS_PER_PAGE)

            for (link in links) {
                if (visited.size >= MAX_PAGES) break
                delay(CRAWL_REQUEST_DELAY_MS)
                crawlPage(link, depth + 1, visited, scanOrigin)
            }
        }
    }

    private suspend fun download(url: String): Pair<String, Map<String, String>>? {
        val target = NetworkSafety.parseTarget(url) ?: return null
        val response = safeRequest(NetworkSafety.withoutSensitiveComponents(target)) ?: return null
        if (response.code !in 200..299) return null

        val contentType = response.headers.entries
            .firstOrNull { it.key.equals("Content-Type", ignoreCase = true) }
            ?.value.orEmpty()
        if (contentType.isNotBlank() &&
            !contentType.contains("text/html", ignoreCase = true) &&
            !contentType.contains("application/xhtml+xml", ignoreCase = true)
        ) return null

        return response.body to response.headers
    }

    private suspend fun safeRequest(
        url: HttpUrl,
        method: String = "GET",
        maxBytes: Int = MAX_RESPONSE_BYTES,
        readBody: Boolean = method == "GET"
    ): SafeHttpResponse? = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", USER_AGENT)
            .header("Accept", "text/html,application/xhtml+xml,application/json,text/plain,*/*")
            .method(method, null)
            .build()
        val call = client.newCall(request)
        activeCalls.add(call)
        try {
            currentCoroutineContext().ensureActive()
            call.execute().use { response ->
                val body = if (readBody && response.isSuccessful) {
                    readLimitedBody(response.body, maxBytes)
                } else {
                    ""
                }
                val certificate = response.handshake?.peerCertificates
                    ?.firstOrNull() as? X509Certificate

                SafeHttpResponse(
                    code = response.code,
                    body = body,
                    headers = safeHeaders(response.headers),
                    certificate = certificate,
                    finalUrl = response.request.url
                )
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            null
        } finally {
            activeCalls.remove(call)
        }
    }

    private fun readLimitedBody(body: ResponseBody?, maxBytes: Int): String {
        if (body == null) return ""
        if (body.contentLength() > maxBytes) throw IOException("Response exceeds size limit")

        val output = ByteArrayOutputStream(minOf(maxBytes, 64 * 1024))
        body.byteStream().use { input ->
            val buffer = ByteArray(8192)
            var total = 0
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                if (total > maxBytes) throw IOException("Response exceeds size limit")
                output.write(buffer, 0, count)
            }
        }
        val charset = body.contentType()?.charset(Charsets.UTF_8) ?: Charsets.UTF_8
        return String(output.toByteArray(), charset)
    }

    private fun safeHeaders(headers: okhttp3.Headers): Map<String, String> {
        val safe = linkedMapOf<String, String>()
        headers.names().take(MAX_HEADER_COUNT).forEach { name ->
            val lowerName = name.lowercase()
            val value = if (
                lowerName.contains("cookie") ||
                lowerName.contains("authorization") ||
                lowerName.contains("token") ||
                lowerName.contains("secret") ||
                lowerName.contains("api-key") ||
                lowerName.contains("api_key") ||
                lowerName.contains("authenticate")
            ) {
                "<redacted>"
            } else {
                headers.values(name).take(3).joinToString(", ") { it.take(MAX_HEADER_VALUE_LENGTH) }
                    .take(MAX_HEADER_VALUE_LENGTH)
            }
            safe[name] = value
        }
        return safe
    }

    /* ========== NOVÉ FUNKCE pro pokročilý OSINT ========== */
    private suspend fun detectHiddenFiles(startUrl: String) {
        val base = NetworkSafety.parseTarget(startUrl) ?: return
        val publicFiles = listOf(
            "/favicon.ico",
            "/humans.txt",
            "/manifest.json"
        )
        addResult(getString(R.string.section_public_files), isTitle = true)

        for (path in publicFiles) {
            val fileUrl = base.newBuilder().encodedPath(path).query(null).fragment(null).build()
            val response = safeRequest(fileUrl, method = "HEAD", readBody = false) ?: continue
            if (response.code in 200..299) {
                addResult(getString(R.string.found_http_path, path, response.code))
            }
        }
    }

    private suspend fun analyzeSslCertificate(startUrl: String) {
        val target = NetworkSafety.parseTarget(startUrl) ?: return
        val response = safeRequest(
            NetworkSafety.withoutSensitiveComponents(target),
            method = "HEAD",
            readBody = false
        )
        addResult(getString(R.string.section_tls), isTitle = true)
        val cert = response?.certificate
        if (cert == null) {
            addResult(getString(R.string.tls_unavailable))
            return
        }
        addResult(getString(R.string.tls_issuer, cert.issuerX500Principal.name.take(220)))
        addResult(getString(R.string.tls_valid_from, cert.notBefore))
        addResult(getString(R.string.tls_valid_until, cert.notAfter))
        addResult(getString(R.string.tls_signature_algorithm, cert.sigAlgName))
        addResult(getString(R.string.tls_subject, cert.subjectX500Principal.name.take(220)))
    }

    private suspend fun getDnsRecords(startUrl: String) {
        val target = NetworkSafety.parseTarget(startUrl) ?: return
        addResult(getString(R.string.section_dns), isTitle = true)

        if (!DomainIntelligence.isDomainName(target.host)) {
            addResult(getString(R.string.dns_requires_domain))
            return
        }

        val queries = listOf(
            target.host to "A",
            target.host to "AAAA",
            target.host to "MX",
            target.host to "NS",
            target.host to "TXT",
            target.host to "CNAME",
            target.host to "SOA",
            target.host to "CAA",
            "_dmarc.${target.host}" to "TXT"
        )
        val displayed = linkedSetOf<String>()
        var dnssecAuthenticated = false
        var answerCount = 0

        for ((queryName, queryType) in queries) {
            currentCoroutineContext().ensureActive()
            val apiUrl = "https://dns.google/resolve".toHttpUrl()
                .newBuilder()
                .addQueryParameter("name", queryName)
                .addQueryParameter("type", queryType)
                .build()
            val response = safeRequest(apiUrl, maxBytes = MAX_DNS_RESPONSE_BYTES) ?: continue
            if (response.code !in 200..299 || response.body.isBlank()) continue

            val lookup = DomainIntelligence.parseDnsResponse(response.body) ?: continue
            if (lookup.status != 0) continue
            dnssecAuthenticated = dnssecAuthenticated || lookup.authenticatedData

            lookup.answers.forEach { answer ->
                val key = "${answer.type}|${answer.name}|${answer.data}"
                if (!displayed.add(key)) return@forEach

                val recordType = DomainIntelligence.recordTypeName(answer.type)
                val recordName = answer.name.trimEnd('.')
                val label = if (queryName.startsWith("_dmarc.")) "DMARC TXT" else recordType
                addResult(getString(R.string.dns_record, label, recordName, answer.data.take(300), answer.ttl))
                answerCount++

                if (recordType == "TXT" && answer.data.contains("v=spf1", ignoreCase = true)) {
                    addResult(getString(R.string.dns_spf_detected))
                }
                if (recordType == "TXT" && answer.data.contains("v=DMARC1", ignoreCase = true)) {
                    addResult(getString(R.string.dns_dmarc_detected))
                }
            }
        }

        addResult(if (dnssecAuthenticated) getString(R.string.dnssec_authenticated)
                  else getString(R.string.dnssec_not_authenticated))
        if (answerCount == 0) addResult(getString(R.string.dns_no_answers))
    }

    private suspend fun getRdapInfo(startUrl: String) {
        val target = NetworkSafety.parseTarget(startUrl) ?: return
        addResult(getString(R.string.section_rdap), isTitle = true)

        if (!DomainIntelligence.isDomainName(target.host)) {
            addResult(getString(R.string.rdap_requires_domain))
            return
        }

        val bootstrapUrl = "https://data.iana.org/rdap/dns.json".toHttpUrl()
        val bootstrap = safeRequest(bootstrapUrl, maxBytes = MAX_RDAP_BOOTSTRAP_BYTES) ?: run {
            addResult(getString(R.string.rdap_bootstrap_unavailable))
            return
        }
        if (bootstrap.code !in 200..299 || bootstrap.body.isBlank()) {
            addResult(getString(R.string.rdap_bootstrap_empty))
            return
        }

        var selectedDomain: String? = null
        var selectedResponse: SafeHttpResponse? = null

        for (candidate in DomainIntelligence.registrationCandidates(target.host)) {
            currentCoroutineContext().ensureActive()
            val base = DomainIntelligence.findRdapBaseUrl(bootstrap.body, candidate)
                ?.toHttpUrlOrNull() ?: continue
            val rdapUrl = base.newBuilder()
                .addPathSegment("domain")
                .addPathSegment(candidate)
                .build()
            val response = safeRequest(rdapUrl, maxBytes = MAX_RDAP_RESPONSE_BYTES) ?: continue
            if (response.code in 200..299 && response.body.isNotBlank()) {
                selectedDomain = candidate
                selectedResponse = response
                break
            }
        }

        val response = selectedResponse
        if (response == null) {
            addResult(getString(R.string.rdap_no_record))
            return
        }

        val summary = DomainIntelligence.parseRdapSummary(response.body)
        if (summary == null) {
            addResult(getString(R.string.rdap_parse_error))
            return
        }

        addResult(getString(R.string.rdap_domain, summary.name.ifBlank { selectedDomain.orEmpty() }))
        summary.handle?.let { addResult(getString(R.string.rdap_handle, it)) }
        summary.registrar?.let { addResult(getString(R.string.rdap_registrar, it)) }
        summary.status.take(8).forEach { addResult(getString(R.string.rdap_status, it)) }
        summary.events.take(8).forEach { event ->
            addResult(getString(R.string.rdap_event, event.action, event.date))
        }
        summary.nameservers.take(12).forEach { addResult(getString(R.string.rdap_nameserver, it)) }
    }

    private suspend fun getReverseIp(startUrl: String) {
        val target = NetworkSafety.parseTarget(startUrl) ?: return
        try {
            val address = PublicInternetDns().lookup(target.host).firstOrNull() ?: return
            val apiUrl = "https://api.hackertarget.com/reverseiplookup/".toHttpUrl()
                .newBuilder().addQueryParameter("q", address.hostAddress).build()
            val response = safeRequest(apiUrl, maxBytes = MAX_API_RESPONSE_BYTES) ?: return
            if (response.code !in 200..299 || response.body.isBlank()) return

            addResult(getString(R.string.section_reverse_ip, address.hostAddress), isTitle = true)
            response.body.lines().filter { it.isNotBlank() }.take(20).forEach {
                addResult(getString(R.string.domain_result, it.trim().take(253)))
            }
        } catch (_: Exception) {
            addResult(getString(R.string.reverse_ip_unavailable))
        }
    }

    private suspend fun getWaybackMachine(startUrl: String) {
        val target = NetworkSafety.parseTarget(startUrl) ?: return
        val cleanTarget = target.newBuilder().encodedPath("/").query(null).fragment(null).build().toString()
        val apiUrl = "https://archive.org/wayback/available".toHttpUrl()
            .newBuilder().addQueryParameter("url", cleanTarget).build()

        try {
            val response = safeRequest(apiUrl, maxBytes = MAX_API_RESPONSE_BYTES) ?: return
            if (response.code !in 200..299 || response.body.isBlank()) return

            val type = object : TypeToken<Map<String, Any>>() {}.type
            val data: Map<String, Any> = gson.fromJson(response.body, type)
            val snapshots = data["archived_snapshots"] as? Map<*, *>
            val closest = snapshots?.get("closest") as? Map<*, *>
            val timestamp = closest?.get("timestamp") as? String
            val archivedUrl = closest?.get("url") as? String

            addResult(getString(R.string.section_wayback), isTitle = true)
            if (timestamp != null && timestamp.length >= 8 && timestamp.all(Char::isDigit)) {
                val date = "${timestamp.substring(0, 4)}-${timestamp.substring(4, 6)}-${timestamp.substring(6, 8)}"
                addResult(getString(R.string.wayback_last_snapshot, date))
            } else {
                addResult(getString(R.string.wayback_no_snapshot))
            }
            val safeArchivedUrl = archivedUrl?.toHttpUrlOrNull()
                ?.let(NetworkSafety::withoutSensitiveComponents)
                ?.toString()
            if (!safeArchivedUrl.isNullOrBlank()) {
                addResult(getString(R.string.wayback_archive_url, safeArchivedUrl.take(400)))
            }
        } catch (_: Exception) {
            addResult(getString(R.string.wayback_unavailable))
        }
    }

    private suspend fun testCommonDirectories(startUrl: String) {
        val base = NetworkSafety.parseTarget(startUrl) ?: return
        val publicPaths = listOf(
            "/sitemap.xml",
            "/.well-known/security.txt"
        )
        addResult(getString(R.string.section_public_paths), isTitle = true)
        for (path in publicPaths) {
            val url = base.newBuilder().encodedPath(path).query(null).fragment(null).build()
            val response = safeRequest(url, method = "HEAD", readBody = false) ?: continue
            if (response.code in 200..299) addResult(getString(R.string.path_available, path, response.code))
            else if (response.code == 401 || response.code == 403) addResult(getString(R.string.path_restricted, path, response.code))
        }
    }

    private suspend fun checkRobotsTxt(startUrl: String) {
        val base = NetworkSafety.parseTarget(startUrl) ?: return
        val url = base.newBuilder().encodedPath("/robots.txt").query(null).fragment(null).build()
        val response = safeRequest(url, maxBytes = MAX_ROBOTS_BYTES)
        addResult(getString(R.string.section_robots), isTitle = true)
        if (response == null || response.code !in 200..299) {
            addResult(getString(R.string.robots_unavailable))
            return
        }

        addResult(getString(R.string.robots_found))
        response.body.lineSequence()
            .filter { it.trim().startsWith("Disallow:", ignoreCase = true) }
            .take(100)
            .forEach { addResult(it.trim().take(300)) }
    }

    /* ========== PŮVODNÍ DETEKTORY ========== */
    private suspend fun addEmails(html: String, text: String) {
        val pattern = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
        val matcher = pattern.matcher("$html $text")
        val found = linkedSetOf<String>()
        while (matcher.find() && found.size < 40) found.add(matcher.group())

        if (found.isNotEmpty()) {
            addResult(getString(R.string.section_emails), isTitle = true)
            found.forEach { addResult(it) }
        }
    }

        private suspend fun addPhones(text: String) {
        val pattern = Pattern.compile("(\\+?\\d{1,4}[\\s-]?)?\\(?\\d{3}\\)?[\\s-]?\\d{3}[\\s-]?\\d{3,4}")
        val matcher = pattern.matcher(text)
        val found = linkedSetOf<String>()
        while (matcher.find() && found.size < 40) {
            val phone = matcher.group().trim()
            if (phone.replace("\\D".toRegex(), "").length >= 7) found.add(phone)
        }

        if (found.isNotEmpty()) {
            addResult(getString(R.string.section_phones), isTitle = true)
            found.forEach { addResult(it) }
        }
    }

        private suspend fun addSocial(doc: org.jsoup.nodes.Document) {
        val domains = listOf(
            "facebook.com", "fb.com", "twitter.com", "x.com", "linkedin.com",
            "instagram.com", "youtube.com", "tiktok.com"
        )
        val found = doc.select("a[href]").mapNotNull { link ->
            val parsed = link.absUrl("href").toHttpUrlOrNull() ?: return@mapNotNull null
            val host = parsed.host.removePrefix("www.")
            if (domains.any { host == it || host.endsWith(".$it") }) {
                NetworkSafety.withoutSensitiveComponents(parsed).toString().take(300)
            } else null
        }.distinct().take(25)

        if (found.isNotEmpty()) {
            addResult(getString(R.string.section_social), isTitle = true)
            found.forEach { addResult(it) }
        }
    }

    private suspend fun addMeta(doc: org.jsoup.nodes.Document) {
        val meta = mutableListOf<String>()
        doc.select("meta[name=generator]").first()?.let { meta.add(getString(R.string.meta_generator, it.attr("content"))) }
        doc.select("meta[name=description]").first()?.let { meta.add(getString(R.string.meta_description, it.attr("content"))) }
        doc.select("meta[name=keywords]").first()?.let { meta.add(getString(R.string.meta_keywords, it.attr("content"))) }

        if (meta.isNotEmpty()) {
            addResult(getString(R.string.section_meta), isTitle = true)
            meta.forEach { addResult(it) }
        }
    }

        private suspend fun addComments(html: String) {
        val matcher = Pattern.compile("<!--([\\s\\S]*?)-->").matcher(html)
        val found = mutableListOf<String>()
        while (matcher.find() && found.size < 5) {
            val comment = matcher.group(1)?.trim().orEmpty()
            if (comment.length > 3) found.add(comment)
        }

        if (found.isNotEmpty()) {
            addResult(getString(R.string.section_html_comments), isTitle = true)
            found.forEach { addResult(it.take(100)) }
        }
    }

        private suspend fun addHeaders(headers: Map<String, String>, html: String) {
        if (headers.isNotEmpty()) {
            addResult(getString(R.string.section_http_headers), isTitle = true)
            headers.entries.take(30).forEach { (key, value) ->
                addResult("$key: ${value.take(MAX_HEADER_VALUE_LENGTH)}")
            }
        }

        val tech = mutableListOf<String>()
        if (html.contains("/wp-content/", ignoreCase = true)) tech.add("WordPress")
        if (html.contains("Joomla!", ignoreCase = true)) tech.add("Joomla")
        if (html.contains("jquery", ignoreCase = true)) tech.add("jQuery")
        if (html.contains("react", ignoreCase = true)) tech.add("React")

        if (tech.isNotEmpty()) {
            addResult(getString(R.string.section_detected_technologies), isTitle = true)
            tech.distinct().forEach { addResult(it) }
        }
    }

    private suspend fun addApiKeys(html: String) {
        val patterns = listOf(
            "AIza[0-9A-Za-z_-]{35}",
            "sk-[a-zA-Z0-9]{32,}",
            "pk_live_[a-zA-Z0-9]{24}"
        )
        val found = mutableSetOf<String>()
        for (pattern in patterns) {
            val matcher = Pattern.compile(pattern).matcher(html)
            while (matcher.find() && found.size < 20) found.add(matcher.group())
        }

        if (found.isNotEmpty()) {
            addResult(getString(R.string.section_api_keys), isTitle = true)
            found.take(5).forEach { secret ->
                val masked = if (secret.length <= 8) "••••••••"
                    else "${secret.take(4)}…${secret.takeLast(4)}"
                addResult(getString(R.string.possible_api_key, masked))
            }
        }
    }

    private suspend fun addErrors(text: String) {
        val keywords = listOf("SQL Error", "Fatal error", "Warning:", "Stack trace")
        val found = mutableListOf<String>()
        for (keyword in keywords) {
            val regex = Regex(".{0,60}$keyword.{0,60}", RegexOption.IGNORE_CASE)
            regex.findAll(text).take(5).forEach { found.add(it.value.replace('\n', ' ').trim()) }
        }

        if (found.isNotEmpty()) {
            addResult(getString(R.string.section_errors), isTitle = true)
            found.take(5).forEach { addResult(it) }
        }
    }

        private suspend fun getSubdomains(startUrl: String) {
        val target = NetworkSafety.parseTarget(startUrl) ?: return
        val host = target.host.removePrefix("www.").lowercase()
        val apiUrl = "https://crt.sh/".toHttpUrl()
            .newBuilder().addQueryParameter("q", "%.$host").addQueryParameter("output", "json").build()

        try {
            val response = safeRequest(apiUrl, maxBytes = MAX_API_RESPONSE_BYTES) ?: return
            if (response.code !in 200..299 || response.body.isBlank()) return

            val listType = object : TypeToken<List<Map<String, String>>>() {}.type
            val records: List<Map<String, String>> = gson.fromJson(response.body, listType)
            val found = linkedSetOf<String>()

            fun consider(candidate: String) {
                val name = candidate.trim().trimEnd('.').lowercase()
                if (name.startsWith("*.") || name == host || !name.endsWith(".$host")) return
                if (name.length > 253 || name.split('.').any { label ->
                    label.isBlank() || label.length > 63 ||
                        !label.matches(Regex("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"))
                }) return
                found.add(name)
            }

            records.forEach { record ->
                record["common_name"]?.let(::consider)
                record["name_value"]?.split('\n')?.forEach(::consider)
            }

            if (found.isNotEmpty()) {
                addResult(getString(R.string.section_subdomains), isTitle = true)
                found.sorted().take(50).forEach { addResult(it) }
                if (found.size > 50) addResult(getString(R.string.subdomains_truncated, found.size))
            }
        } catch (_: Exception) {
            addResult(getString(R.string.crtsh_unavailable))
        }
    }

    
    companion object {
        private const val MAX_PAGES = 20
        private const val DEPTH_LIMIT = 5
        private const val MAX_LINKS_PER_PAGE = 10
        private const val CRAWL_REQUEST_DELAY_MS = 200L
        private const val MAX_RESPONSE_BYTES = 1_048_576
        private const val MAX_API_RESPONSE_BYTES = 512 * 1024
        private const val MAX_DNS_RESPONSE_BYTES = 32 * 1024
        private const val MAX_RDAP_BOOTSTRAP_BYTES = 512 * 1024
        private const val MAX_RDAP_RESPONSE_BYTES = 128 * 1024
        private const val MAX_PARALLEL_MODULES = 4
        private const val MAX_ROBOTS_BYTES = 64 * 1024
        private const val MAX_HEADER_COUNT = 40
        private const val MAX_HEADER_VALUE_LENGTH = 512
        private const val MAX_RESULT_TEXT_LENGTH = 600
        private const val MAX_VISIBLE_RESULTS = 350
        private const val USER_AGENT = "OSINT-Harvester/1.3.0 (+https://github.com/DSL-21/OsintHarvester)"
    }
}


private data class ScanOptions(
    val emails: Boolean = false,
    val phones: Boolean = false,
    val social: Boolean = false,
    val meta: Boolean = false,
    val comments: Boolean = false,
    val headers: Boolean = false,
    val subdomains: Boolean = false,
    val deepCrawl: Boolean = false,
    val wayback: Boolean = false,
    val reverseIp: Boolean = false,
    val dnsRecords: Boolean = false,
    val rdap: Boolean = false,
    val fileDetect: Boolean = false,
    val apiKeys: Boolean = false,
    val errors: Boolean = false,
    val ssl: Boolean = false,
    val publicPaths: Boolean = false,
    val robots: Boolean = false,
    val maxDepth: Int = 1
) {
    fun anySelected(): Boolean =
        emails || phones || social || meta || comments || headers ||
            subdomains || deepCrawl || wayback || reverseIp || dnsRecords ||
            rdap || fileDetect || apiKeys || errors || ssl || publicPaths || robots
}

private data class SafeHttpResponse(
    val code: Int,
    val body: String,
    val headers: Map<String, String>,
    val certificate: X509Certificate?,
    val finalUrl: HttpUrl
)
