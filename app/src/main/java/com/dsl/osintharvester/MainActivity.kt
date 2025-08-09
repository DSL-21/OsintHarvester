package com.dsl.osintharvester

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.SeekBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.*
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import java.net.InetAddress
import java.security.cert.X509Certificate
import java.util.regex.Pattern
import javax.net.ssl.HttpsURLConnection

class MainActivity : AppCompatActivity() {

    /* UI komponenty */
    private lateinit var urlInput: EditText
    private lateinit var scanButton: Button
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
    private lateinit var whoisCk: CheckBox
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
    private val client = OkHttpClient()
    private val gson = Gson()
    private val results = mutableListOf<String>()

    /* Crawling nastavení */
    private val MAX_PAGES = 20
    private var MAX_DEPTH = 1
    private val DEPTH_LIMIT = 5

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initViews()

        scanButton.setOnClickListener {
            val urlTxt = urlInput.text.toString().trim()
            if (urlTxt.isEmpty()) {
                statusText.text = "Zadej URL!"
                return@setOnClickListener
            }
            startCompleteScan(if (!urlTxt.startsWith("http")) "https://$urlTxt" else urlTxt)
        }
    }

    /**
     * Inicializuje všechny UI komponenty z XML layoutu.
     */
    private fun initViews() {
        urlInput = findViewById(R.id.url_input)
        scanButton = findViewById(R.id.scan_button)
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
        whoisCk = findViewById(R.id.whois_check)

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
        depthLabel.text = "Hloubka skenování: ${depthSeekBar.progress + 1}"

        depthSeekBar.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
                MAX_DEPTH = progress + 1
                depthLabel.text = "Hloubka skenování: $MAX_DEPTH"
            }
            override fun onStartTrackingTouch(seekBar: SeekBar?) {}
            override fun onStopTrackingTouch(seekBar: SeekBar?) {}
        })
    }

    /**
     * Spustí kompletní asynchronní sken na zadané URL.
     */
    private fun startCompleteScan(startUrl: String) {
        progressBar.visibility = View.VISIBLE
        scanButton.isEnabled = false
        resultsContainer.removeAllViews()
        statusText.text = "🚀 Spouštím kompletní OSINT sken..."

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val visited = mutableSetOf<String>()

                if (anyBasicChecked() || deepCrawlCk.isChecked) {
                    updateStatus("📄 Skenuji webový obsah...")
                    crawlPage(startUrl, 0, visited)
                }

                if (sslCk.isChecked) {
                    updateStatus("🔐 Analyzuji SSL certifikát...")
                    analyzeSslCertificate(startUrl)
                }

                if (dnsRecordsCk.isChecked) {
                    updateStatus("📡 Získávám DNS záznamy...")
                    getDnsRecords(startUrl)
                }

                if (subdomainsCk.isChecked) {
                    updateStatus("🌐 Hledám subdomény...")
                    getSubdomains(startUrl)
                }

                if (reverseIpCk.isChecked) {
                    updateStatus("🔄 Provádím reverse IP lookup...")
                    getReverseIp(startUrl)
                }

                if (waybackCk.isChecked) {
                    updateStatus("⏰ Hledám historické záznamy...")
                    getWaybackMachine(startUrl)
                }

                if (whoisCk.isChecked) {
                    updateStatus("🔍 Získávám WHOIS informace...")
                    getWhoisInfo(startUrl)
                }

                if (directoriesCk.isChecked) {
                    updateStatus("📁 Testuji běžné adresáře...")
                    testCommonDirectories(startUrl)
                }

                if (robotsTxtCk.isChecked) {
                    updateStatus("🤖 Hledám robots.txt a disallow pravidla...")
                    checkRobotsTxt(startUrl)
                }

                if (fileDetectCk.isChecked) {
                    updateStatus("📂 Hledám skryté soubory...")
                    detectHiddenFiles(startUrl)
                }

                finishScan()

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    resultsContainer.addView(createTextView("❌ Kritická chyba: ${e.message}"))
                    finishScan()
                }
            }
        }
    }

    private fun anyBasicChecked(): Boolean {
        return emailsCk.isChecked || phonesCk.isChecked || socialCk.isChecked ||
                metaCk.isChecked || commentsCk.isChecked || headersCk.isChecked ||
                apiKeysCk.isChecked || errorCk.isChecked
    }

    private suspend fun updateStatus(text: String) {
        withContext(Dispatchers.Main) { statusText.text = text }
    }

    private suspend fun finishScan() {
        withContext(Dispatchers.Main) {
            if (resultsContainer.childCount == 0) resultsContainer.addView(createTextView("ℹ️ Žádné výsledky nenalezeny"))
            progressBar.visibility = View.GONE
            statusText.text = "✅ Skenování dokončeno!"
            scanButton.isEnabled = true
        }
    }

    private fun createTextView(text: String, isTitle: Boolean = false): TextView {
        val textView = TextView(this)
        textView.text = text
        textView.setTextColor(resources.getColor(android.R.color.white, theme))
        if (isTitle) {
            textView.textSize = 16f
            textView.setPadding(0, 16, 0, 4)
        } else {
            textView.textSize = 14f
            textView.setPadding(0, 4, 0, 4)
        }
        return textView
    }

    /* ========== ZÁKLADNÍ CRAWLING ========== */
    private suspend fun crawlPage(url: String, depth: Int, visited: MutableSet<String>) {
        if (visited.size >= MAX_PAGES || visited.contains(url) || depth > MAX_DEPTH) return
        visited.add(url)

        val (html, headers) = download(url) ?: return
        val doc = Jsoup.parse(html)
        val text = doc.text()

        if (emailsCk.isChecked) addEmails(html, text)
        if (phonesCk.isChecked) addPhones(text)
        if (socialCk.isChecked) addSocial(doc)
        if (metaCk.isChecked) addMeta(doc)
        if (commentsCk.isChecked) addComments(html)
        if (headersCk.isChecked) addHeaders(headers, html)
        if (apiKeysCk.isChecked) addApiKeys(html)
        if (errorCk.isChecked) addErrors(text)

        if (deepCrawlCk.isChecked && depth < MAX_DEPTH) {
            val baseHost = url.toHttpUrl().host
            val links = doc.select("a[href]").map { it.absUrl("href") }
                .filter { it.startsWith("http") && it.toHttpUrl().host == baseHost }
                .take(15)
            for (link in links) crawlPage(link, depth + 1, visited)
        }
    }

    private fun download(url: String): Pair<String, Map<String,String>>? {
        return try {
            val request = Request.Builder()
                .url(url)
                .addHeader("User-Agent", "OSINT-Harvester-Pro/2.0")
                .build()
            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: return null
                val headers = response.headers.toMultimap().mapValues { it.value.joinToString() }
                body to headers
            }
        } catch (e: Exception) { null }
    }

    /* ========== NOVÉ FUNKCE pro pokročilý OSINT ========== */
    private suspend fun detectHiddenFiles(startUrl: String) {
        val commonFiles = listOf(
            "sitemap.xml", "favicon.ico", "crossdomain.xml", "security.txt", "humans.txt"
        )
        val host = startUrl.toHttpUrl().host

        withContext(Dispatchers.Main) {
            resultsContainer.addView(createTextView("=== 📂 HLEDANÉ SOUBORY ===", isTitle = true))
        }

        for (file in commonFiles) {
            try {
                val testUrl = startUrl.toHttpUrl().newBuilder().addPathSegment(file).build()
                val request = Request.Builder()
                    .url(testUrl)
                    .addHeader("User-Agent", "OSINT-Harvester-Pro/2.0")
                    .build()
                val response = client.newCall(request).execute()

                withContext(Dispatchers.Main) {
                    if (response.isSuccessful) {
                        resultsContainer.addView(createTextView("✅ $file - nalezen na $host"))
                    }
                }
            } catch (e: Exception) {
                // Tichý pád, pokud soubor neexistuje
            }
        }
    }

    /* ========== POKROČILÉ FUNKCE (původní) ========== */
    private suspend fun analyzeSslCertificate(startUrl: String) {
        try {
            val host = startUrl.toHttpUrl().host
            val connection = java.net.URL("https://$host").openConnection() as HttpsURLConnection
            connection.connect()
            val certificates = connection.serverCertificates

            withContext(Dispatchers.Main) {
                resultsContainer.addView(createTextView("=== 🔐 SSL CERTIFIKÁT ===", isTitle = true))
                if (certificates.isNotEmpty()) {
                    val cert = certificates[0] as X509Certificate
                    resultsContainer.addView(createTextView("🏢 Vydavatel: ${cert.issuerDN}"))
                    resultsContainer.addView(createTextView("📅 Platný od: ${cert.notBefore}"))
                    resultsContainer.addView(createTextView("📅 Platný do: ${cert.notAfter}"))
                    resultsContainer.addView(createTextView("🔑 Algoritmus: ${cert.sigAlgName}"))
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                resultsContainer.addView(createTextView("❌ SSL chyba: ${e.message}"))
            }
        }
    }

    private suspend fun getDnsRecords(startUrl: String) {
        try {
            val host = startUrl.toHttpUrl().host
            val addresses = InetAddress.getAllByName(host)

            withContext(Dispatchers.Main) {
                resultsContainer.addView(createTextView("=== 📡 DNS ZÁZNAMY ===", isTitle = true))
                addresses.forEach { addr ->
                    resultsContainer.addView(createTextView("🌐 A: ${addr.hostAddress}"))
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                resultsContainer.addView(createTextView("❌ DNS chyba: ${e.message}"))
            }
        }
    }

    private suspend fun getReverseIp(startUrl: String) {
        try {
            val host = startUrl.toHttpUrl().host.removePrefix("www.")
            val ip = InetAddress.getByName(host).hostAddress
            val apiUrl = "https://api.hackertarget.com/reverseiplookup/?q=$ip"

            val request = Request.Builder().url(apiUrl).build()
            val response = client.newCall(request).execute()
            val body = response.body?.string() ?: ""

            withContext(Dispatchers.Main) {
                if (body.isNotEmpty() && !body.contains("error")) {
                    resultsContainer.addView(createTextView("=== 🔄 REVERSE IP ($ip) ===", isTitle = true))
                    body.lines().take(20).forEach { domain ->
                        if (domain.trim().isNotEmpty()) {
                            resultsContainer.addView(createTextView("🌐 $domain"))
                        }
                    }
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                resultsContainer.addView(createTextView("❌ Reverse IP chyba: ${e.message}"))
            }
        }
    }

    // NOVÁ, opravená verze pro Wayback Machine V3
    private suspend fun getWaybackMachine(startUrl: String) {
        try {
            // Změna na HTTPS pro vyřešení chyby CLEARTEXT
            val apiUrl = "https://archive.org/wayback/available?url=$startUrl"

            val request = Request.Builder().url(apiUrl).build()
            val response = client.newCall(request).execute()
            val body = response.body?.string() ?: ""

            val type = object : TypeToken<Map<String, Any>>() {}.type
            val data: Map<String, Any> = gson.fromJson(body, type)

            withContext(Dispatchers.Main) {
                resultsContainer.addView(createTextView("=== ⏰ WAYBACK MACHINE ===", isTitle = true))

                if (data.containsKey("archived_snapshots")) {
                    val snapshots = data["archived_snapshots"] as Map<String, Any>
                    val closestSnapshot = snapshots["closest"] as Map<String, String>
                    val timestamp = closestSnapshot["timestamp"]
                    val url = closestSnapshot["url"]
                    val date = "${timestamp?.substring(0,4)}-${timestamp?.substring(4,6)}-${timestamp?.substring(6,8)}"
                    resultsContainer.addView(createTextView("📅 Poslední záznam: $date"))
                    resultsContainer.addView(createTextView("🔗 URL: $url"))
                } else {
                    resultsContainer.addView(createTextView("❌ Žádné historické záznamy nebyly nalezeny."))
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                resultsContainer.addView(createTextView("❌ Wayback chyba: ${e.message}"))
            }
        }
    }

    private suspend fun getWhoisInfo(startUrl: String) {
        try {
            val host = startUrl.toHttpUrl().host.removePrefix("www.")
            val apiUrl = "https://api.hackertarget.com/whois/?q=$host"

            val request = Request.Builder().url(apiUrl).build()
            val response = client.newCall(request).execute()
            val body = response.body?.string() ?: ""

            withContext(Dispatchers.Main) {
                if (body.isNotEmpty() && !body.contains("error")) {
                    resultsContainer.addView(createTextView("=== 🔍 WHOIS INFORMACE ===", isTitle = true))
                    val lines = body.lines().filter {
                        it.contains("Registrar:") || it.contains("Creation Date:") ||
                                it.contains("Expiry Date:") || it.contains("Organization:")
                    }
                    lines.take(10).forEach { line ->
                        resultsContainer.addView(createTextView("ℹ️ $line"))
                    }
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                resultsContainer.addView(createTextView("❌ WHOIS chyba: ${e.message}"))
            }
        }
    }

    private suspend fun testCommonDirectories(startUrl: String) {
        val commonDirs = listOf(
            "/admin", "/wp-admin", "/phpmyadmin", "/robots.txt", "/sitemap.xml",
            "/.git", "/.env", "/backup", "/config", "/api"
        )

        withContext(Dispatchers.Main) {
            resultsContainer.addView(createTextView("=== 📁 BĚŽNÉ ADRESÁŘE ===", isTitle = true))
        }

        for (dir in commonDirs) {
            try {
                val testUrl = startUrl.trimEnd('/') + dir
                val request = Request.Builder()
                    .url(testUrl)
                    .addHeader("User-Agent", "OSINT-Harvester-Pro/2.0")
                    .build()
                val response = client.newCall(request).execute()

                withContext(Dispatchers.Main) {
                    when (response.code) {
                        200 -> resultsContainer.addView(createTextView("✅ $dir - PŘÍSTUPNÝ"))
                        403 -> resultsContainer.addView(createTextView("🔒 $dir - ZAKÁZÁN"))
                        401 -> resultsContainer.addView(createTextView("🔐 $dir - VYŽADUJE AUTENTIFIKACI"))
                    }
                }
            } catch (e: Exception) {
                // Tiše ignorujeme nedostupné adresáře
            }
        }
    }

    private suspend fun checkRobotsTxt(startUrl: String) {
        try {
            val url = startUrl.toHttpUrl().newBuilder().addPathSegment("robots.txt").build()
            val request = Request.Builder().url(url).build()
            val response = client.newCall(request).execute()

            withContext(Dispatchers.Main) {
                if (response.isSuccessful) {
                    val body = response.body?.string()
                    if (!body.isNullOrEmpty()) {
                        resultsContainer.addView(createTextView("=== 🤖 ROBOTS.TXT ===", isTitle = true))
                        resultsContainer.addView(createTextView("✅ Soubor robots.txt nalezen."))
                        body.lines().forEach { line ->
                            if (line.trim().startsWith("Disallow:", ignoreCase = true)) {
                                resultsContainer.addView(createTextView("🚫 ${line.trim()}"))
                            }
                        }
                    } else {
                        resultsContainer.addView(createTextView("❌ robots.txt nalezen, ale je prázdný."))
                    }
                } else {
                    resultsContainer.addView(createTextView("❌ robots.txt nebyl nalezen (kód ${response.code})."))
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                resultsContainer.addView(createTextView("❌ Chyba při hledání robots.txt: ${e.message}"))
            }
        }
    }

    /* ========== PŮVODNÍ DETEKTORY ========== */
    private suspend fun addEmails(html: String, text: String) {
        val pattern = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
        val matcher = pattern.matcher("$html $text")
        val found = mutableSetOf<String>()
        while (matcher.find()) found.add(matcher.group())

        withContext(Dispatchers.Main) {
            if (found.isNotEmpty()) {
                resultsContainer.addView(createTextView("=== 📧 EMAILY ===", isTitle = true))
                found.forEach { resultsContainer.addView(createTextView("📧 $it")) }
            }
        }
    }

    private suspend fun addPhones(text: String) {
        val pattern = Pattern.compile("(\\+?\\d{1,4}[\\s-]?)?\\(?\\d{3}\\)?[\\s-]?\\d{3}[\\s-]?\\d{3,4}")
        val matcher = pattern.matcher(text)
        val found = mutableSetOf<String>()
        while (matcher.find()) {
            val phone = matcher.group().trim()
            if (phone.replace("\\D".toRegex(), "").length >= 7) found.add(phone)
        }

        withContext(Dispatchers.Main) {
            if (found.isNotEmpty()) {
                resultsContainer.addView(createTextView("=== 📞 TELEFONY ===", isTitle = true))
                found.forEach { resultsContainer.addView(createTextView("📞 $it")) }
            }
        }
    }

    private suspend fun addSocial(doc: org.jsoup.nodes.Document) {
        val domains = listOf("facebook.com","fb.com","twitter.com","x.com",
            "linkedin.com","instagram.com","youtube.com","tiktok.com")
        val found = mutableSetOf<String>()
        doc.select("a[href]").forEach { link ->
            val href = link.attr("href")
            if (domains.any { href.contains(it) }) found.add(href)
        }

        withContext(Dispatchers.Main) {
            if (found.isNotEmpty()) {
                resultsContainer.addView(createTextView("=== 🔗 SOCIÁLNÍ MÉDIA ===", isTitle = true))
                found.forEach { resultsContainer.addView(createTextView("🔗 $it")) }
            }
        }
    }

    private suspend fun addMeta(doc: org.jsoup.nodes.Document) {
        val meta = mutableListOf<String>()
        doc.select("meta[name=generator]").first()?.let { meta.add("🔧 Generator: ${it.attr("content")}") }
        doc.select("meta[name=description]").first()?.let { meta.add("📝 Popis: ${it.attr("content")}") }
        doc.select("meta[name=keywords]").first()?.let { meta.add("🏷️ Klíčová slova: ${it.attr("content")}") }

        withContext(Dispatchers.Main) {
            if (meta.isNotEmpty()) {
                resultsContainer.addView(createTextView("=== 🏷️ META TAGY ===", isTitle = true))
                meta.forEach { resultsContainer.addView(createTextView(it)) }
            }
        }
    }

    private suspend fun addComments(html: String) {
        val matcher = Pattern.compile("<!--([\\s\\S]*?)-->").matcher(html)
        val found = mutableListOf<String>()
        while (matcher.find()) {
            val comment = matcher.group(1).trim()
            if (comment.length > 3) found.add(comment)
        }

        withContext(Dispatchers.Main) {
            if (found.isNotEmpty()) {
                resultsContainer.addView(createTextView("=== 💬 KOMENTÁŘE ===", isTitle = true))
                found.take(5).forEach {
                    resultsContainer.addView(createTextView("💬 ${if (it.length > 100) it.take(100) + "..." else it}"))
                }
            }
        }
    }

    private suspend fun addHeaders(headers: Map<String,String>, html: String) {
        withContext(Dispatchers.Main) {
            if (headers.isNotEmpty()) {
                resultsContainer.addView(createTextView("=== 📑 HTTP HLAVIČKY ===", isTitle = true))
                headers.forEach { (k, v) -> resultsContainer.addView(createTextView("📑 $k: $v")) }
            }
        }

        val tech = mutableListOf<String>()
        if (html.contains("/wp-content/")) tech.add("WordPress")
        if (html.contains("Joomla!")) tech.add("Joomla")
        if (html.contains("jquery")) tech.add("jQuery")
        if (html.contains("react")) tech.add("React")

        withContext(Dispatchers.Main) {
            if (tech.isNotEmpty()) {
                resultsContainer.addView(createTextView("=== 🛠️ TECHNOLOGIE ===", isTitle = true))
                tech.distinct().forEach { resultsContainer.addView(createTextView("🛠️ $it")) }
            }
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
            while (matcher.find()) found.add(matcher.group())
        }

        withContext(Dispatchers.Main) {
            if (found.isNotEmpty()) {
                resultsContainer.addView(createTextView("=== 🔑 API KLÍČE ===", isTitle = true))
                found.take(5).forEach { resultsContainer.addView(createTextView("🔑 $it")) }
            }
        }
    }

    private suspend fun addErrors(text: String) {
        val keywords = listOf("SQL Error", "Fatal error", "Warning:", "Stack trace")
        val found = mutableListOf<String>()
        for (keyword in keywords) {
            val regex = Regex(".{0,60}$keyword.{0,60}", RegexOption.IGNORE_CASE)
            regex.findAll(text).forEach { found.add(it.value.replace('\n', ' ').trim()) }
        }

        withContext(Dispatchers.Main) {
            if (found.isNotEmpty()) {
                resultsContainer.addView(createTextView("=== ❌ CHYBOVÉ ZPRÁVY ===", isTitle = true))
                found.take(5).forEach { resultsContainer.addView(createTextView("❌ $it")) }
            }
        }
    }

    private suspend fun getSubdomains(startUrl: String) {
        try {
            val host = startUrl.toHttpUrl().host.removePrefix("www.")
            val apiUrl = "https://crt.sh/?q=%25.$host&output=json"
            val request = Request.Builder().url(apiUrl).build()
            val response = client.newCall(request).execute()
            val body = response.body?.string() ?: ""

            val listType = object : TypeToken<List<Map<String,String>>>() {}.type
            val records: List<Map<String,String>> = gson.fromJson(body, listType)

            val found = mutableSetOf<String>()
            for (record in records) {
                record["common_name"]?.let {
                    if (it.endsWith(".$host") && !it.startsWith("*.")) found.add(it)
                }
                record["name_value"]?.split('\n')?.forEach { name ->
                    if (name.endsWith(".$host") && !name.startsWith("*.")) found.add(name)
                }
            }

            withContext(Dispatchers.Main) {
                if (found.isNotEmpty()) {
                    resultsContainer.addView(createTextView("=== 🌐 SUBDOMÉNY ===", isTitle = true))
                    found.sorted().take(50).forEach { resultsContainer.addView(createTextView("🌐 $it")) }
                    if (found.size > 50) resultsContainer.addView(createTextView("... a dalších ${found.size - 50}"))
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                resultsContainer.addView(createTextView("❌ Subdomény chyba: ${e.message}"))
            }
        }
    }
}
