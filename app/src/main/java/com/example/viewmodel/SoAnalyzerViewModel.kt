package com.example.viewmodel

import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.model.*
import com.example.parser.ElfParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.InputStream

class SoAnalyzerViewModel : ViewModel() {

    // Preset options so users can immediately analyze high-fidelity binary setups
    enum class PresetBinary {
        SEC_HELPER,       // libnative-sec.so (Anti-debug ptrace checks, dynamic logs)
        LICENSE_VERIFY,   // liblicense-verify.so (Dynamic API strings, base64 tokens)
        PAYLOAD_LOADER    // libpayload-loader.so (Sub-thread spawn, dlopen/dlsym exports)
    }

    // Active UI view state representation
    sealed interface UiState {
        object Idle : UiState
        data class Analyzing(val step: Int, val description: String) : UiState
        data class Success(val result: ElfAnalysisResult) : UiState
        data class Error(val message: String) : UiState
    }

    private val _uiState = MutableStateFlow<UiState>(UiState.Idle)
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    // Active Selected Tab index
    private val _selectedTabIndex = MutableStateFlow(1) // Default: Disassembly
    val selectedTabIndex: StateFlow<Int> = _selectedTabIndex.asStateFlow()

    // Sidebar Function Search Query
    private val _functionSearchQuery = MutableStateFlow("")
    val functionSearchQuery: StateFlow<String> = _functionSearchQuery.asStateFlow()

    // Strings Tab Search Query
    private val _stringsSearchQuery = MutableStateFlow("")
    val stringsSearchQuery: StateFlow<String> = _stringsSearchQuery.asStateFlow()

    // Global Filter/Search
    private val _globalSearchQuery = MutableStateFlow("")
    val globalSearchQuery: StateFlow<String> = _globalSearchQuery.asStateFlow()

    // User Custom Session Annotations: Address -> Custom Renamed Name
    private val _renamedSymbols = MutableStateFlow<Map<Long, String>>(emptyMap())
    val renamedSymbols: StateFlow<Map<Long, String>> = _renamedSymbols.asStateFlow()

    // User Custom Inline Notes: Address -> Custom Comment String
    private val _userComments = MutableStateFlow<Map<Long, String>>(emptyMap())
    val userComments: StateFlow<Map<Long, String>> = _userComments.asStateFlow()

    // Bookmarked Addresses (Addresses starred by the user)
    private val _bookmarkedAddresses = MutableStateFlow<Set<Long>>(emptySet())
    val bookmarkedAddresses: StateFlow<Set<Long>> = _bookmarkedAddresses.asStateFlow()

    // Jump / Navigation Call Backstack (IDA Pro-style Back-Forward navigation)
    private val _navigationHistory = MutableStateFlow<List<Long>>(emptyList())
    val navigationHistory: StateFlow<List<Long>> = _navigationHistory.asStateFlow()

    // Selected Instruction / Address range in the disassembler
    private val _selectedAddress = MutableStateFlow<Long?>(null)
    val selectedAddress: StateFlow<Long?> = _selectedAddress.asStateFlow()

    // Currently Selected Hex View Section Index (0 for all bytes, or referencing section index)
    private val _selectedHexSectionIndex = MutableStateFlow<Int>(-1)
    val selectedHexSectionIndex: StateFlow<Int> = _selectedHexSectionIndex.asStateFlow()

    // Raw bytes of currently loaded binary (useful for hex dump mapping)
    private val _rawBytes = MutableStateFlow<ByteArray>(ByteArray(0))
    val rawBytes: StateFlow<ByteArray> = _rawBytes.asStateFlow()

    // Dynamic Strings Min Length slider
    private val _minStringLength = MutableStateFlow(4)
    val minStringLength: StateFlow<Int> = _minStringLength.asStateFlow()

    // Log messages printed to right panel consoling active parse
    private val _consoleLogs = MutableStateFlow<List<AnalysisProgressLog>>(emptyList())
    val consoleLogs: StateFlow<List<AnalysisProgressLog>> = _consoleLogs.asStateFlow()

    init {
        // Automatically load SEC_HELPER preset initially so the app loads with pristine data
        loadPreset(PresetBinary.SEC_HELPER)
    }

    /**
     * Set active tab index
     */
    fun selectTab(index: Int) {
        _selectedTabIndex.value = index
    }

    /**
     * Update search targets
     */
    fun setFunctionSearchQuery(query: String) {
        _functionSearchQuery.value = query
    }

    fun setStringsSearchQuery(query: String) {
        _stringsSearchQuery.value = query
    }

    fun setGlobalSearchQuery(query: String) {
        _globalSearchQuery.value = query
    }

    fun setMinStringLength(len: Int) {
        _minStringLength.value = len
    }

    /**
     * Rename function/symbol
     */
    fun renameSymbol(address: Long, newName: String) {
        val updated = _renamedSymbols.value.toMutableMap()
        if (newName.isBlank()) {
            updated.remove(address)
        } else {
            updated[address] = newName
        }
        _renamedSymbols.value = updated
    }

    /**
     * Add or edit inline assembly comment
     */
    fun addComment(address: Long, comment: String) {
        val updated = _userComments.value.toMutableMap()
        if (comment.isBlank()) {
            updated.remove(address)
        } else {
            updated[address] = comment
        }
        _userComments.value = updated
    }

    /**
     * Toggle address bookmark
     */
    fun toggleBookmark(address: Long) {
        val current = _bookmarkedAddresses.value.toMutableSet()
        if (current.contains(address)) {
            current.remove(address)
        } else {
            current.add(address)
        }
        _bookmarkedAddresses.value = current
    }

    /**
     * Navigate into an instruction address (record to backstack)
     */
    fun navigateToAddress(address: Long) {
        val currentSelected = _selectedAddress.value
        if (currentSelected != null && currentSelected != address) {
            val hist = _navigationHistory.value.toMutableList()
            hist.add(currentSelected)
            _navigationHistory.value = hist
        }

        _selectedAddress.value = address
        // Auto-select Disassembly Tab
        _selectedTabIndex.value = 1
    }

    /**
     * Navigate Back to previous function link (IDA Pro Back arrow)
     */
    fun navigateBack() {
        val hist = _navigationHistory.value.toMutableList()
        if (hist.isNotEmpty()) {
            val prev = hist.removeAt(hist.size - 1)
            _navigationHistory.value = hist
            _selectedAddress.value = prev
        }
    }

    fun setSelectedAddress(addr: Long?) {
        _selectedAddress.value = addr
    }

    fun selectHexSectionIndex(index: Int) {
        _selectedHexSectionIndex.value = index
    }

    /**
     * Load a target preset sandbox binary with progressive step animations
     */
    fun loadPreset(preset: PresetBinary) {
        viewModelScope.launch {
            _uiState.value = UiState.Analyzing(1, "Initializing decompiling processes...")
            _renamedSymbols.value = emptyMap()
            _userComments.value = emptyMap()
            _bookmarkedAddresses.value = emptySet()
            _navigationHistory.value = emptyList()
            _selectedAddress.value = null
            _selectedHexSectionIndex.value = -1

            val dummyBytes = generateHeaderAndSectBytes(preset)
            _rawBytes.value = dummyBytes

            val targetName = when (preset) {
                PresetBinary.SEC_HELPER -> "libnative-sec.so"
                PresetBinary.LICENSE_VERIFY -> "liblicense-verify.so"
                PresetBinary.PAYLOAD_LOADER -> "libpayload-loader.so"
            }

            // Simulate deep decompiling logs step-by-step
            val stepLogs = mutableListOf<AnalysisProgressLog>()
            _consoleLogs.value = stepLogs

            for (i in 1..10) {
                val stepDesc = when (i) {
                    1 -> "ELF magic verification"
                    2 -> "Parsing section tables"
                    3 -> "Checking segments loading offsets"
                    4 -> "Recompiling dynsym references"
                    5 -> "Loading function signatures"
                    6 -> "Extracting strings patterns"
                    7 -> "Generating cross references (XREFs)"
                    8 -> "Detecting dynamic JNI exports"
                    9 -> "Running anti-tamper scans"
                    else -> "Final compilation complete!"
                }
                _uiState.value = UiState.Analyzing(i, stepDesc)
                
                val progressLog = AnalysisProgressLog(
                    step = i,
                    title = "Static Analyzer Step $i",
                    message = stepDesc,
                    timestamp = "Step-$i",
                    isComplete = i < 10
                )
                stepLogs.add(progressLog)
                _consoleLogs.value = stepLogs.toList()
                
                delay(120) // Snappy yet observable sequential load
            }

            // Load high-fidelity analytical results matching requested themes
            val baseResult = when (preset) {
                PresetBinary.SEC_HELPER -> ElfParser.getHighFidelityMockResult("libnative-sec.so")
                PresetBinary.LICENSE_VERIFY -> getLicenseVerifyResult()
                PresetBinary.PAYLOAD_LOADER -> getPayloadLoaderResult()
            }

            _uiState.value = UiState.Success(baseResult)
        }
    }

    /**
     * Load uploaded binary file picked in Compose
     */
    fun loadSelectedFile(context: Context, uri: Uri) {
        viewModelScope.launch {
            _uiState.value = UiState.Analyzing(1, "Staging data streams...")
            _renamedSymbols.value = emptyMap()
            _userComments.value = emptyMap()
            _bookmarkedAddresses.value = emptySet()
            _navigationHistory.value = emptyList()
            _selectedAddress.value = null
            _selectedHexSectionIndex.value = -1

            val systemName = getFileName(context, uri) ?: "imported_binary.so"

            try {
                val contentBytes = withContext(Dispatchers.IO) {
                    readUriBytes(context, uri)
                }

                if (contentBytes == null || contentBytes.isEmpty()) {
                    _uiState.value = UiState.Error("Selected file stream was empty or unreadable.")
                    return@launch
                }

                _rawBytes.value = contentBytes

                // Perform core ELF parsing
                val parseResult = withContext(Dispatchers.Default) {
                    ElfParser.parseElf(contentBytes, systemName)
                }

                _consoleLogs.value = parseResult.logs
                _uiState.value = UiState.Success(parseResult)

            } catch (e: Exception) {
                _uiState.value = UiState.Error("Low level exception resolving ELF bytes: ${e.message}")
            }
        }
    }

    private fun getFileName(context: Context, uri: Uri): String? {
        var name: String? = null
        try {
            val cursor = context.contentResolver.query(uri, null, null, null, null)
            cursor?.use {
                if (it.moveToFirst()) {
                    val index = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                    if (index >= 0) name = it.getString(index)
                }
            }
        } catch (_: Exception) {}
        if (name == null) {
            name = uri.path?.substringAfterLast('/')
        }
        return name
    }

    private fun readUriBytes(context: Context, uri: Uri): ByteArray? {
        var inputStream: InputStream? = null
        try {
            inputStream = context.contentResolver.openInputStream(uri)
            val byteBuffer = ByteArrayOutputStream()
            val bufferSize = 4096
            val buffer = ByteArray(bufferSize)
            var len: Int
            if (inputStream != null) {
                while (inputStream.read(buffer).also { len = it } != -1) {
                    byteBuffer.write(buffer, 0, len)
                }
                return byteBuffer.toByteArray()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {
            inputStream?.close()
        }
        return null
    }

    // Generate dummy array blocks prefixing ELF magic strings to mimic binary headers
    private fun generateHeaderAndSectBytes(preset: PresetBinary): ByteArray {
        val dummy = ByteArray(4096)
        dummy[0] = 0x7F.toByte()
        dummy[1] = 'E'.toByte()
        dummy[2] = 'L'.toByte()
        dummy[3] = 'F'.toByte()
        dummy[4] = 2.toByte() // 64-bit
        dummy[5] = 1.toByte() // Little endian
        // Fill remainder with arbitrary bytes to allow hex dump browsing
        for (i in 6 until 4096) {
            dummy[i] = ((i * 37) xor 0xA3).toByte()
        }
        return dummy
    }

    // Setup license checker simulator results
    private fun getLicenseVerifyResult(): ElfAnalysisResult {
        val logs = mutableListOf<AnalysisProgressLog>()
        fun addLog(title: String, msg: String) {
            logs.add(AnalysisProgressLog(logs.size + 1, title, msg, "Now"))
        }
        addLog("Initialization", "Resolving dynamic targets for liblicense-verify.so")
        addLog("Symbols resolved", "Parsed 9 symbols in relocatable dynamic streams")

        val header = ElfHeader("7F 45 4C 46", "ELF64", "Little Endian", "Linux System V", "Dynamic DLL", "AArch64", 0x2280L, 64, 189410, 0, 64, 7, 16, 15)
        
        val sections = listOf(
            SectionHeader(1, ".plt", "SHT_PROGBITS", "AX", 6, 0x1000, 0x1000, 0x200, 0, 0, 8, 16),
            SectionHeader(2, ".text", "SHT_PROGBITS", "AX", 6, 0x1200, 0x1200, 0x1B00, 0, 0, 16, 0),
            SectionHeader(3, ".rodata", "SHT_PROGBITS", "A", 2, 0x3000, 0x3000, 0x800, 0, 0, 8, 0),
            SectionHeader(4, ".data", "SHT_PROGBITS", "WA", 3, 0x4000, 0x4000, 0x100, 0, 0, 8, 0)
        )

        val programHeaders = listOf(
            ProgramHeader("PT_PHDR", 64, 0x40, 0x40, 224, 224, "R", 8),
            ProgramHeader("PT_LOAD", 0, 0x0, 0x0, 12000, 12000, "R E", 4096)
        )

        val dynamicItems = listOf(
            DynamicItem("DT_NEEDED", "libdl.so", "Load dynamic linker interface"),
            DynamicItem("DT_SONAME", "liblicense-verify.so", "Dynamic Identity")
        )

        val symbols = listOf(
            ElfSymbol(0, 0x0, "strcmp", "strcmp", 0, SymbolType.FUNC, SymbolBinding.GLOBAL, "UNDEF", false, true, false),
            ElfSymbol(1, 0x0, "android_dlopen_ext", "android_dlopen_ext", 0, SymbolType.FUNC, SymbolBinding.GLOBAL, "UNDEF", false, true, false),
            ElfSymbol(2, 0x1200, "Java_com_example_MainActivity_verifyCustomLicense", "Java_com_example_MainActivity_verifyCustomLicense", 340, SymbolType.FUNC, SymbolBinding.GLOBAL, ".text", true, false, true, "com.example.MainActivity", "verifyCustomLicense"),
            ElfSymbol(3, 0x1380, "crypt_key_sha", "crypt_key_sha", 120, SymbolType.FUNC, SymbolBinding.LOCAL, ".text", false, false, false),
            ElfSymbol(4, 0x14F0, "generate_token", "generate_token", 180, SymbolType.FUNC, SymbolBinding.LOCAL, ".text", false, false, false)
        )

        val strings = listOf(
            ExtractedString(0x3010, "license_verified_status_ok", 26, ".rodata", false),
            ExtractedString(0x3030, "MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDZ", 40, ".rodata", true, "Base64 Obfuscated Token"),
            ExtractedString(0x3070, "https://license.server-internal.io/api/activate", 48, ".rodata", true, "Outbound API / Live URL Endpoint"),
            ExtractedString(0x3100, "SECRET_XOR_KEY_2026", 19, ".rodata", true, "Hardcoded Key / API Secrets")
        )

        val instructions = listOf(
            Instruction(0x1200, byteArrayOf(0xfd.toByte(), 0x7b.toByte(), 0xbf.toByte(), 0xa9.toByte()), "STP", "X29, X30, [SP, #-16]!", userComment = "Setup frame pointer", isCall = false, isBranch = false),
            Instruction(0x1204, byteArrayOf(0x00.toByte(), 0x30.toByte(), 0x80.toByte(), 0xd2.toByte()), "MOV", "X0, #0x3000", userComment = "Local encryption base pointer offset"),
            Instruction(0x1208, byteArrayOf(0xa2.toByte(), 0x10.toByte(), 0xc2.toByte(), 0x94.toByte()), "BL", "crypt_key_sha", userComment = "Execute dynamic salt check", isCall = true, isBranch = true, targetAddress = 0x1380L, xrefs = emptyList()),
            Instruction(0x120C, byteArrayOf(0xa1.toByte(), 0x15.toByte(), 0x40.toByte(), 0xf9.toByte()), "LDR", "X1, [X0, #40]", userComment = "Load server url from .rodata index"),
            Instruction(0x1210, byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x94.toByte()), "BL", "strcmp", userComment = "Verify dynamic inputs", isCall = true, isBranch = true, targetAddress = 0L),
            Instruction(0x1214, byteArrayOf(0xfd.toByte(), 0x7b.toByte(), 0xc1.toByte(), 0xa8.toByte()), "LDP", "X29, X30, [SP], #16"),
            Instruction(0x1218, byteArrayOf(0xc0.toByte(), 0x03.toByte(), 0x5f.toByte(), 0xd6.toByte()), "RET", "")
        )

        val antiFlags = listOf(
            AntiAnalysisFlag(
                category = "INTEGRITY",
                title = "Crypto signature checks",
                description = "High density of hardcoded public key headers, cryptographic hashes, and licenser URLs initialized within static blocks.",
                severity = "HIGH"
            )
        )

        return ElfAnalysisResult("liblicense-verify.so", 128912, "ARM64", header, sections, programHeaders, dynamicItems, symbols, strings, instructions, logs, antiFlags)
    }

    // Setup Payload execution loader simulator results
    private fun getPayloadLoaderResult(): ElfAnalysisResult {
        val logs = mutableListOf<AnalysisProgressLog>()
        fun addLog(title: String, msg: String) {
            logs.add(AnalysisProgressLog(logs.size + 1, title, msg, "Now"))
        }
        addLog("Initialization", "Analyzing libpayload-loader.so dynamic library")
        addLog("JNI Analysis", "Locating registration calls in JNI_OnLoad")

        val header = ElfHeader("7F 45 4C 46", "ELF64", "Little Endian", "Linux System V", "Dynamic DLL", "AArch64", 0x1A00L, 64, 91204, 0, 64, 4, 12, 11)

        val sections = listOf(
            SectionHeader(1, ".plt", "SHT_PROGBITS", "AX", 6, 0x600, 0x600, 0x100, 0, 0, 8, 16),
            SectionHeader(2, ".text", "SHT_PROGBITS", "AX", 6, 0x800, 0x800, 0x2000, 0, 0, 16, 0),
            SectionHeader(3, ".rodata", "SHT_PROGBITS", "A", 2, 0x2800, 0x2800, 0x500, 0, 0, 8, 0)
        )

        val programHeaders = listOf(
            ProgramHeader("PT_LOAD", 0, 0x0, 0x0, 8192, 8192, "R E", 4096)
        )

        val dynamicItems = listOf(
            DynamicItem("DT_NEEDED", "liblog.so", "Android logging helper"),
            DynamicItem("DT_NEEDED", "libdl.so", "Dynamic linker loading helper")
        )

        val symbols = listOf(
            ElfSymbol(0, 0x0, "pthread_create", "pthread_create", 0, SymbolType.FUNC, SymbolBinding.GLOBAL, "UNDEF", false, true, false),
            ElfSymbol(1, 0x0, "dlopen", "dlopen", 0, SymbolType.FUNC, SymbolBinding.GLOBAL, "UNDEF", false, true, false),
            ElfSymbol(2, 0x0, "dlsym", "dlsym", 0, SymbolType.FUNC, SymbolBinding.GLOBAL, "UNDEF", false, true, false),
            ElfSymbol(3, 0x800, "JNI_OnLoad", "JNI_OnLoad", 550, SymbolType.FUNC, SymbolBinding.GLOBAL, ".text", true, false, false),
            ElfSymbol(4, 0xAA0, "background_monitor_routine", "background_monitor_routine", 310, SymbolType.FUNC, SymbolBinding.LOCAL, ".text", false, false, false)
        )

        val strings = listOf(
            ExtractedString(0x2850, "pthread_create", 14, ".rodata", false),
            ExtractedString(0x2870, "/data/data/com.example/app_decrypted.dex", 41, ".rodata", true, "Dynamic Loading / Sandbox Check"),
            ExtractedString(0x28C0, "dlopen", 6, ".rodata", false),
            ExtractedString(0x28CE, "dlsym", 5, ".rodata", false)
        )

        val instructions = listOf(
            Instruction(0x800, byteArrayOf(0xfd.toByte(), 0x7b.toByte(), 0xbf.toByte(), 0xa9.toByte()), "STP", "X29, X30, [SP, #-16]!", userComment = "Setup frame pointer", isCall = false, isBranch = false),
            Instruction(0x804, byteArrayOf(0x01.toByte(), 0x00.toByte(), 0x80.toByte(), 0xd2.toByte()), "MOV", "X1, 0xAA0", userComment = "Target function routine callback"),
            Instruction(0x808, byteArrayOf(0x1a.toByte(), 0x22.toByte(), 0xc2.toByte(), 0x94.toByte()), "BL", "pthread_create", userComment = "Launch background monitor threads!", isCall = true, isBranch = true, targetAddress = 0L),
            Instruction(0x80C, byteArrayOf(0x00.toByte(), 0x02.toByte(), 0x80.toByte(), 0xd2.toByte()), "MOV", "X0, #0x10006", userComment = "JNI version check return code"),
            Instruction(0x810, byteArrayOf(0xfd.toByte(), 0x7b.toByte(), 0xc1.toByte(), 0xa8.toByte()), "LDP", "X29, X30, [SP], #16"),
            Instruction(0x814, byteArrayOf(0xc0.toByte(), 0x03.toByte(), 0x5f.toByte(), 0xd6.toByte()), "RET", "")
        )

        val antiFlags = listOf(
            AntiAnalysisFlag(
                category = "INJECTION",
                title = "Early Thread Injection",
                description = "Binary spawns persistent pthread instances in JNI initialization loops. Likely running continuous device rooting / monitor scans.",
                severity = "HIGH"
            ),
            AntiAnalysisFlag(
                category = "OBFUSCATION",
                title = "Dynamic Code Parsing Check",
                description = "Explicit dlsym/dlopen operations loaded alongside decrypted .dex system strings targeting writable local secure sandbox paths.",
                severity = "CRITICAL"
            )
        )

        return ElfAnalysisResult("libpayload-loader.so", 94101, "ARM64", header, sections, programHeaders, dynamicItems, symbols, strings, instructions, logs, antiFlags)
    }
}
