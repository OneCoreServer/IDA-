package com.example.ui

import android.content.Context
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.model.*
import com.example.viewmodel.SoAnalyzerViewModel
import com.example.viewmodel.SoAnalyzerViewModel.UiState
import kotlinx.coroutines.launch

// Color Definitions (IDA Pro-style theme matching specs)
val ColorDarkBg = Color(0xFF0D1117)
val ColorPanelBg = Color(0xFF161B22)
val ColorBorder = Color(0xFF30363D)
val ColorAccentPrimary = Color(0xFF58A6FF)
val ColorAccentSecondary = Color(0xFF1F6FEB)
val ColorExportGreen = Color(0xFF4EC9B0)
val ColorImportOrange = Color(0xFFCE9178)
val ColorLocalBlue = Color(0xFF9CDCFE)
val ColorStringYellow = Color(0xFFE3B341)
val ColorDangerRed = Color(0xFFF97583)
val ColorCommentGreen = Color(0xFF6E9A50)
val ColorTextMuted = Color(0xFF8B949E)
val ColorTextLight = Color(0xFFC9D1D9)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SoAnalyzerApp(viewModel: SoAnalyzerViewModel) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val configuration = LocalConfiguration.current
    val isTablet = configuration.screenWidthDp >= 800

    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val rawBytes by viewModel.rawBytes.collectAsStateWithLifecycle()
    val selectedTabIndex by viewModel.selectedTabIndex.collectAsStateWithLifecycle()

    val renamedSymbols by viewModel.renamedSymbols.collectAsStateWithLifecycle()
    val userComments by viewModel.userComments.collectAsStateWithLifecycle()
    val bookmarkedAddresses by viewModel.bookmarkedAddresses.collectAsStateWithLifecycle()
    val navigationHistory by viewModel.navigationHistory.collectAsStateWithLifecycle()
    val selectedAddress by viewModel.selectedAddress.collectAsStateWithLifecycle()

    val functionSearchQuery by viewModel.functionSearchQuery.collectAsStateWithLifecycle()
    val stringsSearchQuery by viewModel.stringsSearchQuery.collectAsStateWithLifecycle()
    val globalSearchQuery by viewModel.globalSearchQuery.collectAsStateWithLifecycle()
    val minStringLength by viewModel.minStringLength.collectAsStateWithLifecycle()
    val consoleLogs by viewModel.consoleLogs.collectAsStateWithLifecycle()

    var showPresetMenu by remember { mutableStateOf(false) }
    var activeRenameAddr by remember { mutableStateOf<Long?>(null) }
    var renameInputText by remember { mutableStateOf("") }
    var activeCommentAddr by remember { mutableStateOf<Long?>(null) }
    var commentInputText by remember { mutableStateOf("") }
    var showMobileSymbolDrawer by remember { mutableStateOf(false) }

    // File picker launcher
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri ->
        uri?.let {
            viewModel.loadSelectedFile(context, it)
        }
    }

    Scaffold(
        modifier = Modifier
            .fillMaxSize()
            .background(ColorDarkBg)
            .statusBarsPadding(),
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = ColorPanelBg,
                    titleContentColor = ColorTextLight
                ),
                title = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        // Custom premium SO badge matching the HTML spec
                        Box(
                            modifier = Modifier
                                .size(32.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(ColorAccentSecondary),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "SO",
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Color.White
                            )
                        }
                        Column {
                            Text(
                                text = "SoAnalyzer",
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Color.White
                            )
                            val subtitleText = when (val progressState = uiState) {
                                is UiState.Success -> "${progressState.result.fileName} (${progressState.result.architecture})"
                                is UiState.Analyzing -> "Analyzing Binary..."
                                is UiState.Error -> "Analysis Failed"
                                else -> "v1.1-MultiArch ELF"
                            }
                            Text(
                                text = subtitleText,
                                fontSize = 10.sp,
                                color = ColorTextMuted,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                },
                actions = {
                    // Back arrow for jumping navigation history
                    if (navigationHistory.isNotEmpty()) {
                        IconButton(
                            onClick = { viewModel.navigateBack() },
                            modifier = Modifier.testTag("nav_back_button")
                        ) {
                            Icon(
                                imageVector = Icons.Default.ArrowBack,
                                contentDescription = "Go back",
                                tint = ColorAccentPrimary
                            )
                        }
                    }

                    // Open Binary dropdown presets
                    Box {
                        Button(
                            onClick = { showPresetMenu = true },
                            colors = ButtonDefaults.buttonColors(containerColor = ColorAccentSecondary),
                            shape = RoundedCornerShape(4.dp),
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                            modifier = Modifier
                                .padding(end = 8.dp)
                                .testTag("presets_button")
                        ) {
                            Icon(
                                imageVector = Icons.Default.Refresh,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Mock Targets", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                        DropdownMenu(
                            expanded = showPresetMenu,
                            onDismissRequest = { showPresetMenu = false },
                            modifier = Modifier.background(ColorPanelBg)
                        ) {
                            DropdownMenuItem(
                                text = { Text("libnative-sec.so (Anti-Debug)", color = ColorTextLight) },
                                onClick = {
                                    viewModel.loadPreset(SoAnalyzerViewModel.PresetBinary.SEC_HELPER)
                                    showPresetMenu = false
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("liblicense-verify.so (Crypto Checks)", color = ColorTextLight) },
                                onClick = {
                                    viewModel.loadPreset(SoAnalyzerViewModel.PresetBinary.LICENSE_VERIFY)
                                    showPresetMenu = false
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("libpayload-loader.so (Background injection)", color = ColorTextLight) },
                                onClick = {
                                    viewModel.loadPreset(SoAnalyzerViewModel.PresetBinary.PAYLOAD_LOADER)
                                    showPresetMenu = false
                                }
                            )
                        }
                    }

                    // Open actual file local picker
                    Button(
                        onClick = { filePickerLauncher.launch("*/*") },
                        colors = ButtonDefaults.buttonColors(containerColor = ColorPanelBg),
                        border = BorderStroke(1.dp, ColorBorder),
                        shape = RoundedCornerShape(4.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                        modifier = Modifier
                            .padding(end = 8.dp)
                            .testTag("upload_so_button")
                    ) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = "Upload SO File",
                            modifier = Modifier.size(16.dp),
                            tint = ColorAccentPrimary
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Open .so File", color = ColorTextLight, fontSize = 12.sp)
                    }
                }
            )
        },
        bottomBar = {
            // Interactive Bottom Status Bar (Professional Polish specification)
            val bottomBarColor = when (uiState) {
                is UiState.Success -> ColorAccentSecondary
                is UiState.Analyzing -> ColorStringYellow
                is UiState.Error -> ColorDangerRed
                else -> ColorPanelBg
            }
            val bottomBarTextColor = when (uiState) {
                is UiState.Analyzing -> Color.Black
                else -> Color.White
            }

            Surface(
                color = bottomBarColor,
                modifier = Modifier
                    .fillMaxWidth()
                    .windowInsetsPadding(WindowInsets.navigationBars)
                    .border(BorderStroke(1.dp, ColorBorder)),
                tonalElevation = 4.dp
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    when (val state = uiState) {
                        is UiState.Success -> {
                            val res = state.result
                            val elfType = if (res.architecture.contains("64")) "ELF64" else "ELF32"
                            val funcCount = res.symbols.count { it.type == SymbolType.FUNC }
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(16.dp)
                            ) {
                                Text(
                                    text = elfType,
                                    fontSize = 11.sp,
                                    color = bottomBarTextColor,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace
                                )
                                Text(
                                    text = "FUNC: $funcCount",
                                    fontSize = 11.sp,
                                    color = bottomBarTextColor.copy(alpha = 0.9f),
                                    fontFamily = FontFamily.Monospace
                                )
                                Text(
                                    text = "SEC: ${res.sections.size}",
                                    fontSize = 11.sp,
                                    color = bottomBarTextColor.copy(alpha = 0.9f),
                                    fontFamily = FontFamily.Monospace
                                )
                                Text(
                                    text = "TARGET: ${res.fileName}",
                                    fontSize = 11.sp,
                                    color = bottomBarTextColor.copy(alpha = 0.9f),
                                    fontFamily = FontFamily.Monospace,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                val vaddrText = if (selectedAddress != null) "VADDR: 0x${selectedAddress!!.toString(16).uppercase()}" else "READY"
                                Text(
                                    text = vaddrText,
                                    fontSize = 11.sp,
                                    color = bottomBarTextColor,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                        is UiState.Analyzing -> {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(12.dp),
                                    strokeWidth = 2.dp,
                                    color = bottomBarTextColor
                                )
                                Text(
                                    text = "ANALYSIS IN PROGRESS: [STEP ${state.step}/10] ${state.description}",
                                    fontSize = 11.sp,
                                    color = bottomBarTextColor,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                        is UiState.Error -> {
                            Text(
                                text = "DECOMPILER_FAIL: ${state.message}",
                                fontSize = 11.sp,
                                color = bottomBarTextColor,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        else -> {
                            Text(
                                text = "STBY_DEC: Select custom files or mock targets",
                                fontSize = 11.sp,
                                color = ColorTextMuted,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                }
            }
        }
    ) { innerPadding ->
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            color = ColorDarkBg
        ) {
            when (val state = uiState) {
                is UiState.Idle -> {
                    IntroEmptyState(onPresetSelect = { viewModel.loadPreset(it) })
                }
                is UiState.Error -> {
                    CenteredErrorPanel(
                        message = state.message,
                        onRetry = { viewModel.loadPreset(SoAnalyzerViewModel.PresetBinary.SEC_HELPER) }
                    )
                }
                is UiState.Analyzing -> {
                    CenteredDecompilerLoader(step = state.step, message = state.description)
                }
                is UiState.Success -> {
                    val result = state.result

                    if (isTablet) {
                        // IMMERSIVE MULTI-PANEL VIEW FOR TABLETS (IDA Pro Style)
                        Row(modifier = Modifier.fillMaxSize()) {
                            // Left Panel (240dp) for Function Search and Badging details
                            Box(
                                modifier = Modifier
                                    .width(260.dp)
                                    .fillMaxHeight()
                                    .background(ColorPanelBg)
                                    .border(BorderStroke(1.dp, ColorBorder))
                            ) {
                                LeftSymbolsPanel(
                                    symbols = result.symbols,
                                    renamedSymbols = renamedSymbols,
                                    searchQuery = functionSearchQuery,
                                    onSearchChange = { viewModel.setFunctionSearchQuery(it) },
                                    onSymbolSelected = { sym ->
                                        viewModel.navigateToAddress(sym.address)
                                    },
                                    onSymbolRenameRequest = { sym ->
                                        activeRenameAddr = sym.address
                                        renameInputText = renamedSymbols[sym.address] ?: sym.originName
                                    }
                                )
                            }

                            // Center Panel for detailed Tab items
                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .fillMaxHeight()
                                    .border(BorderStroke(1.dp, ColorBorder))
                            ) {
                                CenterTabbedPanel(
                                    result = result,
                                    rawBytes = rawBytes,
                                    selectedTabIndex = selectedTabIndex,
                                    onTabSelect = { viewModel.selectTab(it) },
                                    selectedAddress = selectedAddress,
                                    onAddressSelected = { viewModel.navigateToAddress(it) },
                                    onCommentEditRequest = { addr, txt ->
                                        activeCommentAddr = addr
                                        commentInputText = txt
                                    },
                                    onBookmarkToggle = { viewModel.toggleBookmark(it) },
                                    renamedSymbols = renamedSymbols,
                                    userComments = userComments,
                                    bookmarkedAddresses = bookmarkedAddresses,
                                    stringsSearchQuery = stringsSearchQuery,
                                    onStringSearchQueryChange = { viewModel.setStringsSearchQuery(it) },
                                    globalSearchQuery = globalSearchQuery,
                                    onGlobalSearchQueryChange = { viewModel.setGlobalSearchQuery(it) },
                                    minStringLength = minStringLength,
                                    onMinStringLengthChange = { viewModel.setMinStringLength(it) },
                                    selectedHexSecIndex = viewModel.selectedHexSectionIndex.collectAsStateWithLifecycle().value,
                                    onHexSecIndexSelected = { viewModel.selectHexSectionIndex(it) },
                                    onSectionDetailsTap = { sec ->
                                        // Auto scroll hex target
                                        val idx = result.sections.indexOf(sec)
                                        viewModel.selectHexSectionIndex(idx)
                                        viewModel.selectTab(4) // Open Hex tab
                                    }
                                )
                            }

                            // Right Panel (220dp) for Scanned issues/Anti-debug reports and console warnings
                            Box(
                                modifier = Modifier
                                    .width(220.dp)
                                    .fillMaxHeight()
                                    .background(ColorPanelBg)
                                    .border(BorderStroke(1.dp, ColorBorder))
                            ) {
                                RightScannerPanel(
                                    flags = result.antiAnalysisFlags,
                                    logs = consoleLogs
                                )
                            }
                        }
                    } else {
                        // ADAPTIVE PORTRAIT SMARTPHONE VIEW WITH BOTTOM SHEET NAVS
                        Column(modifier = Modifier.fillMaxSize()) {
                            // Quick Action Header to Search Symbols Drawer
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(ColorPanelBg)
                                    .padding(horizontal = 12.dp, vertical = 6.dp)
                                    .border(BorderStroke(1.dp, ColorBorder)),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    modifier = Modifier.clickable { showMobileSymbolDrawer = true }
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.List,
                                        contentDescription = "Symbols",
                                        tint = ColorAccentPrimary
                                    )
                                    Text(
                                        text = "Lookup Functions (${result.symbols.count { it.type == SymbolType.FUNC }})",
                                        color = ColorAccentPrimary,
                                        fontSize = 13.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                                if (result.antiAnalysisFlags.isNotEmpty()) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(4.dp))
                                            .background(ColorDangerRed.copy(alpha = 0.2f))
                                            .padding(horizontal = 8.dp, vertical = 4.dp)
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.Warning,
                                            contentDescription = "Threat flags",
                                            tint = ColorDangerRed,
                                            modifier = Modifier.size(14.dp)
                                        )
                                        Text(
                                            text = "${result.antiAnalysisFlags.size} Threats",
                                            color = ColorDangerRed,
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }
                            }

                            // Tabs list
                            CenterTabbedPanel(
                                result = result,
                                rawBytes = rawBytes,
                                selectedTabIndex = selectedTabIndex,
                                onTabSelect = { viewModel.selectTab(it) },
                                selectedAddress = selectedAddress,
                                onAddressSelected = { viewModel.navigateToAddress(it) },
                                onCommentEditRequest = { addr, txt ->
                                    activeCommentAddr = addr
                                    commentInputText = txt
                                },
                                onBookmarkToggle = { viewModel.toggleBookmark(it) },
                                renamedSymbols = renamedSymbols,
                                userComments = userComments,
                                bookmarkedAddresses = bookmarkedAddresses,
                                stringsSearchQuery = stringsSearchQuery,
                                onStringSearchQueryChange = { viewModel.setStringsSearchQuery(it) },
                                globalSearchQuery = globalSearchQuery,
                                onGlobalSearchQueryChange = { viewModel.setGlobalSearchQuery(it) },
                                minStringLength = minStringLength,
                                onMinStringLengthChange = { viewModel.setMinStringLength(it) },
                                selectedHexSecIndex = viewModel.selectedHexSectionIndex.collectAsStateWithLifecycle().value,
                                onHexSecIndexSelected = { viewModel.selectHexSectionIndex(it) },
                                onSectionDetailsTap = { sec ->
                                    val idx = result.sections.indexOf(sec)
                                    viewModel.selectHexSectionIndex(idx)
                                    viewModel.selectTab(4) // Open Hex tab
                                }
                            )
                        }

                        // Bottom Dialog for Symbols lookup sheet on Compact mobile sizes
                        if (showMobileSymbolDrawer) {
                            Dialog(onDismissRequest = { showMobileSymbolDrawer = false }) {
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth(0.95f)
                                        .fillMaxHeight(0.85f)
                                        .clip(RoundedCornerShape(8.dp))
                                        .background(ColorPanelBg)
                                        .border(BorderStroke(1.dp, ColorBorder))
                                        .padding(12.dp)
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = "Binary Exported Symbols",
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold,
                                            color = Color.White,
                                            fontSize = 15.sp
                                        )
                                        IconButton(onClick = { showMobileSymbolDrawer = false }) {
                                            Icon(
                                                imageVector = Icons.Default.Clear,
                                                contentDescription = "Close drawer",
                                                tint = ColorTextMuted
                                            )
                                        }
                                    }
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Box(modifier = Modifier.weight(1f)) {
                                        LeftSymbolsPanel(
                                            symbols = result.symbols,
                                            renamedSymbols = renamedSymbols,
                                            searchQuery = functionSearchQuery,
                                            onSearchChange = { viewModel.setFunctionSearchQuery(it) },
                                            onSymbolSelected = { sym ->
                                                viewModel.navigateToAddress(sym.address)
                                                showMobileSymbolDrawer = false
                                            },
                                            onSymbolRenameRequest = { sym ->
                                                activeRenameAddr = sym.address
                                                renameInputText = renamedSymbols[sym.address] ?: sym.originName
                                            }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Modal dialogue for renaming symbols
    if (activeRenameAddr != null) {
        Dialog(onDismissRequest = { activeRenameAddr = null }) {
            Surface(
                color = ColorPanelBg,
                shape = RoundedCornerShape(8.dp),
                border = BorderStroke(1.dp, ColorBorder),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("rename_dialog")
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "Rename Entry Target",
                        fontWeight = FontWeight.Bold,
                        color = ColorAccentPrimary,
                        fontSize = 16.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = "Changing virtual table labels at address 0x${activeRenameAddr!!.toString(16).uppercase()}:",
                        color = ColorTextMuted,
                        fontSize = 12.sp
                    )
                    OutlinedTextField(
                        value = renameInputText,
                        onValueChange = { renameInputText = it },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("rename_input_field"),
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = ColorAccentPrimary,
                            unfocusedBorderColor = ColorBorder,
                            focusedTextColor = Color.White,
                            unfocusedTextColor = ColorTextLight
                        ),
                        placeholder = { Text("sub_1D10...", color = ColorTextMuted) }
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        TextButton(
                            onClick = { activeRenameAddr = null },
                            colors = ButtonDefaults.textButtonColors(contentColor = ColorTextMuted)
                        ) {
                            Text("Cancel")
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = {
                                viewModel.renameSymbol(activeRenameAddr!!, renameInputText)
                                activeRenameAddr = null
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = ColorAccentSecondary),
                            modifier = Modifier.testTag("confirm_rename_button")
                        ) {
                            Text("Apply Refactoring")
                        }
                    }
                }
            }
        }
    }

    // Modal dialogue for adding inline comments
    if (activeCommentAddr != null) {
        Dialog(onDismissRequest = { activeCommentAddr = null }) {
            Surface(
                color = ColorPanelBg,
                shape = RoundedCornerShape(8.dp),
                border = BorderStroke(1.dp, ColorBorder),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("comment_dialog")
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(11.dp)
                ) {
                    Text(
                        text = "Edit Inline Annotation",
                        fontWeight = FontWeight.Bold,
                        color = ColorAccentPrimary,
                        fontSize = 16.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = "Inline notes for assembly register at 0x${activeCommentAddr!!.toString(16).uppercase()}:",
                        color = ColorTextMuted,
                        fontSize = 12.sp
                    )
                    OutlinedTextField(
                        value = commentInputText,
                        onValueChange = { commentInputText = it },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("comment_input_field"),
                        maxLines = 3,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = ColorAccentPrimary,
                            unfocusedBorderColor = ColorBorder,
                            focusedTextColor = Color.White,
                            unfocusedTextColor = ColorTextLight
                        ),
                        placeholder = { Text("ptrace sandbox bypass checks...", color = ColorTextMuted) }
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        TextButton(
                            onClick = { activeCommentAddr = null },
                            colors = ButtonDefaults.textButtonColors(contentColor = ColorTextMuted)
                        ) {
                            Text("Discard")
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = {
                                viewModel.addComment(activeCommentAddr!!, commentInputText)
                                activeCommentAddr = null
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = ColorAccentSecondary),
                            modifier = Modifier.testTag("confirm_comment_button")
                        ) {
                            Text("Save Comment")
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun IntroEmptyState(onPresetSelect: (SoAnalyzerViewModel.PresetBinary) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.Info,
            contentDescription = null,
            tint = ColorAccentPrimary.copy(alpha = 0.5f),
            modifier = Modifier.size(72.dp)
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = "Welcome to SoAnalyzer",
            color = Color.White,
            fontWeight = FontWeight.Bold,
            fontSize = 22.sp,
            fontFamily = FontFamily.Monospace
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "An IDA Pro-style reverse engineering utility built specifically for Android .so (ELF shared libraries) files static-analysis diagnostics.",
            color = ColorTextMuted,
            fontSize = 13.sp,
            modifier = Modifier.fillMaxWidth(0.9f)
        )
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = "ACTIVATE A DIAGNOSTIC SANDBOX TARGET BELOW:",
            color = ColorStringYellow,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace
        )
        Spacer(modifier = Modifier.height(12.dp))

        // Large Quick select cards
        Card(
            modifier = Modifier
                .fillMaxWidth(0.9f)
                .clickable { onPresetSelect(SoAnalyzerViewModel.PresetBinary.SEC_HELPER) },
            colors = CardDefaults.cardColors(containerColor = ColorPanelBg),
            border = BorderStroke(1.dp, ColorBorder)
        ) {
            Row(
                modifier = Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(RoundedCornerShape(4.dp))
                        .background(ColorDangerRed.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(imageVector = Icons.Default.Lock, contentDescription = null, tint = ColorDangerRed)
                }
                Column {
                    Text("libnative-sec.so (Anti-Debug Sandbox)", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Text("Decompile root detection bypass modules, hook structures, and ptrace security segments.", color = ColorTextMuted, fontSize = 11.sp)
                }
            }
        }
        Spacer(modifier = Modifier.height(12.dp))

        Card(
            modifier = Modifier
                .fillMaxWidth(0.9f)
                .clickable { onPresetSelect(SoAnalyzerViewModel.PresetBinary.LICENSE_VERIFY) },
            colors = CardDefaults.cardColors(containerColor = ColorPanelBg),
            border = BorderStroke(1.dp, ColorBorder)
        ) {
            Row(
                modifier = Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(RoundedCornerShape(4.dp))
                        .background(ColorExportGreen.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(imageVector = Icons.Default.Check, contentDescription = null, tint = ColorExportGreen)
                }
                Column {
                    Text("liblicense-verify.so (Crypto Checks)", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Text("Inspect cryptographic SHA headers, server verification strcmp and licensing checks.", color = ColorTextMuted, fontSize = 11.sp)
                }
            }
        }
        Spacer(modifier = Modifier.height(12.dp))

        Card(
            modifier = Modifier
                .fillMaxWidth(0.9f)
                .clickable { onPresetSelect(SoAnalyzerViewModel.PresetBinary.PAYLOAD_LOADER) },
            colors = CardDefaults.cardColors(containerColor = ColorPanelBg),
            border = BorderStroke(1.dp, ColorBorder)
        ) {
            Row(
                modifier = Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(RoundedCornerShape(4.dp))
                        .background(ColorAccentPrimary.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(imageVector = Icons.Default.Notifications, contentDescription = null, tint = ColorAccentPrimary)
                }
                Column {
                    Text("libpayload-loader.so (Background threads)", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Text("Analyze dynamic linkage classes loading subroutines via dlsym and pthread threads launcher.", color = ColorTextMuted, fontSize = 11.sp)
                }
            }
        }
    }
}

@Composable
fun CenteredErrorPanel(message: String, onRetry: () -> Unit) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.padding(24.dp)
        ) {
            Icon(
                imageVector = Icons.Default.Warning,
                contentDescription = null,
                tint = ColorDangerRed,
                modifier = Modifier.size(56.dp)
            )
            Text("Parser Processing Failed", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
            Text(message, color = ColorTextMuted, fontSize = 12.sp)
            Button(
                onClick = onRetry,
                colors = ButtonDefaults.buttonColors(containerColor = ColorAccentSecondary)
            ) {
                Text("Retry Default Target")
            }
        }
    }
}

@Composable
fun CenteredDecompilerLoader(step: Int, message: String) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            CircularProgressIndicator(
                color = ColorAccentPrimary,
                modifier = Modifier.size(48.dp)
            )
            Text(
                text = "DISASSEMBLING ELF SEGMENTS...",
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                color = Color.White,
                fontSize = 13.sp
            )
            Text(
                text = "Decompiler working | Step $step of 10\n$message",
                fontSize = 12.sp,
                color = ColorAccentPrimary,
                fontFamily = FontFamily.Monospace
            )
        }
    }
}

@Composable
fun LeftSymbolsPanel(
    symbols: List<ElfSymbol>,
    renamedSymbols: Map<Long, String>,
    searchQuery: String,
    onSearchChange: (String) -> Unit,
    onSymbolSelected: (ElfSymbol) -> Unit,
    onSymbolRenameRequest: (ElfSymbol) -> Unit
) {
    val filtered = remember(symbols, renamedSymbols, searchQuery) {
        symbols.filter { sym ->
            val activeName = renamedSymbols[sym.address] ?: sym.name
            sym.type == SymbolType.FUNC && (
                activeName.contains(searchQuery, ignoreCase = true) ||
                sym.address.toString(16).uppercase().contains(searchQuery, ignoreCase = true)
            )
        }.sortedBy { it.address }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // Search headers
        OutlinedTextField(
            value = searchQuery,
            onValueChange = onSearchChange,
            modifier = Modifier
                .fillMaxWidth()
                .padding(8.dp)
                .testTag("function_search_field"),
            singleLine = true,
            placeholder = { Text("Filter functions...", fontSize = 11.sp, color = ColorTextMuted) },
            leadingIcon = { Icon(imageVector = Icons.Default.Search, contentDescription = null, tint = ColorTextMuted, modifier = Modifier.size(16.dp)) },
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = ColorDarkBg,
                unfocusedContainerColor = ColorDarkBg,
                focusedBorderColor = ColorAccentPrimary,
                unfocusedBorderColor = ColorBorder,
                focusedTextColor = Color.White,
                unfocusedTextColor = ColorTextLight
            )
        )

        Divider(color = ColorBorder)

        Text(
            text = "FUNCTIONS (${filtered.size})",
            color = ColorTextMuted,
            fontWeight = FontWeight.Bold,
            fontSize = 10.sp,
            modifier = Modifier.padding(start = 12.dp, top = 8.dp, bottom = 4.dp),
            fontFamily = FontFamily.Monospace
        )

        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .testTag("functions_list")
        ) {
            items(filtered) { sym ->
                val renamed = renamedSymbols[sym.address]
                val displayedName = renamed ?: sym.name

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onSymbolSelected(sym) }
                        .padding(horizontal = 8.dp, vertical = 6.dp)
                        .testTag("symbol_item_${sym.address}"),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Symbol Binding identifier Badge color
                    val badgeColor = when {
                        sym.isJni -> ColorExportGreen
                        sym.isExport -> ColorExportGreen
                        sym.isImport -> ColorImportOrange
                        else -> ColorLocalBlue
                    }
                    val badgeTxt = when {
                        sym.isJni -> "JNI"
                        sym.isExport -> "EXP"
                        sym.isImport -> "IMP"
                        else -> "LOC"
                    }

                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(2.dp))
                            .background(badgeColor.copy(alpha = 0.2f))
                            .border(BorderStroke(0.5.dp, badgeColor))
                            .padding(horizontal = 4.dp, vertical = 1.dp)
                    ) {
                        Text(
                            text = badgeTxt,
                            color = badgeColor,
                            fontSize = 8.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    Spacer(modifier = Modifier.width(6.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = displayedName,
                            color = if (renamed != null) ColorStringYellow else ColorTextLight,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = "0x" + sym.address.toString(16).uppercase(),
                                color = ColorTextMuted,
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace
                            )
                            if (sym.size > 0) {
                                Text(
                                    text = "(${sym.size}b)",
                                    color = ColorTextMuted,
                                    fontSize = 9.sp,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                    }

                    // Rename action button
                    IconButton(
                        onClick = { onSymbolRenameRequest(sym) },
                        modifier = Modifier
                            .size(24.dp)
                            .testTag("rename_button_${sym.address}")
                    ) {
                        Icon(
                            imageVector = Icons.Default.Edit,
                            contentDescription = "Rename",
                            tint = ColorTextMuted,
                            modifier = Modifier.size(12.dp)
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun CenterTabbedPanel(
    result: ElfAnalysisResult,
    rawBytes: ByteArray,
    selectedTabIndex: Int,
    onTabSelect: (Int) -> Unit,
    selectedAddress: Long?,
    onAddressSelected: (Long) -> Unit,
    onCommentEditRequest: (Long, String) -> Unit,
    onBookmarkToggle: (Long) -> Unit,
    renamedSymbols: Map<Long, String>,
    userComments: Map<Long, String>,
    bookmarkedAddresses: Set<Long>,
    stringsSearchQuery: String,
    onStringSearchQueryChange: (String) -> Unit,
    globalSearchQuery: String,
    onGlobalSearchQueryChange: (String) -> Unit,
    minStringLength: Int,
    onMinStringLengthChange: (Int) -> Unit,
    selectedHexSecIndex: Int,
    onHexSecIndexSelected: (Int) -> Unit,
    onSectionDetailsTap: (SectionHeader) -> Unit
) {
    val tabs = listOf("Overview", "Disassembly", "Strings", "Sections", "Hex Viewer", "Imports/Exports")

    Column(modifier = Modifier.fillMaxSize()) {
        ScrollableTabRow(
            selectedTabIndex = selectedTabIndex,
            containerColor = ColorPanelBg,
            contentColor = ColorAccentSecondary,
            edgePadding = 8.dp,
            divider = { Divider(color = ColorBorder) },
            modifier = Modifier.testTag("center_tab_row")
        ) {
            tabs.forEachIndexed { index, title ->
                val isSelected = selectedTabIndex == index
                Tab(
                    selected = isSelected,
                    onClick = { onTabSelect(index) },
                    text = {
                        Text(
                            text = title,
                            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = if (isSelected) Color.White else ColorTextMuted
                        )
                    },
                    modifier = Modifier.testTag("tab_$index")
                )
            }
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .background(ColorDarkBg)
        ) {
            when (selectedTabIndex) {
                0 -> OverviewTab(result = result)
                1 -> DisassemblyTab(
                    instructions = result.instructions,
                    selectedAddress = selectedAddress,
                    onAddressClick = onAddressSelected,
                    onCommentEdit = onCommentEditRequest,
                    onBookmarkToggle = onBookmarkToggle,
                    renamedSymbols = renamedSymbols,
                    userComments = userComments,
                    bookmarkedAddresses = bookmarkedAddresses,
                    symbols = result.symbols
                )
                2 -> StringsTab(
                    extractedStrings = result.extractedStrings,
                    searchQuery = stringsSearchQuery,
                    onSearchQueryChange = onStringSearchQueryChange,
                    minStringLength = minStringLength,
                    onMinStringLengthChange = onMinStringLengthChange
                )
                3 -> SectionsTab(
                    sections = result.sections,
                    onSectionTap = onSectionDetailsTap
                )
                4 -> HexViewerTab(
                    rawBytes = rawBytes,
                    sections = result.sections,
                    selectedIndex = selectedHexSecIndex,
                    onIndexSelected = onHexSecIndexSelected
                )
                5 -> ImportsExportsTab(symbols = result.symbols)
            }
        }
    }
}

@Composable
fun OverviewTab(result: ElfAnalysisResult) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("BINARY METADATA SUMMARY", fontWeight = FontWeight.Bold, color = ColorAccentPrimary, fontSize = 14.sp, fontFamily = FontFamily.Monospace)

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = ColorPanelBg),
            border = BorderStroke(1.dp, ColorBorder)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OverviewRow("Target File Name", result.fileName)
                OverviewRow("File Descriptor Size", "${result.fileSize} Bytes")
                OverviewRow("Binary Format class", result.header.elfClass)
                OverviewRow("Architectural Instruction Set", result.header.machine)
                OverviewRow("Bit Byte Order (Endianness)", result.header.endianness)
                OverviewRow("Application ABI Interface", result.header.osAbi)
                OverviewRow("Virtual Code Entry Point", "0x" + result.header.entryAddress.toString(16).uppercase())
            }
        }

        Text("LOW LEVEL HEADER DATA (e_ident)", fontWeight = FontWeight.Bold, color = ColorAccentPrimary, fontSize = 14.sp, fontFamily = FontFamily.Monospace)
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = ColorPanelBg),
            border = BorderStroke(1.dp, ColorBorder)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OverviewRow("Program headers offset (e_phoff)", "0x" + result.header.programHeaderOffset.toString(16).uppercase() + " (${result.header.programHeaderNum} segments)")
                OverviewRow("Section headers offset (e_shoff)", "0x" + result.header.sectionHeaderOffset.toString(16).uppercase() + " (${result.header.sectionHeaderNum} divisions)")
                OverviewRow("Platform Header size", "${result.header.headerSize} bytes")
                OverviewRow("Dynamic link libraries (DT_SONAME)", result.dynamicItems.find { it.tag == "DT_SONAME" }?.value ?: "unresolvable")
            }
        }
    }
}

@Composable
fun OverviewRow(title: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(title, color = ColorTextMuted, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
        Text(value, color = Color.White, fontSize = 12.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
    }
}

@Composable
fun DisassemblyTab(
    instructions: List<Instruction>,
    selectedAddress: Long?,
    onAddressClick: (Long) -> Unit,
    onCommentEdit: (Long, String) -> Unit,
    onBookmarkToggle: (Long) -> Unit,
    renamedSymbols: Map<Long, String>,
    userComments: Map<Long, String>,
    bookmarkedAddresses: Set<Long>,
    symbols: List<ElfSymbol>
) {
    val listState = rememberLazyListState()

    // Smoothly scroll to the selected address when triggered
    LaunchedEffect(selectedAddress) {
        selectedAddress?.let { target ->
            val idx = instructions.indexOfFirst { it.address == target }
            if (idx >= 0) {
                listState.animateScrollToItem(idx)
            }
        }
    }

    LazyColumn(
        state = listState,
        modifier = Modifier
            .fillMaxSize()
            .testTag("disassembly_list")
    ) {
        items(instructions) { inst ->
            val isSelected = selectedAddress == inst.address
            val inlineComment = userComments[inst.address] ?: inst.userComment
            val isBookmarked = bookmarkedAddresses.contains(inst.address)

            // Resolve function boundary starts to trace blocks
            val bounds = symbols.find { it.address == inst.address && it.type == SymbolType.FUNC }
            if (bounds != null) {
                val boundName = renamedSymbols[bounds.address] ?: bounds.name
                FunctionPrologueHeader(name = boundName, address = bounds.address, xrefs = inst.xrefs)
            }

            val lineBgColor = if (isSelected) ColorAccentSecondary.copy(alpha = 0.15f) else Color.Transparent
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(lineBgColor)
                    .clickable { onAddressClick(inst.address) }
                    .padding(vertical = 4.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Selected indicator at the very left, like border-l-2 in HTML design!
                    if (isSelected) {
                        Box(
                            modifier = Modifier
                                .width(3.dp)
                                .height(22.dp)
                                .background(ColorAccentSecondary)
                        )
                    } else {
                        Spacer(modifier = Modifier.width(3.dp))
                    }

                    // Star bookmark icon
                    IconButton(
                        onClick = { onBookmarkToggle(inst.address) },
                        modifier = Modifier
                            .padding(horizontal = 4.dp)
                            .size(24.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Star,
                            contentDescription = "Starred Address",
                            tint = if (isBookmarked) ColorStringYellow else ColorTextMuted.copy(alpha = 0.3f),
                            modifier = Modifier.size(14.dp)
                        )
                    }

                    // Virtual Address Column
                    Text(
                        text = "0x" + inst.address.toString(16).uppercase(),
                        fontWeight = FontWeight.Bold,
                        color = ColorAccentPrimary,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.width(76.dp)
                    )

                    // Raw Opcode bytes
                    Text(
                        text = inst.rawBytesHex,
                        color = ColorTextMuted,
                        fontSize = 9.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.width(100.dp),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )

                    // Mnemonic column
                    val mColor = when (inst.mnemonic) {
                        "BL", "B", "RET", "B.cond", "CBZ", "CBNZ" -> ColorDangerRed
                        "LDR", "STR" -> ColorLocalBlue
                        "SVC" -> ColorExportGreen
                        else -> Color.White
                    }
                    Text(
                        text = inst.mnemonic,
                        color = mColor,
                        fontWeight = FontWeight.Bold,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.width(60.dp)
                    )

                    // Operands (Clickable if call target jump matches list)
                    val isClickableTarget = inst.targetAddress != null && inst.targetAddress > 0L
                    Text(
                        text = inst.operands,
                        color = if (isClickableTarget) ColorSectionLink(inst, symbols) else ColorTextLight,
                        fontWeight = if (isClickableTarget) FontWeight.Bold else FontWeight.Normal,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier
                            .weight(1f)
                            .clickable(enabled = isClickableTarget) {
                                inst.targetAddress?.let { onAddressClick(it) }
                            },
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )

                    // User Inline Commentary
                    if (inlineComment.isNotEmpty()) {
                        Text(
                            text = "; $inlineComment",
                            color = ColorCommentGreen,
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier
                                .width(120.dp)
                                .clickable { onCommentEdit(inst.address, inlineComment) },
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    } else {
                        IconButton(
                            onClick = { onCommentEdit(inst.address, "") },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Edit,
                                contentDescription = "Add comment",
                                tint = ColorTextMuted.copy(alpha = 0.4f),
                                modifier = Modifier.size(12.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ColorSectionLink(inst: Instruction, symbols: List<ElfSymbol>): Color {
    // Check if target points to import or JNI dynamic code
    val sym = symbols.find { it.address == inst.targetAddress }
    return when {
        sym?.isJni == true || sym?.isExport == true -> ColorExportGreen
        sym?.isImport == true -> ColorImportOrange
        else -> ColorAccentPrimary
    }
}

@Composable
fun FunctionPrologueHeader(name: String, address: Long, xrefs: List<Long>) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(ColorPanelBg.copy(alpha = 0.5f))
            .padding(vertical = 8.dp, horizontal = 12.dp)
    ) {
        Text(
            text = "---------- Function: $name (0x${address.toString(16).uppercase()}) ----------",
            fontWeight = FontWeight.Bold,
            color = ColorExportGreen,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace
        )
        if (xrefs.isNotEmpty()) {
            Row(
                modifier = Modifier.padding(top = 2.dp),
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = "XREFs:",
                    color = ColorCommentGreen,
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = xrefs.joinToString(", ") { "0x" + it.toString(16).uppercase() },
                    color = ColorTextMuted,
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
fun StringsTab(
    extractedStrings: List<ExtractedString>,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    minStringLength: Int,
    onMinStringLengthChange: (Int) -> Unit
) {
    val clipboardManager = LocalClipboardManager.current
    val context = LocalContext.current

    val filtered = remember(extractedStrings, searchQuery, minStringLength) {
        extractedStrings.filter { str ->
            str.length >= minStringLength &&
            str.value.contains(searchQuery, ignoreCase = true)
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(8.dp),
            colors = CardDefaults.cardColors(containerColor = ColorPanelBg),
            border = BorderStroke(1.dp, ColorBorder)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = onSearchQueryChange,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    placeholder = { Text("Filter strings (e.g. key, URL, /proc)...", fontSize = 11.sp, color = ColorTextMuted) },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = ColorDarkBg,
                        unfocusedContainerColor = ColorDarkBg,
                        focusedBorderColor = ColorAccentPrimary,
                        unfocusedBorderColor = ColorBorder,
                        focusedTextColor = Color.White,
                        unfocusedTextColor = ColorTextLight
                    )
                )

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Min Length: $minStringLength", color = ColorTextLight, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                    Slider(
                        value = minStringLength.toFloat(),
                        onValueChange = { onMinStringLengthChange(it.toInt()) },
                        valueRange = 4f..20f,
                        steps = 16,
                        modifier = Modifier.width(180.dp),
                        colors = SliderDefaults.colors(
                            thumbColor = ColorAccentPrimary,
                            activeTrackColor = ColorAccentSecondary,
                            inactiveTrackColor = ColorBorder
                        )
                    )
                }
            }
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .testTag("strings_list")
        ) {
            items(filtered) { str ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            clipboardManager.setText(AnnotatedString(str.value))
                            Toast
                                .makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT)
                                .show()
                        }
                        .padding(horizontal = 12.dp, vertical = 8.dp)
                        .border(
                            width = if (str.isSuspicious) 1.dp else 0.dp,
                            color = if (str.isSuspicious) ColorDangerRed.copy(alpha = 0.4f) else Color.Transparent,
                            shape = RoundedCornerShape(4.dp)
                        )
                        .background(if (str.isSuspicious) ColorDangerRed.copy(alpha = 0.05f) else Color.Transparent)
                        .padding(horizontal = 6.dp, vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = "addr: 0x" + str.address.toString(16).uppercase(),
                                color = ColorAccentPrimary,
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(
                                bgBadgeText(str.section),
                                color = ColorLocalBlue,
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace
                            )
                            if (str.isSuspicious) {
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(2.dp))
                                        .background(ColorDangerRed.copy(alpha = 0.2f))
                                        .padding(horizontal = 4.dp, vertical = 1.dp)
                                ) {
                                    Text("FLAGGED", color = ColorDangerRed, fontSize = 8.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                                }
                            }
                        }
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = str.value,
                            color = if (str.isSuspicious) ColorStringYellow else ColorTextLight,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            maxLines = 3,
                            overflow = TextOverflow.Ellipsis
                        )
                        if (str.isSuspicious && str.suspiciousReason != null) {
                            Text(
                                text = "-> Reason: ${str.suspiciousReason}",
                                color = ColorDangerRed,
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }
                    Icon(
                        imageVector = Icons.Default.Share,
                        contentDescription = "Copy",
                        tint = ColorTextMuted,
                        modifier = Modifier.size(14.dp)
                    )
                }
                Divider(color = ColorBorder)
            }
        }
    }
}

fun bgBadgeText(sec: String): String {
    return "[$sec]"
}

@Composable
fun SectionsTab(
    sections: List<SectionHeader>,
    onSectionTap: (SectionHeader) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(12.dp)
    ) {
        Text(
            text = "BINARY SECTIONS SEGMENTATION",
            fontWeight = FontWeight.Bold,
            color = ColorAccentPrimary,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .testTag("sections_list")
        ) {
            items(sections) { sec ->
                // Color Code blocks based on specs: exec (red), writable (yellow), read-only (blue)
                val cSec = when {
                    sec.flags.contains("X") -> ColorDangerRed
                    sec.flags.contains("W") -> ColorStringYellow
                    else -> ColorLocalBlue
                }

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp)
                        .clickable { onSectionTap(sec) },
                    colors = CardDefaults.cardColors(containerColor = ColorPanelBg),
                    border = BorderStroke(1.dp, ColorBorder)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Box(
                                    modifier = Modifier
                                        .size(10.dp)
                                        .clip(RoundedCornerShape(5.dp))
                                        .background(cSec)
                                )
                                Text(
                                    text = sec.name,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.White,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 12.sp
                                )
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                                Text("Virtual Addr: 0x" + sec.virtualAddress.toString(16).uppercase(), color = ColorTextMuted, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                                Text("Offset: 0x" + sec.fileOffset.toString(16).uppercase(), color = ColorTextMuted, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                            }
                        }

                        Column(horizontalAlignment = Alignment.End) {
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(2.dp))
                                    .background(cSec.copy(alpha = 0.15f))
                                    .border(BorderStroke(0.5.dp, cSec))
                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                            ) {
                                Text(
                                    text = sec.flags,
                                    color = cSec,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "Size: ${sec.size}b",
                                color = ColorTextMuted,
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun HexViewerTab(
    rawBytes: ByteArray,
    sections: List<SectionHeader>,
    selectedIndex: Int,
    onIndexSelected: (Int) -> Unit
) {
    var rangeStart by remember { mutableStateOf(0) }
    val displayRangeSize = 512

    // Compute active slicing offset
    val activeSec = if (selectedIndex in sections.indices) sections[selectedIndex] else null
    val targetOffset = activeSec?.fileOffset?.toInt() ?: 0
    val targetLimit = if (activeSec != null) (activeSec.fileOffset + activeSec.size).toInt() else rawBytes.size

    LaunchedEffect(selectedIndex) {
        rangeStart = targetOffset
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // Section Selector bar
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(ColorPanelBg)
                .border(BorderStroke(1.dp, ColorBorder))
                .padding(8.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = { onIndexSelected(-1) },
                    colors = ButtonDefaults.buttonColors(containerColor = if (selectedIndex == -1) ColorAccentSecondary else ColorDarkBg),
                    shape = RoundedCornerShape(4.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text("Entire Loader", fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                }

                sections.forEachIndexed { idx, sec ->
                    Button(
                        onClick = { onIndexSelected(idx) },
                        colors = ButtonDefaults.buttonColors(containerColor = if (selectedIndex == idx) ColorAccentSecondary else ColorDarkBg),
                        shape = RoundedCornerShape(4.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                    ) {
                        Text(sec.name, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                    }
                }
            }
        }

        // Pagination buttons
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Viewing Range: 0x${Integer.toHexString(rangeStart).uppercase()} - 0x${Integer.toHexString((rangeStart + displayRangeSize).coerceAtMost(targetLimit)).uppercase()}",
                color = ColorTextLight,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                IconButton(
                    onClick = { rangeStart = (rangeStart - displayRangeSize).coerceAtLeast(targetOffset) },
                    enabled = rangeStart > targetOffset,
                    modifier = Modifier.size(28.dp)
                ) {
                    Icon(imageVector = Icons.Default.ArrowBack, contentDescription = "Page back", tint = ColorAccentPrimary)
                }

                IconButton(
                    onClick = { rangeStart = (rangeStart + displayRangeSize).coerceAtMost(targetLimit - 16) },
                    enabled = rangeStart + displayRangeSize < targetLimit,
                    modifier = Modifier.size(28.dp)
                ) {
                    Icon(imageVector = Icons.Default.PlayArrow, contentDescription = "Page next", tint = ColorAccentPrimary)
                }
            }
        }

        Divider(color = ColorBorder)

        // Rendering core 16-byte grid rows
        val scrollState = rememberScrollState()
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .background(ColorDarkBg)
                .padding(horizontal = 8.dp)
                .verticalScroll(scrollState)
                .testTag("hex_dump_area")
        ) {
            val chunkLimit = (rangeStart + displayRangeSize).coerceAtMost(targetLimit)
            for (offset in rangeStart until chunkLimit step 16) {
                HexRow(offset = offset, bytes = rawBytes, limit = targetLimit)
            }
        }
    }
}

@Composable
fun HexRow(offset: Int, bytes: ByteArray, limit: Int) {
    val rowSize = (limit - offset).coerceAtMost(16)
    val rowBytes = ByteArray(16)
    if (offset < bytes.size) {
        val readSize = (bytes.size - offset).coerceAtMost(rowSize)
        System.arraycopy(bytes, offset, rowBytes, 0, readSize)
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 1.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // Memory Offset
        Text(
            text = String.format("%08X", offset),
            color = ColorAccentPrimary,
            fontSize = 10.sp,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.width(68.dp)
        )

        // Hex bytes display
        val hexSb = StringBuilder()
        for (i in 0 until 16) {
            if (i < rowSize) {
                hexSb.append(String.format("%02X ", rowBytes[i]))
            } else {
                hexSb.append("   ")
            }
            if (i == 7) hexSb.append(" ") // Standard IDA gap separator
        }
        Text(
            text = hexSb.toString(),
            color = ColorTextLight,
            fontSize = 10.sp,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.width(280.dp)
        )

        // ASCII Translation
        val asciiSb = StringBuilder()
        for (i in 0 until rowSize) {
            val b = rowBytes[i].toInt() and 0xFF
            if (b in 32..126) {
                asciiSb.append(b.toChar())
            } else {
                asciiSb.append(".")
            }
        }
        Text(
            text = asciiSb.toString(),
            color = ColorStringYellow,
            fontSize = 10.sp,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
fun ImportsExportsTab(symbols: List<ElfSymbol>) {
    val imports = remember(symbols) { symbols.filter { it.isImport } }
    val exports = remember(symbols) { symbols.filter { it.isExport || it.isJni } }

    var filterType by remember { mutableStateOf(0) } // 0 = Exports / JNI, 1 = Library Imports

    Column(modifier = Modifier.fillMaxSize()) {
        TabRow(
            selectedTabIndex = filterType,
            containerColor = ColorPanelBg,
            contentColor = ColorAccentPrimary,
            divider = { Divider(color = ColorBorder) }
        ) {
            Tab(selected = filterType == 0, onClick = { filterType = 0 }, text = { Text("JNI Exports (${exports.size})") })
            Tab(selected = filterType == 1, onClick = { filterType = 1 }, text = { Text("Libc Imports (${imports.size})") })
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .padding(8.dp)
        ) {
            if (filterType == 0) {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    items(exports) { sym ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = ColorPanelBg),
                            border = BorderStroke(1.dp, ColorBorder)
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = sym.name,
                                        fontWeight = FontWeight.Bold,
                                        color = colorForBadge(sym),
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 12.sp,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        modifier = Modifier.weight(1f)
                                    )
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(2.dp))
                                            .background(ColorAccentPrimary.copy(alpha = 0.15f))
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                    ) {
                                        Text(
                                            text = if (sym.isJni) "JNI API" else "GLOBAL",
                                            color = ColorAccentPrimary,
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Bold,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }
                                }

                                if (sym.isJni && sym.jniClassName != null) {
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Text("Class: ${sym.jniClassName}", color = ColorTextLight, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                                    Text("Method: ${sym.jniMethodName}", color = ColorLocalBlue, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                                }

                                Spacer(modifier = Modifier.height(4.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text("vaddr: 0x" + sym.address.toString(16).uppercase(), color = ColorTextMuted, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                                    Text("bind: ${sym.binding}", color = ColorTextMuted, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                                }
                            }
                        }
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    items(imports) { sym ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = ColorPanelBg),
                            border = BorderStroke(1.dp, ColorBorder)
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        text = sym.name,
                                        fontWeight = FontWeight.Bold,
                                        color = ColorImportOrange,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 12.sp,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        text = "STUB [PLT]",
                                        color = ColorTextMuted,
                                        fontSize = 10.sp,
                                        fontFamily = FontFamily.Monospace
                                    )
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                                Text("Dependent Section: ${sym.section}", color = ColorTextMuted, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                            }
                        }
                    }
                }
            }
        }
    }
}

fun colorForBadge(sym: ElfSymbol): Color {
    return if (sym.isJni) ColorExportGreen else ColorLocalBlue
}

@Composable
fun RightScannerPanel(
    flags: List<AntiAnalysisFlag>,
    logs: List<AnalysisProgressLog>
) {
    var viewMode by remember { mutableStateOf(0) } // 0 = Scanner, 1 = Analysis Log console

    Column(modifier = Modifier.fillMaxSize()) {
        TabRow(
            selectedTabIndex = viewMode,
            containerColor = ColorPanelBg,
            contentColor = ColorAccentPrimary,
            divider = { Divider(color = ColorBorder) }
        ) {
            Tab(selected = viewMode == 0, onClick = { viewMode = 0 }, text = { Text("Scan", fontSize = 11.sp, fontWeight = FontWeight.Bold) })
            Tab(selected = viewMode == 1, onClick = { viewMode = 1 }, text = { Text("Log", fontSize = 11.sp, fontWeight = FontWeight.Bold) })
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .background(ColorPanelBg)
        ) {
            if (viewMode == 0) {
                // Suspicious scan rules
                if (flags.isEmpty()) {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text("No threats found in binary", color = ColorExportGreen, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(8.dp)
                            .testTag("sec_scan_area"),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(flags) { flag ->
                            val sColor = when (flag.severity) {
                                "CRITICAL" -> ColorDangerRed
                                "HIGH" -> ColorDangerRed
                                "MEDIUM" -> ColorStringYellow
                                else -> ColorLocalBlue
                            }

                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = ColorDarkBg),
                                border = BorderStroke(1.dp, sColor.copy(alpha = 0.5f))
                            ) {
                                Column(modifier = Modifier.padding(8.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = flag.category,
                                            color = sColor,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 8.sp,
                                            fontFamily = FontFamily.Monospace
                                        )
                                        Text(
                                            text = flag.severity,
                                            color = sColor,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 8.sp,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = flag.title,
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = flag.description,
                                        color = ColorTextMuted,
                                        fontSize = 10.sp,
                                        lineHeight = 12.sp
                                    )
                                }
                            }
                        }
                    }
                }
            } else {
                // Analysis Log console
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(8.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    items(logs) { log ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text(
                                text = ">>",
                                color = if (log.isComplete) ColorExportGreen else ColorStringYellow,
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace
                            )
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = log.title,
                                    color = Color.White,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace
                                )
                                Text(
                                    text = log.message,
                                    color = ColorTextMuted,
                                    fontSize = 9.sp,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                        Divider(color = ColorBorder.copy(alpha = 0.5f))
                    }
                }
            }
        }
    }
}
