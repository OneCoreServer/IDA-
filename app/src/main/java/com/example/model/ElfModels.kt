package com.example.model

import java.io.Serializable

data class ElfHeader(
    val magic: String,          // e.g. "7F 45 4C 46"
    val elfClass: String,       // 32-bit or 64-bit
    val endianness: String,     // Little Endian / Big Endian
    val osAbi: String,          // System V, Linux, etc.
    val type: String,           // shared object file, executable, etc.
    val machine: String,        // ARM, AArch64, x86_64, etc.
    val entryAddress: Long,     // Entry point virtual address
    val programHeaderOffset: Long,
    val sectionHeaderOffset: Long,
    val flags: Long,
    val headerSize: Int,
    val programHeaderNum: Int,
    val sectionHeaderNum: Int,
    val stringTableIndex: Int
) : Serializable

data class SectionHeader(
    val index: Int,
    val name: String,
    val type: String,
    val flags: String,          // R/W/X representation
    val rawFlags: Long,
    val virtualAddress: Long,
    val fileOffset: Long,
    val size: Long,
    val link: Long,
    val info: Long,
    val alignment: Long,
    val entrySize: Long
) : Serializable

data class ProgramHeader(
    val type: String,
    val offset: Long,
    val virtualAddress: Long,
    val physicalAddress: Long,
    val fileSize: Long,
    val memorySize: Long,
    val flags: String,
    val alignment: Long
) : Serializable

data class DynamicItem(
    val tag: String,
    val value: String,
    val description: String
) : Serializable

enum class SymbolType {
    FUNC, OBJECT, NOTYPE, FILE, SECTION
}

enum class SymbolBinding {
    GLOBAL, LOCAL, WEAK
}

data class ElfSymbol(
    val index: Int,
    val address: Long,
    val name: String,
    val originName: String = name, // Keep original when renaming
    val size: Long,
    val type: SymbolType,
    val binding: SymbolBinding,
    val section: String,
    val isExport: Boolean,
    val isImport: Boolean,
    val isJni: Boolean,
    val jniClassName: String? = null,
    val jniMethodName: String? = null
) : Serializable

data class Instruction(
    val address: Long,
    val rawBytes: ByteArray,
    val mnemonic: String,
    val operands: String,
    val userComment: String = "",
    val isCall: Boolean = false,
    val isBranch: Boolean = false,
    val targetAddress: Long? = null,
    val xrefs: List<Long> = emptyList() // List of addresses calling this instruction/function
) : Serializable {
    val rawBytesHex: String
        get() = rawBytes.joinToString(" ") { String.format("%02X", it) }
}

data class ExtractedString(
    val address: Long,
    val value: String,
    val length: Int,
    val section: String,
    val isSuspicious: Boolean,
    val suspiciousReason: String? = null
) : Serializable

data class AnalysisProgressLog(
    val step: Int,
    val title: String,
    val message: String,
    val timestamp: String,
    val isComplete: Boolean = false
) : Serializable

data class ElfAnalysisResult(
    val fileName: String,
    val fileSize: Long,
    val architecture: String,
    val header: ElfHeader,
    val sections: List<SectionHeader>,
    val programHeaders: List<ProgramHeader>,
    val dynamicItems: List<DynamicItem>,
    val symbols: List<ElfSymbol>,
    val extractedStrings: List<ExtractedString>,
    val instructions: List<Instruction>,
    val logs: List<AnalysisProgressLog>,
    val antiAnalysisFlags: List<AntiAnalysisFlag>
) : Serializable

data class AntiAnalysisFlag(
    val category: String, // ANTI_DEBUG, SANDBOX_CHECK, INJECTION, OBFUSCATION, INTEGRITY
    val title: String,
    val description: String,
    val severity: String // CRITICAL, HIGH, MEDIUM, INFO
) : Serializable
