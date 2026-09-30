#include "elfscope/output_formatter.hpp"

#include <elf.h>

#include <iomanip>
#include <sstream>

namespace elfscope {

namespace {

std::string elf_class_name(ElfClass value)
{
    switch (value) {
    case ElfClass::elf32:
        return "ELF32";
    case ElfClass::elf64:
        return "ELF64";
    default:
        return "UNKNOWN";
    }
}

std::string endianness_name(Endianness value)
{
    switch (value) {
    case Endianness::little:
        return "little";
    case Endianness::big:
        return "big";
    default:
        return "unknown";
    }
}

std::string elf_type_name(std::uint16_t type)
{
    switch (type) {
    case ET_NONE:
        return "NONE";
    case ET_REL:
        return "REL";
    case ET_EXEC:
        return "EXEC";
    case ET_DYN:
        return "DYN";
    case ET_CORE:
        return "CORE";
    default:
        return "UNKNOWN";
    }
}

std::string machine_name(std::uint16_t machine)
{
    switch (machine) {
    case EM_NONE:
        return "No machine";
    case EM_386:
        return "Intel 80386";
    case EM_X86_64:
        return "AMD x86-64";
    case EM_ARM:
        return "ARM";
    case EM_AARCH64:
        return "AArch64";
    case EM_MIPS:
        return "MIPS";
    case EM_PPC:
        return "PowerPC";
    case EM_PPC64:
        return "PowerPC64";
    case EM_RISCV:
        return "RISC-V";
    case EM_SPARC:
        return "SPARC";
    case EM_SPARCV9:
        return "SPARC V9";
    default:
        return "Unknown";
    }
}

std::string os_abi_name(std::uint8_t abi)
{
    switch (abi) {
    case ELFOSABI_SYSV:
        return "UNIX - System V";
    case ELFOSABI_LINUX:
        return "Linux";
    case ELFOSABI_FREEBSD:
        return "FreeBSD";
    case ELFOSABI_NETBSD:
        return "NetBSD";
    case ELFOSABI_SOLARIS:
        return "Solaris";
    default:
        return "Unknown";
    }
}

std::string yes_no(bool value)
{
    return value ? "yes" : "no";
}

std::string or_none(const std::string& value)
{
    return value.empty() ? "none" : value;
}

std::string human_bytes(std::uint64_t bytes)
{
    std::ostringstream out;
    out << bytes << " bytes";

    if (bytes >= 1024) {
        out << ", " << std::fixed << std::setprecision(1);

        if (bytes >= 1024 * 1024) {
            out << static_cast<double>(bytes) / (1024.0 * 1024.0) << " MiB";
        } else {
            out << static_cast<double>(bytes) / 1024.0 << " KiB";
        }
    }

    return out.str();
}

}

std::string format_info(const ElfFile& elf)
{
    std::ostringstream out;

    out
        << "file: " << elf.path << '\n'
        << "class: " << elf_class_name(elf.elf_class) << '\n'
        << "endianness: " << endianness_name(elf.endianness) << '\n'
        << "os abi: " << os_abi_name(elf.os_abi) << '\n'
        << "type: " << elf_type_name(elf.type) << '\n'
        << "machine: " << machine_name(elf.machine) << '\n'
        << "entry: 0x" << std::hex << elf.entry << std::dec << '\n'
        << "program header offset: 0x"
        << std::hex << elf.program_header_offset << std::dec << '\n'
        << "section header offset: 0x"
        << std::hex << elf.section_header_offset << std::dec << '\n'
        << "program headers: " << elf.program_header_count << '\n'
        << "sections: " << elf.section_header_count << '\n'
        << "section name index: " << elf.section_name_index << '\n'
        << "interpreter: " << or_none(elf.interpreter) << '\n';

    return out.str();
}

std::string format_sections(const std::vector<Section>& sections)
{
    std::ostringstream out;

    out << "sections: " << sections.size() << "\n\n";

    out
        << std::left
        << std::setw(4) << "ID"
        << std::setw(24) << "NAME"
        << std::setw(12) << "TYPE"
        << std::setw(8) << "FLAGS"
        << std::setw(18) << "ADDRESS"
        << std::setw(14) << "OFFSET"
        << std::setw(12) << "SIZE"
        << '\n'
        << std::string(92, '-') << '\n';

    for (std::size_t index = 0; index < sections.size(); ++index) {
        const auto& section = sections[index];

        out
            << std::left
            << std::setw(4) << index
            << std::setw(24) << section.name
            << std::setw(12) << section_type_name(section.type)
            << std::setw(8) << section_flags_name(section.flags)
            << "0x" << std::right << std::hex
            << std::setw(16) << section.address
            << std::dec
            << std::setw(14) << section.offset
            << std::setw(12) << section.size
            << '\n';
    }

    return out.str();
}

std::string format_segments(const std::vector<Segment>& segments)
{
    std::ostringstream out;

    out << "segments: " << segments.size() << "\n\n";

    out
        << std::left
        << std::setw(4) << "ID"
        << std::setw(16) << "TYPE"
        << std::setw(8) << "FLAGS"
        << std::setw(18) << "OFFSET"
        << std::setw(18) << "VADDR"
        << std::setw(14) << "FILE SIZE"
        << std::setw(14) << "MEM SIZE"
        << std::setw(12) << "ALIGN"
        << '\n'
        << std::string(100, '-') << '\n';

    for (std::size_t index = 0; index < segments.size(); ++index) {
        const auto& segment = segments[index];

        out
            << std::left
            << std::setw(4) << index
            << std::setw(16) << segment_type_name(segment.type)
            << std::setw(8) << segment_flags_name(segment.flags)
            << "0x" << std::right << std::hex
            << std::setw(16) << segment.offset
            << " 0x" << std::setw(16) << segment.virtual_address
            << std::dec
            << std::setw(14) << segment.file_size
            << std::setw(14) << segment.memory_size
            << std::setw(12) << segment.alignment
            << '\n';
    }

    return out.str();
}

std::string format_mapping(
    const std::vector<Section>& sections,
    const std::vector<SectionSegmentMapping>& mappings)
{
    std::ostringstream out;

    out << "section to segment mapping:\n\n";

    for (const auto& mapping : mappings) {
        // mapper and section list come from the same file, but be safe anyway
        if (mapping.section_index >= sections.size()) {
            continue;
        }

        const auto& section = sections[mapping.section_index];

        out
            << '[' << mapping.section_index << "] "
            << (section.name.empty() ? "<unnamed>" : section.name)
            << " ->";

        if (mapping.segment_indices.empty()) {
            out << " none";
        }

        for (const auto segment : mapping.segment_indices) {
            out << ' ' << segment;
        }

        out << '\n';
    }

    return out.str();
}

std::string format_symbols(const std::vector<Symbol>& symbols)
{
    std::ostringstream out;

    out << "symbols: " << symbols.size() << "\n\n";

    for (const auto& symbol : symbols) {
        out
            << symbol.name
            << "  type=" << symbol_type_name(symbol.type)
            << "  binding=" << symbol_binding_name(symbol.binding)
            << "  visibility=" << symbol_visibility_name(symbol.visibility)
            << "  section=" << symbol_section_name(symbol.section_index)
            << "  value=0x" << std::hex << symbol.value
            << "  size=" << std::dec << symbol.size
            << "  table=" << symbol.table
            << '\n';
    }

    return out.str();
}

std::string format_relocations(const std::vector<Relocation>& relocations)
{
    std::ostringstream out;

    out << "relocations: " << relocations.size() << "\n\n";
    out << "TABLE OFFSET TYPE SYMBOL ADDEND\n";

    for (const auto& relocation : relocations) {
        out
            << relocation.table
            << " 0x" << std::hex << relocation.offset << std::dec
            << ' ' << relocation.type_name
            << ' ' << (relocation.symbol_name.empty() ? "-" : relocation.symbol_name)
            << ' ' << relocation.addend
            << '\n';
    }

    return out.str();
}

std::string format_dependencies(const std::vector<Dependency>& dependencies)
{
    std::ostringstream out;

    out << "dependencies: " << dependencies.size() << "\n\n";

    if (dependencies.empty()) {
        out << "  none\n";
        return out.str();
    }

    for (const auto& dependency : dependencies) {
        out << "  " << dependency.name << '\n';
    }

    return out.str();
}

std::string format_dynamic(const DynamicInfo& dynamic)
{
    std::ostringstream out;

    out
        << "dynamic:\n"
        << "  entries: " << dynamic.entry_count << '\n'
        << "  soname: " << or_none(dynamic.soname) << '\n'
        << "  rpath: " << or_none(dynamic.rpath) << '\n'
        << "  runpath: " << or_none(dynamic.runpath) << '\n'
        << "  flags: " << dynamic_flags_name(dynamic.flags) << '\n'
        << "  flags_1: " << dynamic_flags_1_name(dynamic.flags_1) << '\n'
        << std::hex
        << "  plt_got: 0x" << dynamic.plt_got << '\n'
        << "  plt_relocation_size: 0x" << dynamic.plt_relocation_size << '\n'
        << "  rela: 0x" << dynamic.rela << '\n'
        << "  rela_size: 0x" << dynamic.rela_size << '\n'
        << "  rela_entry_size: 0x" << dynamic.rela_entry_size << '\n'
        << "  rel: 0x" << dynamic.rel << '\n'
        << "  rel_size: 0x" << dynamic.rel_size << '\n'
        << "  jmprel: 0x" << dynamic.jmprel << '\n'
        << "  hash: 0x" << dynamic.hash << '\n'
        << "  gnu_hash: 0x" << dynamic.gnu_hash << '\n'
        << "  init: 0x" << dynamic.init << '\n'
        << "  fini: 0x" << dynamic.fini << '\n'
        << "  init_array: 0x" << dynamic.init_array << '\n'
        << "  init_array_size: 0x" << dynamic.init_array_size << '\n'
        << "  fini_array: 0x" << dynamic.fini_array << '\n'
        << "  fini_array_size: 0x" << dynamic.fini_array_size << '\n'
        << std::dec
        << "  needed: " << dynamic.needed.size() << '\n';

    for (const auto& dependency : dynamic.needed) {
        out << "    " << dependency << '\n';
    }

    return out.str();
}

std::string format_security(const SecurityReport& report)
{
    std::ostringstream out;

    out
        << "security: " << report.path << '\n'
        << "  kind: " << binary_kind_name(report.kind) << '\n';

    if (!report.linked) {
        out << "  hardening checks do not apply to this kind of file\n";
        return out.str();
    }

    out
        << "  linking: "
        << (report.dynamically_linked ? "dynamic" : "static") << '\n'
        << "  PIE: " << yes_no(report.pie) << '\n'
        << "  NX stack: " << yes_no(report.nx) << '\n'
        << "  RELRO: " << relro_name(report.relro) << '\n'
        << "  stack canary: " << yes_no(report.canary) << '\n'
        << "  fortify: " << yes_no(report.fortify);

    if (report.fortify) {
        out << " (" << report.fortified_calls << " fortified functions)";
    }

    out
        << '\n'
        << "  stripped: " << yes_no(report.stripped) << '\n'
        << "  text relocations: " << yes_no(report.textrel) << '\n'
        << "  rpath: " << or_none(report.rpath) << '\n'
        << "  runpath: " << or_none(report.runpath) << '\n';

    if (report.findings.empty()) {
        out << "\nno findings\n";
        return out.str();
    }

    out << "\nfindings: " << report.findings.size() << '\n';

    for (const auto& finding : report.findings) {
        out << "  - " << finding << '\n';
    }

    return out.str();
}

std::string format_stats(
    const SectionAnalysis& sections,
    const SymbolAnalysis& symbols,
    const DependencyAnalysis& dependencies)
{
    std::ostringstream out;

    out
        << "sections:\n"
        << "  total: " << sections.total << '\n'
        << "  allocatable: " << sections.allocatable
        << "  (" << human_bytes(sections.allocatable_bytes) << ")\n"
        << "  executable: " << sections.executable
        << "  (" << human_bytes(sections.executable_bytes) << ")\n"
        << "  writable: " << sections.writable
        << "  (" << human_bytes(sections.writable_bytes) << ")\n"
        << "  code: " << sections.code
        << "  (" << human_bytes(sections.code_bytes) << ")\n"
        << "  data: " << sections.data
        << "  (" << human_bytes(sections.data_bytes) << ")\n"
        << "  rodata: " << sections.rodata
        << "  (" << human_bytes(sections.rodata_bytes) << ")\n"
        << "  nobits: " << sections.nobits << '\n'
        << "  tls: " << sections.tls << '\n'
        << "  symbol tables: " << sections.symbol_tables << '\n'
        << "  string tables: " << sections.string_tables << '\n';

    for (const auto& issue : sections.issues) {
        out
            << "  issue: [" << issue.index << "] "
            << issue.name << ": " << issue.reason << '\n';
    }

    out
        << "\nsymbols:\n"
        << "  total: " << symbols.total << '\n'
        << "  defined: " << symbols.defined << '\n'
        << "  undefined: " << symbols.undefined << '\n'
        << "  functions: " << symbols.functions << '\n'
        << "  objects: " << symbols.objects << '\n'
        << "  tls: " << symbols.tls << '\n'
        << "  ifunc: " << symbols.ifunc << '\n'
        << "  global: " << symbols.global << '\n'
        << "  weak: " << symbols.weak << '\n'
        << "  local: " << symbols.local << '\n'
        << "  hidden: " << symbols.hidden << '\n'
        << "  imported functions: " << symbols.imported_functions << '\n'
        << "  imported objects: " << symbols.imported_objects << '\n'
        << "  exported: " << symbols.exported << '\n';

    for (const auto& issue : symbols.issues) {
        out << "  issue: " << issue.name << ": " << issue.reason << '\n';
    }

    out
        << "\ndependencies:\n"
        << "  total: " << dependencies.count << '\n'
        << "  unique: " << dependencies.unique_count << '\n'
        << "  duplicates: " << dependencies.duplicate_count << '\n';

    for (const auto& name : dependencies.duplicates) {
        out << "  duplicate: " << name << '\n';
    }

    for (const auto& issue : dependencies.issues) {
        out << "  issue: " << issue.name << ": " << issue.reason << '\n';
    }

    return out.str();
}

std::string format_comparison(
    const std::string& first,
    const std::string& second,
    const FileComparison& c)
{
    std::ostringstream out;

    out
        << "a: " << first << " (" << c.size_a << " bytes)\n"
        << "b: " << second << " (" << c.size_b << " bytes)\n\n"
        << "identical bytes: " << yes_no(c.same_bytes) << '\n'
        << "same size: " << yes_no(c.same_size) << '\n'
        << "same class: " << yes_no(c.same_class) << '\n'
        << "same endianness: " << yes_no(c.same_endianness) << '\n'
        << "same machine: " << yes_no(c.same_machine) << '\n'
        << "same type: " << yes_no(c.same_type) << '\n'
        << "same entry: " << yes_no(c.same_entry) << '\n'
        << "same section count: " << yes_no(c.same_section_count) << '\n'
        << "same segment count: " << yes_no(c.same_segment_count) << '\n'
        << "same sections: " << yes_no(c.same_sections) << '\n'
        << "same segments: " << yes_no(c.same_segments) << '\n'
        << "same symbols: " << yes_no(c.same_symbols) << '\n'
        << "same dependencies: " << yes_no(c.same_dependencies) << '\n';

    if (c.differences.empty()) {
        out << "\nno differences\n";
        return out.str();
    }

    out << "\ndifferences: " << c.differences.size() << '\n';

    for (const auto& difference : c.differences) {
        out << "  - " << difference << '\n';
    }

    return out.str();
}

}
