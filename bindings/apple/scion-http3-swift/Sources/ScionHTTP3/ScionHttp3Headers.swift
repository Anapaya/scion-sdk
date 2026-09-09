// Copyright 2026 Anapaya Systems
import Foundation

/// A header section: ordered, case-insensitive by name, and able to hold a name more than once.
///
/// Order and repetition are both preserved, because HTTP/3 gives them meaning that merging would
/// destroy: several `set-cookie` lines are not one joined line.
public struct ScionHttp3Headers: Sendable, Equatable {
    /// One header line.
    public struct Entry: Sendable, Equatable {
        public let name: String
        public let value: String

        public init(name: String, value: String) {
            self.name = name
            self.value = value
        }
    }

    private var entries: [Entry]

    /// A section with no lines.
    public init() {
        entries = []
    }

    /// A section holding exactly the given lines, in the given order. A name may repeat.
    public init(_ lines: KeyValuePairs<String, String>) {
        entries = lines.map { Entry(name: $0.key, value: $0.value) }
    }

    init(entries: [Entry]) {
        self.entries = entries
    }

    /// How many lines the section has, counting a repeated name once per occurrence.
    public var count: Int { entries.count }

    /// Whether the section has no lines.
    public var isEmpty: Bool { entries.isEmpty }

    /// The distinct names present, lower-cased, in the order they first appear.
    public var names: [String] {
        var seen = Set<String>()
        return entries.compactMap { entry in
            let name = entry.name.lowercased()
            return seen.insert(name).inserted ? name : nil
        }
    }

    /// The first value for `name` or nil if the section has none.
    public subscript(name: String) -> String? {
        entries.first { Self.sameName($0.name, name) }?.value
    }

    /// Every value for `name`, in order; empty when the section has none.
    public func values(_ name: String) -> [String] {
        entries.filter { Self.sameName($0.name, name) }.map(\.value)
    }

    /// Whether `name` is present at all.
    public func contains(_ name: String) -> Bool {
        entries.contains { Self.sameName($0.name, name) }
    }

    /// Appends a line, keeping any line that already has this name.
    public mutating func add(_ name: String, _ value: String) {
        entries.append(Entry(name: name, value: value))
    }

    /// Replaces every line with this name, wherever they were, with a single line.
    public mutating func set(_ name: String, _ value: String) {
        removeAll(name)
        add(name, value)
    }

    /// Removes every line with this name.
    public mutating func removeAll(_ name: String) {
        entries.removeAll { Self.sameName($0.name, name) }
    }

    /// Appends the line only if the section does not have its name yet.
    mutating func addIfAbsent(_ name: String, _ value: String) {
        if !contains(name) {
            add(name, value)
        }
    }

    /// Throws `ScionHttp3Error.invalidRequest` for the first line the section cannot carry.
    func validate() throws {
        for entry in entries {
            try Self.validateName(entry.name)
            try Self.validateValue(entry.value, of: entry.name)
        }
    }

    private static func sameName(_ a: String, _ b: String) -> Bool {
        a.caseInsensitiveCompare(b) == .orderedSame
    }

    // RFC 9110's token.
    static let tokenSymbols: Set<Unicode.Scalar> = Set("!#$%&'*+-.^_`|~".unicodeScalars)

    static func isToken(_ scalar: Unicode.Scalar) -> Bool {
        let value = scalar.value
        let alphanumeric =
            (0x30...0x39).contains(value) || (0x41...0x5A).contains(value)
            || (0x61...0x7A).contains(value)
        return alphanumeric || tokenSymbols.contains(scalar)
    }

    private static func validateName(_ name: String) throws {
        if name.isEmpty {
            throw ScionHttp3Error.invalidRequest(detail: "a header name cannot be empty")
        }
        for (index, scalar) in name.unicodeScalars.enumerated() where !isToken(scalar) {
            throw ScionHttp3Error.invalidRequest(
                detail: "header name \"\(name)\" holds \(describe(scalar)) at index \(index)")
        }
    }

    private static func validateValue(_ value: String, of name: String) throws {
        // Tab and printable ASCII only.
        for (index, scalar) in value.unicodeScalars.enumerated() {
            let allowed = scalar.value == 0x09 || (0x20...0x7E).contains(scalar.value)
            if !allowed {
                throw ScionHttp3Error.invalidRequest(
                    detail: "value of header \"\(name)\" holds \(describe(scalar)) at index "
                        + "\(index). Header values have to be ASCII; encode anything else, "
                        + "e.g., as base64.")
            }
        }
    }

    private static func describe(_ scalar: Unicode.Scalar) -> String {
        switch scalar.value {
        case 0x0A: return "a line feed"
        case 0x0D: return "a carriage return"
        case 0x00: return "a NUL"
        case 0x7F: return "a DEL"
        default: return String(format: "U+%04X", scalar.value)
        }
    }
}

extension ScionHttp3Headers: Sequence {
    public func makeIterator() -> IndexingIterator<[Entry]> {
        entries.makeIterator()
    }
}

extension ScionHttp3Headers: CustomStringConvertible {
    public var description: String {
        entries.map { "\($0.name): \($0.value)" }.joined(separator: ", ")
    }
}
