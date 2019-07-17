//
//          File:   Extensions.swift
//    Created by:   African Swift

import Foundation

internal extension String
{
  /// Strips whitespace and newline characters
  ///
  /// - returns: String
  internal func trim() -> String {
    return self.trimmingCharacters(in: .whitespacesAndNewlines)
  }
  
  /// String index of
  ///
  /// - parameter of: Character to locate
  /// - returns: Int?
  internal func index(of c: Character) -> Int?
  {
    guard let currentIndex = self.characters.index(of: c)
      else { return nil }
    return self.distance(from: self.startIndex, to: self.index(of: c)!)
  }
  
  /// String subscripting
  ///
  /// - parameter with: Range<Int> to use for extraction
  /// - returns: String extracted from range
  internal func substring(with range: Range<Int>) -> String?
  {
    guard let start = self.index(
        self.startIndex, offsetBy: range.lowerBound, limitedBy: self.endIndex),
      let end = self.index(
        self.startIndex, offsetBy: range.upperBound, limitedBy: self.endIndex)
      else {
        return nil
    }
    return self.substring(with: start..<end)
  }
  
  /// String subscripting
  ///
  /// - parameter atIndex: Int to use for extraction
  /// - returns: Character?
  internal func substring(atIndex index: Int) -> Character?
  {
    guard let start = self.index(
      self.startIndex, offsetBy: index, limitedBy: self.endIndex),
      let end = self.index(
        self.startIndex, offsetBy: index + 1, limitedBy: self.endIndex)
      else { return nil }
    return Character(self.substring(with: start..<end))
  }
}

internal extension Character
{
  /// Character to String
  ///
  /// - returns: String
  internal func toString() -> String
  {
    return String(self)
  }
}
