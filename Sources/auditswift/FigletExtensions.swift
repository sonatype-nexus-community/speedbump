//
//          File:   Extensions.swift
//    Created by:   African Swift

import Foundation

extension String
{
  /// Strips whitespace and newline characters
  ///
  /// - returns: String
  func trim() -> String {
    return self.trimmingCharacters(in: .whitespacesAndNewlines)
  }
  
  
  /// String subscripting
  ///
  /// - parameter with: Range<Int> to use for extraction
  /// - returns: String extracted from range
  func substring(with range: Range<Int>) -> String?
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
  func substring(atIndex index: Int) -> Character?
  {
    guard let start = self.index(
      self.startIndex, offsetBy: index, limitedBy: self.endIndex),
      let end = self.index(
        self.startIndex, offsetBy: index + 1, limitedBy: self.endIndex)
      else { return nil }
    return Character(self.substring(with: start..<end))
  }
}

extension Character
{
  /// Character to String
  ///
  /// - returns: String
  func toString() -> String
  {
    return String(self)
  }
}
