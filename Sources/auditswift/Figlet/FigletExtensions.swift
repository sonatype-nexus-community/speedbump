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
    return String(self[start..<end])
  }
  
  /// String subscripting
  ///
  /// - parameter atIndex: Int to use for extraction
  /// - returns: Character?
  func substring(atIndex i: Int) -> Character?
  {
    guard let _ = self.index(
      self.startIndex, offsetBy: i, limitedBy: self.endIndex),
      let _ = self.index(
        self.startIndex, offsetBy: i + 1, limitedBy: self.endIndex)
      else { return nil }
    return self[index(startIndex, offsetBy: i)]
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
