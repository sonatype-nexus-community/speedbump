//
//          File:   FigletHeader.swift
//    Created by:   African Swift

import Foundation

// The first five characters must be "flf2a"
//
//         flf2a$ 6 5 20 15 3 0 143 229
//           |  | | | |  |  | |  |   |
//          /  /  | | |  |  | |  |   \
// Signature  /  /  | |  |  | |   \   Codetag_Count
//   Hardblank  /  /  |  |  |  \   SmushFull
//        Height  /   |  |   \  Print_Direction
//        Baseline   /    \   Comment_Lines
//         Max_Length      SmushOld

/// Figlet Header Structure
internal struct FigletHeader
{
  /// Font name
  internal let name: String
  
  /// The signature is the first five characters: "flf2a".
  internal let signature: String
  
  /// Hardblank is a character adjacent to the signature.
  internal let hardblank: Character
  
  /// Height of a character
  internal let height: Int
  
  /// Height of a character, not including descenders
  internal let baseline: Int
  
  /// Max line length (excluding comment lines) + a fudge factor
  internal let length: Int
  
  /// Old smushmode
  internal let smushold: Int
  
  /// Number of comment lines
  internal let comments: Int
  
  /// Each line has one or two endmark characters, locations designate width
  internal let endmark: Character
  
  /// Last line containing endmark
  internal let lastline: Int
  
  internal static let signature = "flf2a"
  
  internal enum FigError
  {
    case signature, hardblank, height, baseLine
    case maxLength, oldlayout, commentLines
    case printDirection, fulllayout, codetagCount
    case missingParameters, endmarkInconsistency
  }
  
}

internal extension FigletHeader
{
  internal init(lines: [String], name: String) throws
  {
    let headerline = lines[0].characters
      .split(separator: " ", omittingEmptySubsequences: false)
      .map { String($0) }
    
    // Validate Figlet signature
    guard let signature = headerline[0].substring(with: 0..<5), signature == FigletHeader.signature else {
        throw Figlet.FigError.header(.signature)
    }
    
    // These six values are the minimum required, fail if any are invalid
    guard let hardblank = headerline[0].substring(atIndex: 5) else {
      throw Figlet.FigError.header(.hardblank)
    }
    
    guard let height = Int(headerline[1]) else {
      throw Figlet.FigError.header(.height)
    }
    
    guard let baseline = Int(headerline[2]) else {
      throw Figlet.FigError.header(.baseLine)
    }
    
    guard let length = Int(headerline[3]) else {
      throw Figlet.FigError.header(.maxLength)
    }
    
    guard let smushold = Int(headerline[4]) else {
      throw Figlet.FigError.header(.oldlayout)
    }
    
    guard let comments = Int(headerline[5]) else {
      throw Figlet.FigError.header(.commentLines)
    }
    
    // Last line(foot) of FIGcharacter has two endmarks
    let foot = lines[comments + height].trim()
    if foot.characters.count < 2
    {
      throw Figlet.FigError.header(.endmarkInconsistency)
    }
    let footEndmark = foot.substring(from: foot.index(foot.endIndex, offsetBy: -2))
    guard let endmark = footEndmark.substring(atIndex: 0),
      let adjmark = footEndmark.substring(atIndex: 1), endmark == adjmark else {
        throw Figlet.FigError.header(.endmarkInconsistency)
    }
    
    // Find last line with endmark
    var lastIndex = 0
    for idx in (0...lines.count - 1).reversed()
    {
      if lines[idx].contains(endmark.toString())
      {
        lastIndex = idx
        break
      }
    }
    
    self.name = name
    self.signature = signature
    self.hardblank = hardblank
    self.height = height
    self.baseline = baseline
    self.length = length
    self.smushold = smushold
    self.comments = comments
    self.endmark = endmark
    self.lastline = lastIndex
  }
}
