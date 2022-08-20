//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

/// A type with values represented by some (fixed) subset of bits in a byte
///
/// Bits in the `rawValue` may be set to `1` only if the respective `mask` bit is `1`,
/// all bits  where the `mask` is `0` are cleared to `0`.
///
protocol ByteFragment: Sendable, Hashable, RawRepresentable where RawValue == UInt8 {

  /// A type property defining relevant bits
  static var mask: RawValue { get }

  /// Creates a new instance from the bit pattern of the given `source` by
  /// applying (`&`) the `mask` to fit this type.
  ///
  /// Where the bit of `mask` is set to `1` the bit in `source` is
  /// left unchanged, where
  /// least-significant bits of `source`. For example, when converting a
  /// 16-bit value to an 8-bit type, only the lower 8 bits of `source` are
  /// used.
  ///
  ///     let p: Int16 = -500
  ///     // 'p' has a binary representation of 11111110_00001100
  ///     let q = Int8(truncatingIfNeeded: p)
  ///     // q == 12
  ///     // 'q' has a binary representation of 00001100
  ///
  /// When the bit width of `T` is less than this type's bit width, the result
  /// is *sign-extended* to fill the remaining bits. That is, if `source` is
  /// negative, the result is padded with ones; otherwise, the result is
  /// padded with zeros.
  ///
  ///     let u: Int8 = 21
  ///     // 'u' has a binary representation of 00010101
  ///     let v = Int16(truncatingIfNeeded: u)
  ///     // v == 21
  ///     // 'v' has a binary representation of 00000000_00010101
  ///
  ///     let w: Int8 = -21
  ///     // 'w' has a binary representation of 11101011
  ///     let x = Int16(truncatingIfNeeded: w)
  ///     // x == -21
  ///     // 'x' has a binary representation of 11111111_11101011
  ///     let y = UInt16(truncatingIfNeeded: w)
  ///     // y == 65515
  ///     // 'y' has a binary representation of 11111111_11101011
  ///
  /// - Parameter source: An integer to convert to this type.
  init(truncatingIfNeeded source: RawValue)
}

extension ByteFragment {
  init(truncatingIfNeeded source: RawValue) {
    self.init(rawValue: source & Self.mask)!
  }
}
