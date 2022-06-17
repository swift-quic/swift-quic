//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

protocol Header {
  var form: HeaderForm { get }
}

extension Header {
  func isLong() -> Bool { form.isLong() }
  func isShort() -> Bool { form.isShort() }
}
