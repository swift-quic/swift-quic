//  Copyright Kenneth Laskoski. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

extension Version {
  static let version1: Version = 1
  static let versionDraft27: Version = 0xff00_001b
  static let versionDraft28: Version = 0xff00_001c
  static let versionDraft29: Version = 0xff00_001d
}

let currentVersion: Version = { .version1 }()

let supportedVersions: [Version] = { [.version1] }()

let knownVersions: [Version] =  {
  [
    .version1,
    .versionDraft27,
    .versionDraft28,
    .versionDraft29,
  ]
}()

func isKnown(version: Version) -> Bool {
  knownVersions.contains(version)
}

func isSupported(version: Version) -> Bool {
  supportedVersions.contains(version)
}

let minDatagramSize = { 1200 }()
let maxConnectionIDLength = { 20 }()
