// This file Copyright © Transmission authors and contributors.
// It may be used under the MIT (SPDX: MIT) license.
// License text can be found in the licenses/ folder.

#import <AppKit/AppKit.h>

@class Torrent;

@interface BtpkUpdatePanelController : NSWindowController

+ (instancetype)presentForTorrent:(Torrent*)torrent;

- (IBAction)publishUpdate:(id)sender;
- (IBAction)cancelUpdate:(id)sender;

@end
