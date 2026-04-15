// This file Copyright © Transmission authors and contributors.
// It may be used under the MIT (SPDX: MIT) license.
// License text can be found in the licenses/ folder.

#import <AppKit/AppKit.h>

#import "InfoViewController.h"

@interface InfoHistoryViewController : NSViewController<InfoViewController, NSTableViewDelegate, NSTableViewDataSource>

- (void)setInfoForTorrents:(NSArray<Torrent*>*)torrents;
- (void)updateInfo;
- (void)saveViewSize;

- (IBAction)downloadSelectedVersion:(id)sender;

@end
