// This file Copyright © Transmission authors and contributors.
// It may be used under the MIT (SPDX: MIT) license.
// License text can be found in the licenses/ folder.

#import <AppKit/AppKit.h>

#import "InfoViewController.h"

@interface InfoOptionsViewController : NSViewController<InfoViewController>

- (NSRect)viewRect;
- (void)checkLayout;
- (void)checkWindowSize;
- (void)updateWindowLayout;

- (void)setInfoForTorrents:(NSArray<Torrent*>*)torrents;
- (void)updateInfo;
- (void)updateOptions;

- (IBAction)setUseSpeedLimit:(id)sender;
- (IBAction)setSpeedLimit:(id)sender;
- (IBAction)setUseGlobalSpeedLimit:(id)sender;

- (IBAction)setRatioSetting:(id)sender;
- (IBAction)setRatioLimit:(id)sender;

- (IBAction)setIdleSetting:(id)sender;
- (IBAction)setIdleLimit:(id)sender;

- (IBAction)setRemoveWhenSeedingCompletes:(id)sender;

- (IBAction)setPriority:(id)sender;

- (IBAction)setPeersConnectLimit:(id)sender;

- (IBAction)setBtpkUpdateMode:(id)sender;
- (IBAction)setBtpkAllowAdditional:(id)sender;
- (IBAction)setBtpkAllowRenaming:(id)sender;
- (IBAction)setBtpkAllowOverwrites:(id)sender;
- (IBAction)setBtpkAllowDeletions:(id)sender;
- (IBAction)setBtpkVersionsToKeep:(id)sender;
- (IBAction)setBtpkMaxStorageGb:(id)sender;
- (void)updateBtpkViewHeight;

@property(nonatomic) IBOutlet NSView* fPriorityView;
@property(nonatomic) IBOutlet NSView* fBtpkView;
@property(nonatomic) IBOutlet NSLayoutConstraint* fBtpkHeightConstraint;
@property(nonatomic) IBOutlet NSPopUpButton* fBtpkModePopUp;
@property(nonatomic) IBOutlet NSButton* fBtpkAllowAdditionalCheck;
@property(nonatomic) IBOutlet NSButton* fBtpkAllowRenamingCheck;
@property(nonatomic) IBOutlet NSButton* fBtpkAllowOverwritesCheck;
@property(nonatomic) IBOutlet NSButton* fBtpkAllowDeletionsCheck;
@property(nonatomic) IBOutlet NSTextField* fBtpkVersionsField;
@property(nonatomic) IBOutlet NSTextField* fBtpkStorageField;
@property(nonatomic) IBOutlet NSTextField* fBtpkVersionsLabel;
@property(nonatomic) IBOutlet NSTextField* fBtpkStorageLabel;
@property(nonatomic) IBOutlet NSTextField* fBtpkVersionsUnit;
@property(nonatomic) IBOutlet NSTextField* fBtpkStorageUnit;
@property(nonatomic) CGFloat oldHeight;

@end
