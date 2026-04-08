// This file Copyright © Transmission authors and contributors.
// It may be used under the MIT (SPDX: MIT) license.
// License text can be found in the licenses/ folder.

#import "BtpkUpdatePanelController.h"
#import "Torrent.h"

#include "libtransmission/btpk-utils.h"

@interface BtpkUpdatePanelController ()<NSControlTextEditingDelegate>

// Identity display
@property(nonatomic, weak) IBOutlet NSTextField* fNameField;
@property(nonatomic, weak) IBOutlet NSTextField* fFingerprintField;

// Key input
@property(nonatomic, weak) IBOutlet NSTextField* fKeyField;
@property(nonatomic, weak) IBOutlet NSTextField* fKeyStatusField;

// Buttons
@property(nonatomic, weak) IBOutlet NSButton* fPublishButton;
@property(nonatomic, weak) IBOutlet NSButton* fCancelButton;

@property(nonatomic) Torrent* fTorrent;

@end

@implementation BtpkUpdatePanelController

+ (instancetype)presentForTorrent:(Torrent*)torrent
{
    NSParameterAssert(torrent != nil);
    NSParameterAssert(torrent.hasBtpk);

    BtpkUpdatePanelController* controller = [[BtpkUpdatePanelController alloc] initWithWindowNibName:@"BtpkUpdatePanelController"];
    controller.fTorrent = torrent;

    // Force window load, then configure as floating panel
    NSPanel* panel = (NSPanel*)controller.window;
    panel.floatingPanel = YES;
    panel.becomesKeyOnlyIfNeeded = YES;
    [panel setLevel:NSFloatingWindowLevel];

    // Open Finder to the torrent content folder, then position panel top-right
    NSString* dataLocation = torrent.dataLocation;
    if (dataLocation)
    {
        NSString* containingDir = [dataLocation stringByDeletingLastPathComponent];
        [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:containingDir]];

        NSScreen* screen = NSScreen.mainScreen;
        NSRect screenRect = screen.visibleFrame;
        NSRect panelFrame = panel.frame;
        panelFrame.origin.x = NSMaxX(screenRect) - NSWidth(panelFrame) - 20.0;
        panelFrame.origin.y = NSMaxY(screenRect) - NSHeight(panelFrame) - 20.0;
        [panel setFrame:panelFrame display:NO];
    }

    [panel orderFront:nil];
    return controller;
}

- (void)windowDidLoad
{
    [super windowDidLoad];

    self.fNameField.stringValue = self.fTorrent.name;
    self.fFingerprintField.stringValue = self.fTorrent.btpkFingerprintString ?: @"";

    self.fKeyField.placeholderString = NSLocalizedString(@"Paste private key (PEM format)", "btpk update panel -> key field placeholder");
    self.fKeyStatusField.stringValue = @"";
    self.fPublishButton.enabled = NO;
}

#pragma mark - Actions

- (IBAction)publishUpdate:(id)sender
{
    NSString* pemString = [self.fKeyField.stringValue stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];

    // Parse the PEM key into raw bytes
    auto keyOpt = libtransmission::tr_btpk_private_key_from_pem(pemString.UTF8String);
    if (!keyOpt)
    {
        self.fKeyStatusField.stringValue = NSLocalizedString(@"Invalid key \u2014 paste the PEM block from your password manager.",
                                                             "btpk update panel -> bad key message");
        self.fKeyStatusField.textColor = NSColor.systemRedColor;
        NSBeep();
        return;
    }

    auto& privKey = *keyOpt;

    // Wrap in NSData to cross the C++ boundary into Torrent
    NSData* keyData = [NSData dataWithBytes:privKey.data() length:privKey.size()];

    // Zero our local copy now — Torrent takes its own copy via NSData
    libtransmission::tr_btpk_zero_key(privKey);

    // Verify the key matches before committing to the publish
    if (![self.fTorrent btpkPrivateKeyMatchesData:keyData])
    {
        self.fKeyStatusField.stringValue = NSLocalizedString(@"This key does not match the torrent\u2019s public key.",
                                                             "btpk update panel -> key mismatch message");
        self.fKeyStatusField.textColor = NSColor.systemRedColor;
        NSBeep();
        return;
    }

    self.fKeyStatusField.stringValue = NSLocalizedString(@"Scanning files and publishing\u2026", "btpk update panel -> publishing status");
    self.fKeyStatusField.textColor = NSColor.secondaryLabelColor;
    self.fPublishButton.enabled = NO;
    self.fCancelButton.enabled = NO;

    [self.fTorrent publishBtpkUpdateWithKeyData:keyData completionHandler:^(NSString* _Nullable newMagnetLink, NSError* _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error)
            {
                self.fKeyStatusField.stringValue = error.localizedDescription;
                self.fKeyStatusField.textColor = NSColor.systemRedColor;
                self.fPublishButton.enabled = YES;
                self.fCancelButton.enabled = YES;
            }
            else
            {
                if (newMagnetLink)
                {
                    [NSPasteboard.generalPasteboard clearContents];
                    [NSPasteboard.generalPasteboard setString:newMagnetLink forType:NSPasteboardTypeString];
                }
                NSAlert* alert = [[NSAlert alloc] init];
                alert.messageText = NSLocalizedString(@"Update published.", "btpk update -> success title");
                alert.informativeText = NSLocalizedString(@"The magnet link has been copied to the clipboard.", "btpk update -> success body");
                [alert addButtonWithTitle:NSLocalizedString(@"OK", "button")];
                [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse __unused r) {
                    [self.window close];
                }];
            }
        });
    }];
}

- (IBAction)cancelUpdate:(id)sender
{
    [self.window close];
}

#pragma mark - NSControlTextEditingDelegate

- (void)controlTextDidChange:(NSNotification*)notification
{
    NSString* trimmed = [self.fKeyField.stringValue stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    BOOL looksLikePem = [trimmed hasPrefix:@"-----BEGIN"];
    self.fPublishButton.enabled = looksLikePem && trimmed.length > 0;
    self.fKeyStatusField.stringValue = @"";
}

@end
