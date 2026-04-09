// This file Copyright © Transmission authors and contributors.
// It may be used under the MIT (SPDX: MIT) license.
// License text can be found in the licenses/ folder.

#import "InfoGeneralViewController.h"
#import "NSStringAdditions.h"
#import "Torrent.h"

@interface InfoGeneralViewController ()

@property(nonatomic, copy) NSArray<Torrent*>* fTorrents;

@property(nonatomic) BOOL fSet;

@property(nonatomic) IBOutlet NSTextField* fPiecesField;
@property(nonatomic) IBOutlet NSTextField* fHashField;
@property(nonatomic) IBOutlet NSTextField* fSecureField;
@property(nonatomic) IBOutlet NSTextField* fDataLocationField;
@property(nonatomic) IBOutlet NSTextField* fLastDataLocationField;
@property(nonatomic) IBOutlet NSTextField* fLastDataLabel;
@property(nonatomic) IBOutlet NSTextField* fCreatorField;
@property(nonatomic) IBOutlet NSTextField* fDateCreatedField;

@property(nonatomic) IBOutlet NSTextField* fBtpkUpdateFeedLabel;
@property(nonatomic) IBOutlet NSTextField* fBtpkUpdateFeedField;
@property(nonatomic) IBOutlet NSTextField* fBtpkFingerprintLabel;
@property(nonatomic) IBOutlet NSTextField* fBtpkFingerprintField;
@property(nonatomic) IBOutlet NSTextField* fBtpkSeqLabel;
@property(nonatomic) IBOutlet NSTextField* fBtpkSeqField;

@property(nonatomic) IBOutlet NSTextView* fCommentView;

@property(nonatomic) IBOutlet NSButton* fRevealDataButton;

@end

@implementation InfoGeneralViewController

- (instancetype)init
{
    if ((self = [super initWithNibName:@"InfoGeneralView" bundle:nil]))
    {
        self.title = NSLocalizedString(@"General Info", "Inspector view -> title");
    }

    return self;
}

- (void)setInfoForTorrents:(NSArray<Torrent*>*)torrents
{
    //don't check if it's the same in case the metadata changed
    self.fTorrents = torrents;

    self.fSet = NO;
}

- (void)updateInfo
{
    if (!self.fSet)
    {
        [self setupInfo];
    }

    if (self.fTorrents.count != 1)
    {
        return;
    }

    Torrent* torrent = self.fTorrents[0];

    NSString* location = torrent.dataLocation;
    NSString* lastKnownDataLocation = torrent.lastKnownDataLocation;

    self.fDataLocationField.stringValue = location ? location.stringByAbbreviatingWithTildeInPath : @"";
    self.fDataLocationField.toolTip = location ? location : @"";

    self.fLastDataLabel.hidden = location ? YES : NO;
    self.fLastDataLocationField.hidden = location ? YES : NO;
    self.fLastDataLocationField.stringValue = location ? @"" : lastKnownDataLocation.stringByAbbreviatingWithTildeInPath ?: @"";
    self.fLastDataLocationField.toolTip = location ? @"" : lastKnownDataLocation;

    self.fRevealDataButton.hidden = location ? NO : YES;

    // Refresh btpk seq live (it updates as DHT resolves)
    if (torrent.hasBtpk && self.fBtpkSeqField)
    {
        NSInteger const seq = torrent.btpkSeq;
        self.fBtpkSeqField.stringValue = seq >= 0 ? [NSString stringWithFormat:@"%ld", seq] : @"\u2014";
    }
}

- (void)revealDataFile:(id)sender
{
    Torrent* torrent = self.fTorrents[0];
    NSString* location = torrent.dataLocation;
    if (!location)
    {
        return;
    }

    NSURL* file = [NSURL fileURLWithPath:location];
    [NSWorkspace.sharedWorkspace activateFileViewerSelectingURLs:@[ file ]];
}

#pragma mark - Private

- (void)setupInfo
{
    self.fLastDataLabel.hidden = YES;
    self.fLastDataLocationField.hidden = YES;

    if (self.fTorrents.count == 1)
    {
        Torrent* torrent = self.fTorrents[0];

        // Associated Press Style: "Use a semicolon to clarify a series that includes a number of commas."
        NSString* piecesString = !torrent.magnet ?
            [NSString localizedStringWithFormat:@"%ld; %@", torrent.pieceCount, [NSString stringForFileSize:torrent.pieceSize]] :
            @"";
        self.fPiecesField.stringValue = piecesString;

        NSString* hashString = torrent.hashString;
        self.fHashField.stringValue = hashString;
        self.fHashField.toolTip = hashString;
        self.fSecureField.stringValue = torrent.privateTorrent ?
            NSLocalizedString(@"Private Torrent, non-tracker peer discovery disabled", "Inspector -> private torrent") :
            NSLocalizedString(@"Public Torrent", "Inspector -> private torrent");

        NSString* commentString = torrent.comment;
        self.fCommentView.string = commentString;

        NSString* creatorString = torrent.creator;
        self.fCreatorField.stringValue = creatorString;
        self.fDateCreatedField.objectValue = torrent.dateCreated;

        // btpk update feed info
        BOOL const hasBtpk = torrent.hasBtpk;
        self.fBtpkUpdateFeedLabel.hidden = !hasBtpk;
        self.fBtpkUpdateFeedField.hidden = !hasBtpk;
        self.fBtpkFingerprintLabel.hidden = !hasBtpk;
        self.fBtpkFingerprintField.hidden = !hasBtpk;
        self.fBtpkSeqLabel.hidden = !hasBtpk;
        self.fBtpkSeqField.hidden = !hasBtpk;
        if (hasBtpk)
        {
            NSString* fingerprint = torrent.btpkFingerprintString ?: @"";
            self.fBtpkFingerprintField.stringValue = fingerprint;
            self.fBtpkFingerprintField.toolTip = fingerprint;

            NSInteger const seq = torrent.btpkSeq;
            self.fBtpkSeqField.stringValue = seq >= 0 ? [NSString stringWithFormat:@"%ld", seq] : @"\u2014";

            NSString* modeName;
            switch (torrent.btpkUpdateMode)
            {
            case BtpkUpdateModeWhenOffered:
                modeName = NSLocalizedString(@"When offered", "Inspector -> btpk update mode");
                break;
            case BtpkUpdateModeVersioned:
                modeName = NSLocalizedString(@"Always versioned", "Inspector -> btpk update mode");
                break;
            case BtpkUpdateModeNever:
            default:
                modeName = NSLocalizedString(@"Never", "Inspector -> btpk update mode");
                break;
            }
            self.fBtpkUpdateFeedField.stringValue = modeName;
        }
    }
    else
    {
        self.fPiecesField.stringValue = @"";
        self.fHashField.stringValue = @"";
        self.fHashField.toolTip = nil;
        self.fSecureField.stringValue = @"";
        self.fCommentView.string = @"";

        self.fCreatorField.stringValue = @"";
        self.fDateCreatedField.stringValue = @"";

        self.fBtpkUpdateFeedLabel.hidden = YES;
        self.fBtpkUpdateFeedField.hidden = YES;
        self.fBtpkFingerprintLabel.hidden = YES;
        self.fBtpkFingerprintField.hidden = YES;
        self.fBtpkSeqLabel.hidden = YES;
        self.fBtpkSeqField.hidden = YES;

        self.fDataLocationField.stringValue = @"";
        self.fDataLocationField.toolTip = nil;

        self.fRevealDataButton.hidden = YES;
    }

    self.fSet = YES;
}

@end
