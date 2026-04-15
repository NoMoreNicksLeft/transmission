// This file Copyright © Transmission authors and contributors.
// It may be used under the MIT (SPDX: MIT) license.
// License text can be found in the licenses/ folder.

#import "InfoHistoryViewController.h"
#import "Torrent.h"
#import "Controller.h"

// Column identifiers — Seq is in the XIB, Hash is added programmatically
static NSString* const kSeqColumnId = @"Seq";
static NSString* const kHashColumnId = @"Hash";

@interface InfoHistoryViewController ()

@property(nonatomic) NSArray<Torrent*>* fTorrents;

// UI outlets
@property(nonatomic, weak) IBOutlet NSTableView* fHistoryTable;
@property(nonatomic, weak) IBOutlet NSButton* fDownloadButton;
@property(nonatomic, weak) IBOutlet NSTextField* fPlaceholderLabel;

// Data — each entry is @{@"seq": NSNumber, @"hash": NSString (40-char hex)}
@property(nonatomic) NSMutableArray<NSDictionary*>* fHistoryEntries;

@end

@implementation InfoHistoryViewController

- (instancetype)init
{
    if ((self = [super initWithNibName:@"InfoHistoryView" bundle:nil]))
    {
        self.title = NSLocalizedString(@"History", "Inspector -> tab");
        self.fHistoryEntries = [[NSMutableArray alloc] init];
    }
    return self;
}

- (void)awakeFromNib
{
    [super awakeFromNib];

    CGFloat const height = [NSUserDefaults.standardUserDefaults floatForKey:@"InspectorContentHeightHistory"];
    if (height != 0.0)
    {
        NSRect viewRect = self.view.frame;
        viewRect.size.height = height;
        self.view.frame = viewRect;
    }

    // Both columns are created in code to avoid XIB auto-resize issues
    if (self.fHistoryTable.numberOfColumns == 0)
    {
        NSTextFieldCell* seqDataCell = [[NSTextFieldCell alloc] initTextCell:@""];
        seqDataCell.font = [NSFont systemFontOfSize:11.0];
        seqDataCell.alignment = NSTextAlignmentCenter;

        NSTableColumn* seqCol = [[NSTableColumn alloc] initWithIdentifier:kSeqColumnId];
        seqCol.title = NSLocalizedString(@"Version", "inspector -> history table -> header");
        seqCol.width = 60;
        seqCol.minWidth = 40;
        seqCol.maxWidth = 80;
        seqCol.editable = NO;
        seqCol.dataCell = seqDataCell;
        [self.fHistoryTable addTableColumn:seqCol];

        NSTextFieldCell* hashDataCell = [[NSTextFieldCell alloc] initTextCell:@""];
        hashDataCell.font = [NSFont monospacedSystemFontOfSize:10.0 weight:NSFontWeightRegular];
        hashDataCell.lineBreakMode = NSLineBreakByTruncatingMiddle;

        NSTableColumn* hashCol = [[NSTableColumn alloc] initWithIdentifier:kHashColumnId];
        hashCol.title = NSLocalizedString(@"Info Hash", "inspector -> history table -> header");
        hashCol.width = 350;
        hashCol.minWidth = 150;
        hashCol.editable = NO;
        hashCol.dataCell = hashDataCell;
        [self.fHistoryTable addTableColumn:hashCol];
    }

    self.fHistoryTable.doubleAction = @selector(downloadSelectedVersion:);
    self.fHistoryTable.target = self;
}

#pragma mark - InfoViewController

- (void)setInfoForTorrents:(NSArray<Torrent*>*)torrents
{
    self.fTorrents = torrents;
    [self updateInfo];
}

- (void)updateInfo
{
    [self.fHistoryEntries removeAllObjects];

    BOOL const singleBtpk = (self.fTorrents.count == 1 && self.fTorrents.firstObject.hasBtpk);

    if (singleBtpk)
    {
        Torrent* torrent = self.fTorrents.firstObject;
        NSArray<NSDictionary*>* history = torrent.btpkHistory;
        [self.fHistoryEntries addObjectsFromArray:history];

        // Sort descending by seq — newest first
        [self.fHistoryEntries sortUsingComparator:^NSComparisonResult(NSDictionary* a, NSDictionary* b) {
            return [b[@"seq"] compare:a[@"seq"]];
        }];
    }

    self.fHistoryTable.hidden = !singleBtpk;
    self.fDownloadButton.hidden = !singleBtpk;
    self.fPlaceholderLabel.hidden = singleBtpk;

    if (!singleBtpk)
    {
        if (self.fTorrents.count == 0)
            self.fPlaceholderLabel.stringValue =
                NSLocalizedString(@"No Torrent Selected", "inspector -> history tab -> no selection");
        else if (self.fTorrents.count > 1)
            self.fPlaceholderLabel.stringValue =
                NSLocalizedString(@"Select a single torrent to view its history.",
                                  "inspector -> history tab -> multiple selected");
        else
            self.fPlaceholderLabel.stringValue =
                NSLocalizedString(@"This torrent is not updatable.",
                                  "inspector -> history tab -> not btpk");
    }

    [self.fHistoryTable reloadData];
    [self updateDownloadButton];
}

- (void)saveViewSize
{
    [NSUserDefaults.standardUserDefaults setFloat:NSHeight(self.view.frame) forKey:@"InspectorContentHeightHistory"];
}

#pragma mark - Actions

- (IBAction)downloadSelectedVersion:(id)sender
{
    NSInteger row = self.fHistoryTable.selectedRow;
    if (row < 0 || (NSUInteger)row >= self.fHistoryEntries.count)
        return;

    NSDictionary* entry = self.fHistoryEntries[row];
    NSString* hashString = entry[@"hash"];

    NSString* magnetURI = [NSString stringWithFormat:@"magnet:?xt=urn:btih:%@", hashString];
    Controller* controller = (Controller*)NSApp.delegate;
    [controller openURL:magnetURI];
}

#pragma mark - NSTableViewDataSource (cell-based)

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView
{
    return self.fHistoryEntries.count;
}

- (id)tableView:(NSTableView*)tableView objectValueForTableColumn:(NSTableColumn*)tableColumn row:(NSInteger)row
{
    if ((NSUInteger)row >= self.fHistoryEntries.count)
        return @"";

    NSDictionary* entry = self.fHistoryEntries[row];
    NSString* identifier = tableColumn.identifier;

    if ([identifier isEqualToString:kSeqColumnId])
    {
        return [NSString stringWithFormat:@"%@", entry[@"seq"]];
    }
    else if ([identifier isEqualToString:kHashColumnId])
    {
        return entry[@"hash"];
    }
    return @"";
}

#pragma mark - NSTableViewDelegate

- (void)tableViewSelectionDidChange:(NSNotification*)notification
{
    [self updateDownloadButton];
}

#pragma mark - Private

- (void)updateDownloadButton
{
    self.fDownloadButton.enabled = (self.fHistoryTable.selectedRow >= 0);
}

@end
