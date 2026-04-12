// This file Copyright © Transmission authors and contributors.
// It may be used under the MIT (SPDX: MIT) license.
// License text can be found in the licenses/ folder.

#include <chrono>
#include <cmath>
#include <future>
#include <optional>
#include <utility>

#include <libtransmission/transmission.h>

#include <libtransmission/error.h>
#include <libtransmission/btpk-utils.h>
#include <libtransmission/makemeta.h>
#include <libtransmission/utils.h>
#include <libtransmission/web-utils.h> // tr_urlIsValidTracker()

#import "CreatorWindowController.h"
#import "Controller.h"
#import "NSStringAdditions.h"

typedef NS_ENUM(NSUInteger, TrackerSegmentTag) {
    TrackerSegmentTagAdd = 0,
    TrackerSegmentTagRemove = 1,
};

@interface CreatorWindowController ()<NSWindowRestoration, NSMenuItemValidation, NSTextFieldDelegate>

@property(nonatomic) IBOutlet NSImageView* fIconView;
@property(nonatomic) IBOutlet NSTextField* fNameField;
@property(nonatomic) IBOutlet NSTextField* fStatusField;
@property(nonatomic) IBOutlet NSTextField* fPiecesField;
@property(nonatomic) IBOutlet NSTextField* fLocationField;
@property(nonatomic) IBOutlet NSTableView* fTrackerTable;
@property(nonatomic) IBOutlet NSSegmentedControl* fTrackerAddRemoveControl;
@property(nonatomic) IBOutlet NSTextView* fCommentView;
@property(nonatomic) IBOutlet NSButton* fPrivateCheck;
@property(nonatomic) IBOutlet NSButton* fOpenCheck;
@property(nonatomic) IBOutlet NSTextField* fSource;

// BEP 46 btpk controls
@property(nonatomic) IBOutlet NSButton* fMutableCheck;
@property(nonatomic) IBOutlet NSTextField* fBtpkKeyField;
@property(nonatomic) IBOutlet NSButton* fBtpkGenerate;
@property(nonatomic) IBOutlet NSButton* fBtpkCopy;
@property(nonatomic) IBOutlet NSTextField* fBtpkFingerprint;
@property(nonatomic) IBOutlet NSStepper* fPieceSizeStepper;

@property(nonatomic) IBOutlet NSView* fProgressView;
@property(nonatomic) IBOutlet NSProgressIndicator* fProgressIndicator;

@property(nonatomic, readonly) std::shared_ptr<tr_metainfo_builder> fBuilder;
@property(nonatomic, readonly) NSURL* fPath;
@property(nonatomic) std::shared_future<tr_error> fFuture;
@property(nonatomic) NSURL* fLocation; // path to new torrent file
@property(nonatomic) NSMutableArray<NSString*>* fTrackers;

@property(nonatomic) NSTimer* fTimer;
@property(nonatomic) BOOL fStarted;
@property(nonatomic) BOOL fOpenWhenCreated;

@property(nonatomic, readonly) NSUserDefaults* fDefaults;

@end

static NSMutableSet* creatorWindowControllerSet;

@implementation CreatorWindowController

+ (CreatorWindowController*)createTorrentFile:(tr_session*)handle
{
    //get file/folder for torrent
    NSURL* path;
    if (!(path = [CreatorWindowController chooseFile]))
    {
        return nil;
    }

    CreatorWindowController* creator = [[self alloc] initWithHandle:handle path:path];
    [creator showWindow:nil];
    return creator;
}

+ (CreatorWindowController*)createTorrentFile:(tr_session*)handle forFile:(NSURL*)file
{
    CreatorWindowController* creator = [[self alloc] initWithHandle:handle path:file];
    [creator showWindow:nil];
    return creator;
}

- (instancetype)initWithHandle:(tr_session*)handle path:(NSURL*)path
{
    if ((self = [super initWithWindowNibName:@"Creator"]))
    {
        if (!creatorWindowControllerSet)
        {
            creatorWindowControllerSet = [NSMutableSet set];
        }

        _fStarted = NO;

        _fPath = path;
        _fBuilder = std::make_shared<tr_metainfo_builder>(_fPath.path.UTF8String);

        if (_fBuilder->file_count() == 0U)
        {
            NSAlert* alert = [[NSAlert alloc] init];
            [alert addButtonWithTitle:NSLocalizedString(@"OK", "Create torrent -> no files -> button")];
            alert.messageText = NSLocalizedString(@"This folder contains no files.", "Create torrent -> no files -> title");
            alert.informativeText = NSLocalizedString(@"There must be at least one file in a folder to create a torrent file.",
                                                      "Create torrent -> no files -> warning");
            alert.alertStyle = NSAlertStyleWarning;

            [alert runModal];

            return nil;
        }
        if (_fBuilder->total_size() == 0U)
        {
            NSAlert* alert = [[NSAlert alloc] init];
            [alert addButtonWithTitle:NSLocalizedString(@"OK", "Create torrent -> zero size -> button")];
            alert.messageText = NSLocalizedString(@"The total file size is zero bytes.", "Create torrent -> zero size -> title");
            alert.informativeText = NSLocalizedString(@"A torrent file cannot be created for files with no size.",
                                                      "Create torrent -> zero size -> warning");
            alert.alertStyle = NSAlertStyleWarning;

            [alert runModal];

            return nil;
        }

        _fDefaults = NSUserDefaults.standardUserDefaults;

        //get list of trackers
        if (!(_fTrackers = [[_fDefaults arrayForKey:@"CreatorTrackers"] mutableCopy]))
        {
            _fTrackers = [[NSMutableArray alloc] init];

            //check for single tracker from versions before 1.3
            NSString* tracker;
            if ((tracker = [_fDefaults stringForKey:@"CreatorTracker"]))
            {
                [_fDefaults removeObjectForKey:@"CreatorTracker"];
                if (![tracker isEqualToString:@""])
                {
                    [_fTrackers addObject:tracker];
                    [_fDefaults setObject:_fTrackers forKey:@"CreatorTrackers"];
                }
            }
        }

        //remove potentially invalid addresses
        for (NSInteger i = _fTrackers.count - 1; i >= 0; i--)
        {
            if (!tr_urlIsValidTracker(_fTrackers[i].UTF8String))
            {
                [_fTrackers removeObjectAtIndex:i];
            }
        }

        [creatorWindowControllerSet addObject:self];
    }
    return self;
}

- (void)awakeFromNib
{
    [super awakeFromNib];
    self.window.restorationClass = [self class];

    NSString* name = self.fPath.lastPathComponent;

    self.window.title = name;

    //disable fullscreen support
    self.window.collectionBehavior = NSWindowCollectionBehaviorFullScreenNone;

    self.fNameField.stringValue = name;
    self.fNameField.toolTip = self.fPath.path;

    auto const is_folder = self.fBuilder->file_count() > 1 || tr_strv_contains(self.fBuilder->path(0), '/');

    NSImage* icon = [NSWorkspace.sharedWorkspace
        iconForFileType:is_folder ? NSFileTypeForHFSTypeCode(kGenericFolderIcon) : self.fPath.pathExtension];
    icon.size = self.fIconView.frame.size;
    self.fIconView.image = icon;

    NSString* status_string = [NSString stringForFileSize:self.fBuilder->total_size()];
    if (is_folder)
    {
        NSUInteger const count = self.fBuilder->file_count();
        NSString* const fileString = count != 1 ?
            [NSString localizedStringWithFormat:NSLocalizedString(@"%lu files", "Create torrent -> info"), count] :
            NSLocalizedString(@"1 file", "Create torrent -> info");
        status_string = [NSString stringWithFormat:@"%@, %@", fileString, status_string];
    }
    self.fStatusField.stringValue = status_string;

    [self updatePiecesField];
    self.fPieceSizeStepper.intValue = static_cast<int>(log2(self.fBuilder->piece_size()));

    self.fLocation = [[self.fDefaults URLForKey:@"CreatorLocationURL"]
        URLByAppendingPathComponent:[name stringByAppendingPathExtension:@"torrent"]];
    if (!self.fLocation)
    {
        //Compatibility with Transmission 2.5 and earlier,
        //when it was "CreatorLocation" and not "CreatorLocationURL"
        NSString* location = [self.fDefaults stringForKey:@"CreatorLocation"];
        self.fLocation = [[NSURL alloc]
            initFileURLWithPath:[location.stringByExpandingTildeInPath
                                    stringByAppendingPathComponent:[name stringByAppendingPathExtension:@"torrent"]]];
    }
    [self updateLocationField];

    //set previously saved values
    if ([self.fDefaults objectForKey:@"CreatorPrivate"])
    {
        self.fPrivateCheck.state = [self.fDefaults boolForKey:@"CreatorPrivate"] ? NSControlStateValueOn : NSControlStateValueOff;
    }

    if ([self.fDefaults objectForKey:@"CreatorSource"])
    {
        self.fSource.stringValue = [self.fDefaults stringForKey:@"CreatorSource"];
    }

    self.fOpenCheck.state = [self.fDefaults boolForKey:@"CreatorOpen"] ? NSControlStateValueOn : NSControlStateValueOff;

    //set tracker table column width to table width
    [self.fTrackerTable sizeToFit];

    // BEP 46: btpk controls start disabled until the checkbox is checked
    self.fBtpkKeyField.enabled = NO;
    self.fBtpkGenerate.enabled = NO;
    self.fBtpkCopy.enabled = NO;

    // Use SF Symbol for the copy button — looks native and scales correctly
    NSImage* copyImage = [NSImage imageWithSystemSymbolName:@"doc.on.doc" accessibilityDescription:@"Copy to clipboard"];
    if (copyImage)
    {
        // Icon + label, icon on left
        self.fBtpkCopy.image = copyImage;
        self.fBtpkCopy.imagePosition = NSImageLeft;
        self.fBtpkCopy.imageScaling = NSImageScaleProportionallyDown;
    }
    // Watch the key field for paste/type so we can update the fingerprint live
    self.fBtpkKeyField.delegate = self;
}

- (void)dealloc
{
    _fBuilder.reset();

    [_fTimer invalidate];
}

+ (void)restoreWindowWithIdentifier:(NSString*)identifier
                              state:(NSCoder*)state
                  completionHandler:(void (^)(NSWindow*, NSError*))completionHandler
{
    NSURL* path = [state decodeObjectForKey:@"TRCreatorPath"];
    if (!path || ![path checkResourceIsReachableAndReturnError:nil])
    {
        completionHandler(nil, [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotOpenFile userInfo:nil]);
        return;
    }

    NSWindow* window = [self createTorrentFile:((Controller*)NSApp.delegate).sessionHandle forFile:path].window;
    completionHandler(window, nil);
}

- (void)window:(NSWindow*)window willEncodeRestorableState:(NSCoder*)state
{
    [state encodeObject:self.fPath forKey:@"TRCreatorPath"];
    [state encodeObject:self.fLocation forKey:@"TRCreatorLocation"];
    [state encodeObject:self.fTrackers forKey:@"TRCreatorTrackers"];
    [state encodeInteger:self.fOpenCheck.state forKey:@"TRCreatorOpenCheck"];
    [state encodeInteger:self.fPrivateCheck.state forKey:@"TRCreatorPrivateCheck"];
    [state encodeObject:self.fSource.stringValue forKey:@"TRCreatorSource"];
    [state encodeObject:self.fCommentView.string forKey:@"TRCreatorPrivateComment"];
}

- (void)window:(NSWindow*)window didDecodeRestorableState:(NSCoder*)coder
{
    self.fLocation = [coder decodeObjectForKey:@"TRCreatorLocation"];
    [self updateLocationField];

    self.fTrackers = [coder decodeObjectForKey:@"TRCreatorTrackers"];
    [self.fTrackerTable reloadData];

    self.fOpenCheck.state = [coder decodeIntegerForKey:@"TRCreatorOpenCheck"];
    self.fPrivateCheck.state = [coder decodeIntegerForKey:@"TRCreatorPrivateCheck"];
    self.fSource.stringValue = [coder decodeObjectForKey:@"TRCreatorSource"];
    self.fCommentView.string = [coder decodeObjectForKey:@"TRCreatorPrivateComment"];
}

// Called whenever the text in fBtpkKeyField changes (typing or paste).
// Attempt to parse the current contents as hex or PEM and update the fingerprint.
- (void)controlTextDidChange:(NSNotification*)notification
{
    if (notification.object != self.fBtpkKeyField)
    {
        return;
    }

    auto const key_str = std::string{ self.fBtpkKeyField.stringValue.UTF8String };

    // Try hex
    auto priv = libtransmission::tr_btpk_private_key_from_hex(key_str);
    // Try PEM if hex failed
    if (!priv)
    {
        priv = libtransmission::tr_btpk_private_key_from_pem(key_str);
    }

    if (priv)
    {
        // Valid key — derive public key and show fingerprint
        libtransmission::BtpkPublicKey pub{};
        std::copy_n(priv->data() + 64, 32, pub.data());
        self.fBuilder->set_btpk_public_key(pub);
        // Generate a unique per-torrent salt so each torrent gets its own
        // DHT slot even when the same keypair is reused for multiple torrents.
        // SHA1(pubkey + salt) is the DHT target — without salt all torrents
        // with the same keypair compete for one slot (BEP 44).
        {
            uint8_t saltBytes[8];
            arc4random_buf(saltBytes, sizeof(saltBytes));
            char saltHex[17] = {};
            for (int i = 0; i < 8; i++)
                snprintf(saltHex + i*2, 3, "%02x", saltBytes[i]);
            self.fBuilder->set_btpk_salt(std::string_view{ saltHex, 16 });
        }
        auto const fp = libtransmission::tr_btpk_fingerprint(pub);
        self.fBtpkFingerprint.stringValue = [NSString stringWithFormat:@"Fingerprint: %s", fp.c_str()];
        libtransmission::tr_btpk_zero_key(*priv);
        self.fBtpkCopy.enabled = YES;
    }
    else
    {
        // Not yet a valid key — clear fingerprint and btpk state
        self.fBtpkFingerprint.stringValue = @"Fingerprint: —";
        self.fBuilder->clear_btpk();
        self.fBtpkCopy.enabled = NO;
    }
}

- (IBAction)copyBtpkKeyToClipboard:(id)sender
{
    NSString* const displayed = self.fBtpkKeyField.stringValue;
    if (displayed.length == 0)
    {
        return;
    }

    // Parse whatever is in the field (PEM or hex) and copy as PEM —
    // the format suitable for password managers and secure notes.
    auto const key_str = std::string{ displayed.UTF8String };
    auto priv = libtransmission::tr_btpk_private_key_from_pem(key_str);
    if (!priv)
    {
        priv = libtransmission::tr_btpk_private_key_from_hex(key_str);
    }

    NSString* to_copy;
    if (priv)
    {
        auto const pem = libtransmission::tr_btpk_private_key_to_pem(*priv);
        libtransmission::tr_btpk_zero_key(*priv);
        to_copy = [NSString stringWithUTF8String:pem.c_str()];
    }
    else
    {
        // Fallback: copy as-is if we can't parse it
        to_copy = displayed;
    }

    [NSPasteboard.generalPasteboard clearContents];
    [NSPasteboard.generalPasteboard setString:to_copy forType:NSPasteboardTypeString];

    // Brief visual feedback — disable the button momentarily
    self.fBtpkCopy.enabled = NO;
    self.fBtpkCopy.image = nil; // hide icon during feedback
    self.fBtpkCopy.title = @"Copied!";
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        self.fBtpkCopy.title = @"Copy";
        NSImage* img = [NSImage imageWithSystemSymbolName:@"doc.on.doc" accessibilityDescription:@"Copy to clipboard"];
        self.fBtpkCopy.image = img;
        self.fBtpkCopy.imagePosition = NSImageLeft;
        self.fBtpkCopy.enabled = YES;
    });
}

- (IBAction)toggleMutableUpdates:(id)sender
{
    BOOL const enabled = self.fMutableCheck.state == NSControlStateValueOn;
    self.fBtpkKeyField.enabled = enabled;
    self.fBtpkGenerate.enabled = enabled;
    self.fBtpkCopy.enabled = enabled && self.fBtpkKeyField.stringValue.length > 0;
    // Clear the key and fingerprint if the user unchecks the box
    if (!enabled)
    {
        self.fBtpkKeyField.stringValue = @"";
        self.fBtpkFingerprint.stringValue = @"Fingerprint: —";
        self.fBuilder->clear_btpk();
    }
}

- (IBAction)generateBtpkKey:(id)sender
{
    // Generate a fresh ed25519 keypair.
    libtransmission::BtpkPublicKey pub{};
    libtransmission::BtpkPrivateKey priv{};
    libtransmission::tr_btpk_key_generate(pub, priv);

    // Show the private key as PEM — the format password managers expect.
    auto const pem = libtransmission::tr_btpk_private_key_to_pem(priv);
    self.fBtpkKeyField.stringValue = [NSString stringWithUTF8String:pem.c_str()];

    // Show the fingerprint so the user can identify this key later.
    auto const fp = libtransmission::tr_btpk_fingerprint(pub);
    self.fBtpkFingerprint.stringValue = [NSString stringWithFormat:@"Fingerprint: %s", fp.c_str()];

    // Store the public key on the builder — the private key is NOT stored by the app.
    // The user must copy it to their password manager before closing this window.
    self.fBuilder->set_btpk_public_key(pub);
        // Generate a unique per-torrent salt so each torrent gets its own
        // DHT slot even when the same keypair is reused for multiple torrents.
        // SHA1(pubkey + salt) is the DHT target — without salt all torrents
        // with the same keypair compete for one slot (BEP 44).
        {
            uint8_t saltBytes[8];
            arc4random_buf(saltBytes, sizeof(saltBytes));
            char saltHex[17] = {};
            for (int i = 0; i < 8; i++)
                snprintf(saltHex + i*2, 3, "%02x", saltBytes[i]);
            self.fBuilder->set_btpk_salt(std::string_view{ saltHex, 16 });
        }

    // Securely erase the private key from memory — we have no further use for it.
    libtransmission::tr_btpk_zero_key(priv);
    self.fBtpkCopy.enabled = YES;

    // Warn the user to save the key that is now shown in the field.
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = NSLocalizedString(@"Save your private key", @"btpk key generation alert title");
    alert.informativeText = NSLocalizedString(
        @"Your private key is shown in the key field above. Copy it to your password manager now — "
         "the application does not store it. You will need it to publish updates to this torrent.",
        @"btpk key generation alert message");
    [alert addButtonWithTitle:NSLocalizedString(@"OK", @"btpk key generation alert button")];
    [alert beginSheetModalForWindow:self.window completionHandler:nil];
}

- (IBAction)setLocation:(id)sender
{
    NSSavePanel* panel = [NSSavePanel savePanel];

    panel.prompt = NSLocalizedString(@"Select", "Create torrent -> location sheet -> button");
    panel.message = NSLocalizedString(@"Select the name and location for the torrent file.", "Create torrent -> location sheet -> message");

    panel.allowedFileTypes = @[ @"org.bittorrent.torrent", @"torrent" ];
    panel.canSelectHiddenExtension = YES;

    panel.directoryURL = self.fLocation.URLByDeletingLastPathComponent;
    panel.nameFieldStringValue = self.fLocation.lastPathComponent;

    [panel beginSheetModalForWindow:self.window completionHandler:^(NSInteger result) {
        if (result == NSModalResponseOK)
        {
            self.fLocation = panel.URL;
            [self updateLocationField];
        }
    }];
}

- (IBAction)create:(id)sender
{
    //make sure the trackers are no longer being verified
    if (self.fTrackerTable.editedRow != -1)
    {
        [self.window endEditingFor:self.fTrackerTable];
    }

    BOOL const isPrivate = self.fPrivateCheck.state == NSControlStateValueOn;
    if (self.fTrackers.count == 0 && [self.fDefaults boolForKey:isPrivate ? @"WarningCreatorPrivateBlankAddress" : @"WarningCreatorBlankAddress"])
    {
        NSAlert* alert = [[NSAlert alloc] init];
        alert.messageText = NSLocalizedString(@"There are no tracker addresses.", "Create torrent -> blank address -> title");

        NSString* infoString = isPrivate ?
            NSLocalizedString(
                @"A transfer marked as private with no tracker addresses will be unable to connect to peers."
                 " The torrent file will only be useful if you plan to upload the file to a tracker website"
                 " that will add the addresses for you.",
                "Create torrent -> blank address -> message") :
            NSLocalizedString(
                @"The transfer will not contact trackers for peers, and will have to rely solely on"
                 " non-tracker peer discovery methods such as PEX and DHT to download and seed.",
                "Create torrent -> blank address -> message");

        alert.informativeText = infoString;
        [alert addButtonWithTitle:NSLocalizedString(@"Create", "Create torrent -> blank address -> button")];
        [alert addButtonWithTitle:NSLocalizedString(@"Cancel", "Create torrent -> blank address -> button")];
        alert.showsSuppressionButton = YES;

        [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode) {
            if (alert.suppressionButton.state == NSControlStateValueOn)
            {
                [NSUserDefaults.standardUserDefaults setBool:NO forKey:@"WarningCreatorBlankAddress"]; //set regardless of private/public
                if (self.fPrivateCheck.state == NSControlStateValueOn)
                {
                    [NSUserDefaults.standardUserDefaults setBool:NO forKey:@"WarningCreatorPrivateBlankAddress"];
                }
            }

            if (returnCode == NSAlertFirstButtonReturn)
            {
                [self performSelectorOnMainThread:@selector(createReal) withObject:nil waitUntilDone:NO];
            }
        }];
    }
    else
    {
        [self createReal];
    }
}

- (IBAction)cancelCreateWindow:(id)sender
{
    [self.window close];
}

- (void)windowWillClose:(NSNotification*)notification
{
    [creatorWindowControllerSet removeObject:self];
}

- (IBAction)cancelCreateProgress:(id)sender
{
    self.fBuilder->cancel_checksums();
    [self.fTimer fire];
}

- (IBAction)incrementOrDecrementPieceSize:(id)sender
{
    uint32_t const piece_size = 1U << [(NSStepper*)sender intValue];

    if (self.fBuilder->set_piece_size(piece_size))
    {
        [self updatePiecesField];
    }
}

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView
{
    return self.fTrackers.count;
}

- (id)tableView:(NSTableView*)tableView objectValueForTableColumn:(NSTableColumn*)tableColumn row:(NSInteger)row
{
    return self.fTrackers[row];
}

- (IBAction)addRemoveTracker:(id)sender
{
    //don't allow add/remove when currently adding - it leads to weird results
    if (self.fTrackerTable.editedRow != -1)
    {
        return;
    }

    if ([[sender cell] tagForSegment:[sender selectedSegment]] == TrackerSegmentTagRemove)
    {
        [self.fTrackers removeObjectsAtIndexes:self.fTrackerTable.selectedRowIndexes];

        [self.fTrackerTable deselectAll:self];
        [self.fTrackerTable reloadData];
    }
    else
    {
        [self.fTrackers addObject:@""];
        [self.fTrackerTable reloadData];

        NSInteger const row = self.fTrackers.count - 1;
        [self.fTrackerTable selectRowIndexes:[NSIndexSet indexSetWithIndex:row] byExtendingSelection:NO];
        [self.fTrackerTable editColumn:0 row:row withEvent:nil select:YES];
    }
}

- (void)tableView:(NSTableView*)tableView
    setObjectValue:(id)object
    forTableColumn:(NSTableColumn*)tableColumn
               row:(NSInteger)row
{
    NSString* tracker = (NSString*)object;

    tracker = [tracker stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];

    if ([tracker rangeOfString:@"://"].location == NSNotFound)
    {
        tracker = [@"http://" stringByAppendingString:tracker];
    }

    if (!tr_urlIsValidTracker(tracker.UTF8String))
    {
        NSBeep();
        [self.fTrackers removeObjectAtIndex:row];
    }
    else
    {
        self.fTrackers[row] = tracker;
    }

    [self.fTrackerTable deselectAll:self];
    [self.fTrackerTable reloadData];
}

- (void)tableViewSelectionDidChange:(NSNotification*)notification
{
    [self.fTrackerAddRemoveControl setEnabled:self.fTrackerTable.numberOfSelectedRows > 0 forSegment:TrackerSegmentTagRemove];
}

- (void)copy:(id)sender
{
    NSArray* addresses = [self.fTrackers objectsAtIndexes:self.fTrackerTable.selectedRowIndexes];
    NSString* text = [addresses componentsJoinedByString:@"\n"];

    NSPasteboard* pb = NSPasteboard.generalPasteboard;
    [pb clearContents];
    [pb writeObjects:@[ text ]];
}

- (BOOL)validateMenuItem:(NSMenuItem*)menuItem
{
    SEL const action = menuItem.action;

    if (action == @selector(copy:))
    {
        return self.window.firstResponder == self.fTrackerTable && self.fTrackerTable.numberOfSelectedRows > 0;
    }

    if (action == @selector(paste:))
    {
        return self.window.firstResponder == self.fTrackerTable &&
            [NSPasteboard.generalPasteboard canReadObjectForClasses:@[ [NSString class] ] options:nil];
    }

    return YES;
}

- (void)paste:(id)sender
{
    NSMutableArray* tempTrackers = [NSMutableArray array];

    NSArray* items = [NSPasteboard.generalPasteboard readObjectsForClasses:@[ [NSString class] ] options:nil];
    NSAssert(items != nil, @"no string items to paste; should not be able to call this method");

    for (NSString* pbItem in items)
    {
        for (NSString* tracker in [pbItem componentsSeparatedByString:@"\n"])
        {
            [tempTrackers addObject:tracker];
        }
    }

    BOOL added = NO;

    for (__strong NSString* tracker in tempTrackers)
    {
        tracker = [tracker stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];

        if ([tracker rangeOfString:@"://"].location == NSNotFound)
        {
            tracker = [@"http://" stringByAppendingString:tracker];
        }

        if (tr_urlIsValidTracker(tracker.UTF8String))
        {
            [self.fTrackers addObject:tracker];
            added = YES;
        }
    }

    if (added)
    {
        [self.fTrackerTable deselectAll:self];
        [self.fTrackerTable reloadData];
    }
    else
    {
        NSBeep();
    }
}

#pragma mark - Private

- (void)updatePiecesField
{
    auto const piece_size = self.fBuilder->piece_size();
    auto const piece_count = self.fBuilder->piece_count();

    if (piece_count == 1U)
    {
        self.fPiecesField.stringValue = [NSString stringWithFormat:NSLocalizedString(@"1 piece, %@", "Create torrent -> info"),
                                                                   [NSString stringForFileSize:piece_size]];
    }
    else
    {
        self.fPiecesField.stringValue = [NSString stringWithFormat:NSLocalizedString(@"%u pieces, %@ each", "Create torrent -> info"),
                                                                   piece_count,
                                                                   [NSString stringForFileSize:piece_size]];
    }
}

- (void)updateLocationField
{
    NSString* pathString = self.fLocation.path;
    self.fLocationField.stringValue = pathString.stringByAbbreviatingWithTildeInPath;
    self.fLocationField.toolTip = pathString;
}

+ (NSURL*)chooseFile
{
    NSOpenPanel* panel = [NSOpenPanel openPanel];

    panel.title = NSLocalizedString(@"Create Torrent File", "Create torrent -> select file");
    panel.prompt = NSLocalizedString(@"Select", "Create torrent -> select file");
    panel.allowsMultipleSelection = NO;
    panel.canChooseFiles = YES;
    panel.canChooseDirectories = YES;
    panel.canCreateDirectories = NO;

    panel.message = NSLocalizedString(@"Select a file or folder for the torrent file.", "Create torrent -> select file");

    BOOL success = [panel runModal] == NSModalResponseOK;
    return success ? panel.URLs[0] : nil;
}

- (void)createReal
{
    //check if the location currently exists
    if (![self.fLocation.URLByDeletingLastPathComponent checkResourceIsReachableAndReturnError:NULL])
    {
        NSAlert* alert = [[NSAlert alloc] init];
        [alert addButtonWithTitle:NSLocalizedString(@"OK", "Create torrent -> directory doesn't exist warning -> button")];
        alert.messageText = NSLocalizedString(@"The chosen torrent file location does not exist.",
                                              "Create torrent -> directory doesn't exist warning -> title");
        alert.informativeText = [NSString
            stringWithFormat:NSLocalizedString(@"The directory \"%@\" does not currently exist. "
                                                "Create this directory or choose a different one to create the torrent file.",
                                               "Create torrent -> directory doesn't exist warning -> warning"),
                             self.fLocation.URLByDeletingLastPathComponent.path];
        alert.alertStyle = NSAlertStyleWarning;

        [alert beginSheetModalForWindow:self.window completionHandler:nil];
        return;
    }

    //check if a file with the same name and location already exists
    if ([self.fLocation checkResourceIsReachableAndReturnError:NULL])
    {
        NSArray* pathComponents = self.fLocation.pathComponents;
        NSInteger count = pathComponents.count;

        NSAlert* alert = [[NSAlert alloc] init];
        [alert addButtonWithTitle:NSLocalizedString(@"OK", "Create torrent -> file already exists warning -> button")];
        alert.messageText = NSLocalizedString(@"A torrent file with this name and directory cannot be created.",
                                              "Create torrent -> file already exists warning -> title");
        alert.informativeText = [NSString
            stringWithFormat:NSLocalizedString(@"A file with the name \"%@\" already exists in the directory \"%@\". "
                                                "Choose a new name or directory to create the torrent file.",
                                               "Create torrent -> file already exists warning -> warning"),
                             pathComponents[count - 1],
                             pathComponents[count - 2]];
        alert.alertStyle = NSAlertStyleWarning;

        [alert beginSheetModalForWindow:self.window completionHandler:nil];
        return;
    }

    // trackers
    auto trackers = tr_announce_list{};
    for (NSUInteger i = 0; i < self.fTrackers.count; ++i)
    {
        trackers.add((char*)(self.fTrackers[i]).UTF8String, trackers.nextTier());
    }
    self.fBuilder->set_announce_list(std::move(trackers));

    //store values
    [self.fDefaults setObject:self.fTrackers forKey:@"CreatorTrackers"];
    [self.fDefaults setBool:self.fPrivateCheck.state == NSControlStateValueOn forKey:@"CreatorPrivate"];
    [self.fDefaults setObject:self.fSource.stringValue forKey:@"CreatorSource"];
    [self.fDefaults setBool:self.fOpenCheck.state == NSControlStateValueOn forKey:@"CreatorOpen"];
    self.fOpenWhenCreated = self.fOpenCheck.state ==
        NSControlStateValueOn; //need this since the check box might not exist, and value in prefs might have changed from another creator window
    [self.fDefaults setURL:self.fLocation.URLByDeletingLastPathComponent forKey:@"CreatorLocationURL"];

    self.window.restorable = NO;

    [NSNotificationCenter.defaultCenter postNotificationName:@"BeginCreateTorrentFile" object:self.fLocation userInfo:nil];

    self.fBuilder->set_comment(self.fCommentView.string.UTF8String);
    self.fBuilder->set_private(self.fPrivateCheck.state == NSControlStateValueOn);
    self.fBuilder->set_source(self.fSource.stringValue.UTF8String);

    // BEP 46: if the user checked "Make this torrent updatable (btpk)",
    // attempt to parse a pasted private key and set the public key on the builder.
    // If the key was generated via the Generate button, it is already set.
    // If the user pasted a key manually, parse it here.
    if (self.fMutableCheck.state == NSControlStateValueOn)
    {
        auto const key_str = std::string{ self.fBtpkKeyField.stringValue.UTF8String };
        if (!self.fBuilder->has_btpk() && !key_str.empty())
        {
            // Try hex first, then PEM
            auto priv = libtransmission::tr_btpk_private_key_from_hex(key_str);
            if (!priv)
            {
                priv = libtransmission::tr_btpk_private_key_from_pem(key_str);
            }
            if (priv)
            {
                // Derive the public key — it lives in priv[64..95]
                libtransmission::BtpkPublicKey pub{};
                std::copy_n(priv->data() + 64, 32, pub.data());
                self.fBuilder->set_btpk_public_key(pub);
        // Generate a unique per-torrent salt so each torrent gets its own
        // DHT slot even when the same keypair is reused for multiple torrents.
        // SHA1(pubkey + salt) is the DHT target — without salt all torrents
        // with the same keypair compete for one slot (BEP 44).
        {
            uint8_t saltBytes[8];
            arc4random_buf(saltBytes, sizeof(saltBytes));
            char saltHex[17] = {};
            for (int i = 0; i < 8; i++)
                snprintf(saltHex + i*2, 3, "%02x", saltBytes[i]);
            self.fBuilder->set_btpk_salt(std::string_view{ saltHex, 16 });
        }
                auto const fp = libtransmission::tr_btpk_fingerprint(pub);
                self.fBtpkFingerprint.stringValue = [NSString stringWithFormat:@"Fingerprint: %s", fp.c_str()];
                libtransmission::tr_btpk_zero_key(*priv);
            }
        }
    }
    else
    {
        // Checkbox is unchecked — ensure no btpk data is embedded
        self.fBuilder->clear_btpk();
    }

    self.fFuture = self.fBuilder->make_checksums();
    self.fTimer = [NSTimer scheduledTimerWithTimeInterval:0.1 target:self selector:@selector(checkProgress) userInfo:nil
                                                  repeats:YES];
}

- (void)checkProgress
{
    auto const is_done = !self.fFuture.valid() || self.fFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready;

    if (!is_done)
    {
        auto const [current, total] = self.fBuilder->checksum_status();
        self.fProgressIndicator.doubleValue = static_cast<double>(current) / total;

        if (!self.fStarted)
        {
            self.fStarted = YES;

            self.fProgressView.hidden = YES;

            NSWindow* window = self.window;
            window.frameAutosaveName = @"";

            NSRect windowRect = window.frame;
            CGFloat difference = self.fProgressView.frame.size.height - window.contentView.frame.size.height;
            windowRect.origin.y -= difference;
            windowRect.size.height += difference;

            //don't allow vertical resizing
            CGFloat height = windowRect.size.height;
            window.minSize = NSMakeSize(window.minSize.width, height);
            window.maxSize = NSMakeSize(window.maxSize.width, height);

            window.contentView = self.fProgressView;
            [window setFrame:windowRect display:YES animate:YES];
            self.fProgressView.hidden = NO;

            [window standardWindowButton:NSWindowCloseButton].enabled = NO;
        }

        return;
    }

    // stop the timer
    [self.fTimer invalidate];
    self.fTimer = nil;

    auto error = self.fFuture.get();
    if (!error)
    {
        self.fBuilder->save(self.fLocation.path.UTF8String, &error);
    }

    if (error)
    {
        auto* const alert = [[NSAlert alloc] init];
        [alert addButtonWithTitle:NSLocalizedString(@"OK", "Create torrent -> failed -> button")];
        alert.messageText = [NSString stringWithFormat:NSLocalizedString(@"Creation of \"%@\" failed.", "Create torrent -> failed -> title"),
                                                       self.fLocation.lastPathComponent];
        alert.alertStyle = NSAlertStyleWarning;

        alert.informativeText = [NSString
            stringWithFormat:@"%.*s (%d)", static_cast<int>(std::size(error.message())), std::data(error.message()), error.code()];
        [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse /*returnCode*/) {
            [self.window close];
        }];
    }
    else
    {
        if (self.fOpenWhenCreated)
        {
            NSDictionary* dict = @{ @"File" : self.fLocation.path, @"Path" : self.fPath.URLByDeletingLastPathComponent.path };
            [NSNotificationCenter.defaultCenter postNotificationName:@"OpenCreatedTorrentFile" object:self userInfo:dict];
        }

        // BEP 46: if a btpk key was set, show the magnet link so the user can share it.
        if (self.fBuilder->has_btpk())
        {
            auto const magnet = self.fBuilder->magnet_link();
            if (!magnet.empty())
            {
                NSString* magnetStr = [NSString stringWithUTF8String:magnet.c_str()];
                NSAlert* magnetAlert = [[NSAlert alloc] init];
                magnetAlert.messageText = NSLocalizedString(@"Updatable torrent created", @"btpk magnet link alert title");
                magnetAlert.informativeText = [NSString
                    stringWithFormat:NSLocalizedString(@"Share this btpk: magnet link. Anyone who adds it will automatically receive your updates:\n\n%@",
                                                       @"btpk magnet link alert message"),
                                     magnetStr];
                [magnetAlert addButtonWithTitle:NSLocalizedString(@"Copy Link", @"btpk magnet copy button")];
                [magnetAlert addButtonWithTitle:NSLocalizedString(@"OK", @"btpk magnet ok button")];
                [magnetAlert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse resp) {
                    if (resp == NSAlertFirstButtonReturn)
                    {
                        [NSPasteboard.generalPasteboard clearContents];
                        [NSPasteboard.generalPasteboard setString:magnetStr forType:NSPasteboardTypeString];
                    }
                    [self.window close];
                }];
                return; // window closed by alert handler above
            }
        }

        [self.window close];
    }
}

@end
