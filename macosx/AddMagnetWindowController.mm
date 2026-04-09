// This file Copyright © Transmission authors and contributors.
// It may be used under the MIT (SPDX: MIT) license.
// License text can be found in the licenses/ folder.

#import "AddMagnetWindowController.h"
#import "Controller.h"
#import "ExpandedPathToIconTransformer.h"
#import "GroupsController.h"
#import "NSStringAdditions.h"
#import "Torrent.h"

typedef NS_ENUM(NSUInteger, PopupPriority) {
    PopupPriorityHigh = 0,
    PopupPriorityNormal = 1,
    PopupPriorityLow = 2,
};

@interface AddMagnetWindowController ()

@property(nonatomic) IBOutlet NSImageView* fLocationImageView;
@property(nonatomic) IBOutlet NSTextField* fNameField;
@property(nonatomic) IBOutlet NSTextField* fLocationField;
@property(nonatomic) IBOutlet NSButton* fStartCheck;
@property(nonatomic) IBOutlet NSPopUpButton* fGroupPopUp;
@property(nonatomic) IBOutlet NSPopUpButton* fPriorityPopUp;
@property(nonatomic) IBOutlet NSTextField* fUpdateModeLabel;
@property(nonatomic) IBOutlet NSPopUpButton* fUpdateModePopUp;
@property(nonatomic) IBOutlet NSButton* fUpdateModeAllowAdditional;
@property(nonatomic) IBOutlet NSButton* fUpdateModeAllowRenaming;
@property(nonatomic) IBOutlet NSButton* fUpdateModeAllowOverwrites;
@property(nonatomic) IBOutlet NSButton* fUpdateModeAllowDeletions;
@property(nonatomic) IBOutlet NSLayoutConstraint* fUpdateModeBoxSpacing;

@property(nonatomic, readonly) Controller* fController;

@property(nonatomic) NSString* fDestination;

@property(nonatomic) NSInteger fGroupValue;
@property(nonatomic) TorrentDeterminationType fGroupDeterminationType;

@end

@implementation AddMagnetWindowController

- (instancetype)initWithTorrent:(Torrent*)torrent destination:(NSString*)path controller:(Controller*)controller
{
    if ((self = [super initWithWindowNibName:@"AddMagnetWindow"]))
    {
        _torrent = torrent;
        _fDestination = path.stringByExpandingTildeInPath;

        _fController = controller;

        _fGroupValue = torrent.groupValue;
        _fGroupDeterminationType = TorrentDeterminationAutomatic;
    }
    return self;
}

- (void)awakeFromNib
{
    [super awakeFromNib];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(updateGroupMenu:) name:@"UpdateGroups" object:nil];

    NSString* name = self.torrent.name;
    self.window.title = name;
    self.fNameField.stringValue = name;
    self.fNameField.toolTip = name;

    //disable fullscreen support
    self.window.collectionBehavior = NSWindowCollectionBehaviorFullScreenNone;

    [self setGroupsMenu];
    [self.fGroupPopUp selectItemWithTag:self.fGroupValue];

    PopupPriority priorityIndex;
    switch (self.torrent.priority)
    {
    case TR_PRI_HIGH:
        priorityIndex = PopupPriorityHigh;
        break;
    case TR_PRI_NORMAL:
        priorityIndex = PopupPriorityNormal;
        break;
    case TR_PRI_LOW:
        priorityIndex = PopupPriorityLow;
        break;
    default:
        NSAssert1(NO, @"Unknown priority for adding torrent: %d", self.torrent.priority);
        priorityIndex = PopupPriorityNormal;
    }
    [self.fPriorityPopUp selectItemAtIndex:priorityIndex];

    self.fStartCheck.state = [NSUserDefaults.standardUserDefaults boolForKey:@"AutoStartDownload"] ? NSControlStateValueOn :
                                                                                                     NSControlStateValueOff;

    // Show update behavior row for btpk torrents, pre-populated from prefs
    if (self.torrent.hasBtpk)
    {
        NSInteger const defaultMode = [NSUserDefaults.standardUserDefaults integerForKey:@"MutableUpdateBehavior"];
        [self.fUpdateModePopUp selectItemWithTag:defaultMode];
        self.fUpdateModeLabel.hidden = NO;
        self.fUpdateModePopUp.hidden = NO;
        // Pre-populate allow checkboxes from prefs
        self.fUpdateModeAllowAdditional.state = [NSUserDefaults.standardUserDefaults boolForKey:@"MutableAllowAdditional"] ?
            NSControlStateValueOn :
            NSControlStateValueOff;
        self.fUpdateModeAllowRenaming.state = [NSUserDefaults.standardUserDefaults boolForKey:@"MutableAllowRenaming"] ?
            NSControlStateValueOn :
            NSControlStateValueOff;
        self.fUpdateModeAllowOverwrites.state = [NSUserDefaults.standardUserDefaults boolForKey:@"MutableAllowOverwrites"] ?
            NSControlStateValueOn :
            NSControlStateValueOff;
        self.fUpdateModeAllowDeletions.state = [NSUserDefaults.standardUserDefaults boolForKey:@"MutableAllowDeletions"] ?
            NSControlStateValueOn :
            NSControlStateValueOff;
        [self updateAllowCheckboxVisibility];
        // Push Add/Cancel buttons down to make room
        self.fUpdateModeBoxSpacing.constant = 72.0;
        // Expand window height
        NSRect frame = self.window.frame;
        frame.size.height += 64.0;
        frame.origin.y -= 64.0;
        [self.window setFrame:frame display:NO];
    }

    if (self.fDestination)
    {
        [self setDestinationPath:self.fDestination determinationType:TorrentDeterminationAutomatic];
    }
    else
    {
        self.fLocationField.stringValue = @"";
        self.fLocationImageView.image = nil;
    }
}

- (void)windowDidLoad
{
    //if there is no destination, prompt for one right away
    if (!self.fDestination)
    {
        [self setDestination:nil];
    }
}

- (void)setDestination:(id)sender
{
    NSOpenPanel* panel = [NSOpenPanel openPanel];

    panel.prompt = NSLocalizedString(@"Select", "Open torrent -> prompt");
    panel.allowsMultipleSelection = NO;
    panel.canChooseFiles = NO;
    panel.canChooseDirectories = YES;
    panel.canCreateDirectories = YES;

    panel.message = [NSString stringWithFormat:NSLocalizedString(@"Select the download folder for \"%@\"", "Add -> select destination folder"),
                                               self.torrent.name];

    [panel beginSheetModalForWindow:self.window completionHandler:^(NSInteger result) {
        if (result == NSModalResponseOK)
        {
            [self setDestinationPath:panel.URLs[0].path determinationType:TorrentDeterminationUserSpecified];
        }
        else
        {
            if (!self.fDestination)
            {
                [self performSelectorOnMainThread:@selector(cancelAdd:) withObject:nil waitUntilDone:NO];
            }
        }
    }];
}

- (void)add:(id)sender
{
    if ([self.fDestination.lastPathComponent isEqualToString:self.torrent.name] &&
        [NSUserDefaults.standardUserDefaults boolForKey:@"WarningFolderDataSameName"])
    {
        NSAlert* alert = [[NSAlert alloc] init];
        alert.messageText = NSLocalizedString(@"The destination directory and root data directory have the same name.",
                                              "Add torrent -> same name -> title");
        alert.informativeText = NSLocalizedString(
            @"If you are attempting to use already existing data,"
             " the root data directory should be inside the destination directory.",
            "Add torrent -> same name -> message");
        alert.alertStyle = NSAlertStyleWarning;
        [alert addButtonWithTitle:NSLocalizedString(@"Cancel", "Add torrent -> same name -> button")];
        [alert addButtonWithTitle:NSLocalizedString(@"Add", "Add torrent -> same name -> button")];
        alert.showsSuppressionButton = YES;

        [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode) {
            if (alert.suppressionButton.state == NSControlStateValueOn)
            {
                [NSUserDefaults.standardUserDefaults setBool:NO forKey:@"WarningFolderDataSameName"];
            }

            if (returnCode == NSAlertSecondButtonReturn)
            {
                [self performSelectorOnMainThread:@selector(confirmAdd) withObject:nil waitUntilDone:NO];
            }
        }];
    }
    else
    {
        [self confirmAdd];
    }
}

- (void)cancelAdd:(id)sender
{
    [self.window performClose:sender];
}

//only called on cancel
- (BOOL)windowShouldClose:(id)window
{
    [self.fController askOpenMagnetConfirmed:self add:NO];
    return YES;
}

- (void)changePriority:(id)sender
{
    tr_priority_t priority;
    switch ([sender indexOfSelectedItem])
    {
    case PopupPriorityHigh:
        priority = TR_PRI_HIGH;
        break;
    case PopupPriorityNormal:
        priority = TR_PRI_NORMAL;
        break;
    case PopupPriorityLow:
        priority = TR_PRI_LOW;
        break;
    default:
        NSAssert1(NO, @"Unknown priority tag for adding torrent: %ld", [sender tag]);
        priority = TR_PRI_NORMAL;
    }
    self.torrent.priority = priority;
}

- (void)updateGroupMenu:(NSNotification*)notification
{
    [self setGroupsMenu];
    if (![self.fGroupPopUp selectItemWithTag:self.fGroupValue])
    {
        self.fGroupValue = -1;
        self.fGroupDeterminationType = TorrentDeterminationAutomatic;
        [self.fGroupPopUp selectItemWithTag:self.fGroupValue];
    }
}

#pragma mark - Private

- (IBAction)changeUpdateMode:(id)sender
{
    [self updateAllowCheckboxVisibility];
}

- (void)updateAllowCheckboxVisibility
{
    BOOL const whenOffered = ([self.fUpdateModePopUp selectedTag] == 1);
    self.fUpdateModeAllowAdditional.hidden = !whenOffered;
    self.fUpdateModeAllowRenaming.hidden = !whenOffered;
    self.fUpdateModeAllowOverwrites.hidden = !whenOffered;
    self.fUpdateModeAllowDeletions.hidden = !whenOffered;
}

- (void)confirmAdd
{
    [self.torrent setGroupValue:self.fGroupValue determinationType:self.fGroupDeterminationType];

    if (self.torrent.hasBtpk)
        self.torrent.btpkUpdateMode = (BtpkUpdateMode)[self.fUpdateModePopUp selectedTag];

    if (self.fStartCheck.state == NSControlStateValueOn)
    {
        [self.torrent startMagnetTransferAfterMetaDownload];
    }

    [self close];
    [self.fController askOpenMagnetConfirmed:self add:YES];
}

- (void)setDestinationPath:(NSString*)destination determinationType:(TorrentDeterminationType)determinationType
{
    destination = destination.stringByExpandingTildeInPath;
    if (!self.fDestination || ![self.fDestination isEqualToString:destination])
    {
        self.fDestination = destination;

        [self.torrent changeDownloadFolderBeforeUsing:self.fDestination determinationType:determinationType];
    }

    self.fLocationField.stringValue = self.fDestination.stringByAbbreviatingWithTildeInPath;
    self.fLocationField.toolTip = self.fDestination;

    ExpandedPathToIconTransformer* iconTransformer = [[ExpandedPathToIconTransformer alloc] init];
    self.fLocationImageView.image = [iconTransformer transformedValue:self.fDestination];
}

- (void)setGroupsMenu
{
    NSMenu* groupMenu = [GroupsController.groups groupMenuWithTarget:self action:@selector(changeGroupValue:) isSmall:NO];
    self.fGroupPopUp.menu = groupMenu;
}

- (void)changeGroupValue:(id)sender
{
    NSInteger previousGroup = self.fGroupValue;
    self.fGroupValue = [sender tag];
    self.fGroupDeterminationType = TorrentDeterminationUserSpecified;

    if ([GroupsController.groups usesCustomDownloadLocationForIndex:self.fGroupValue])
    {
        [self setDestinationPath:[GroupsController.groups customDownloadLocationForIndex:self.fGroupValue]
               determinationType:TorrentDeterminationAutomatic];
    }
    else if ([self.fDestination isEqualToString:[GroupsController.groups customDownloadLocationForIndex:previousGroup]])
    {
        [self setDestinationPath:[NSUserDefaults.standardUserDefaults stringForKey:@"DownloadFolder"]
               determinationType:TorrentDeterminationAutomatic];
    }
}

@end
