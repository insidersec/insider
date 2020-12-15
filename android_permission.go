package insider

import "github.com/insidersec/insider/report"

func getManifestPermission() []report.ManifestPermission {
	return []report.ManifestPermission{
		report.ManifestPermission{
			Title:       "android.permission.SEND_SMS",
			Description: "Enviar Mensagens SMS",
			Info:        "Permite a aplicação enviar Mensagens SMS. Aplicações maliciosas podem gastar dinheiro enviando mensagens sem sua confirmação.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SEND_SMS_NO_CONFIRMATION",
			Description: "Send SMS messages",
			Info:        "Allows sending SMS messages via messaging application without user input or confirmation.",
		},

		report.ManifestPermission{
			Title:       "android.permission.CALL_PHONE",
			Description: "Call phone numbers directly",
			Info:        "Allows the application to be activated without your intervention. Malicious applications can generate unexpected costs on your phone bill. Note that this does not allow the application to call emergency numbers.",
		},

		report.ManifestPermission{
			Title:       "android.permission.RECEIVE_SMS",
			Description: "Receive SMS",
			Info:        "Allows the app to receive and process SMS messages. Malicious apps can monitor or delete your messages without you knowing it.",
		},

		report.ManifestPermission{
			Title:       "android.permission.RECEIVE_MMS",
			Description: "Receive MMS",
			Info:        "Allows the app to receive and process MMS messages. Malicious apps can monitor or delete your messages without you knowing it.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_SMS",
			Description: "Read SMS or MMS",
			Info:        "Allows the app to read SMS messages saved on your phone or SIM card. Malicious apps can read your confidential messages.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WRITE_SMS",
			Description: "Edit SMS or MMS",
			Info:        "Allows the app to write SMS messages saved on your phone or SIM card. Malicious apps can delete your messages.",
		},

		report.ManifestPermission{
			Title:       "android.permission.RECEIVE_WAP_PUSH",
			Description: "Receive WAP",
			Info:        "Allows the app to receive and process WAP messages. Malicious apps can monitor your messages or delete you without knowing it.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_CONTACTS",
			Description: "read contact information",
			Info:        "Allows the app to read all the contact (address) data captured on your phone. Malicious apps can use this to send your data to others.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WRITE_CONTACTS",
			Description: "write contact information",
			Info:        "Allows the app to modify the contact (address) data captured on your phone. Malicious apps can use this to delete or modify contact data.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_PROFILE",
			Description: "read the user's personal profile data",
			Info:        "Allows the Application to read the user's personal data.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WRITE_PROFILE",
			Description: "write the user's personal profile data",
			Info:        "Allows the written application (but does not read) to read the user's personal data.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_SOCIAL_STREAM",
			Description: "read from the user's social stream",
			Info:        "Allows the app to read from the user's social stream.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WRITE_SOCIAL_STREAM",
			Description: "write from the user's social flow",
			Info:        "Allows the app to write from the user's social stream.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_CALENDAR",
			Description: "read calendar events",
			Info:        "Allows the app to read all calendar events stored on your phone. Malicious apps can use this to send your calendar events to others.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WRITE_CALENDAR",
			Description: "add or modify calendar events and send guests emails",
			Info:        "Allows the app to add or change events on your calendar, which can send emails to guests. Malicious apps can use this to delete or modify events on your calendar or send emails to guests.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_USER_DICTIONARY",
			Description: "read user-defined dictionary",
			Info:        "It allows the application of unique keywords, names and particular phrases that the user may have stored in the user dictionary.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WRITE_USER_DICTIONARY",
			Description: "write to the user-defined dictionary",
			Info:        "Allows the app to write new words in the user dictionary.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_HISTORY_BOOKMARKS",
			Description: "read browser history and bookmarks",
			Info:        "Allows the app to read all the URLs the browser visits and all the browser's favorites.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WRITE_HISTORY_BOOKMARKS",
			Description: "write browser history and bookmarks",
			Info:        "Allows the app to modify the browser history or bookmarks to capture on your phone. Malicious apps can use this to delete or modify your browser data.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SET_ALARM",
			Description: "set alarm on alarm clock",
			Info:        "Allows the app to set an alarm in the installed alarm application. Some alarm applications may not implement this feature.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ACCESS_FINE_LOCATION",
			Description: "fine location (GPS)",
			Info:        "Access fine location sources, such as the Global Positioning System on the phone, when available. Malicious apps can use this to determine where you are and consume additional battery power.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ACCESS_COARSE_LOCATION",
			Description: "approximate location (network based)",
			Info:        "Access approximate location sources, such as the mobile network database, to determine an approximate phone location, when available. Malicious apps can use this to roughly determine where you are.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ACCESS_MOCK_LOCATION",
			Description: "fake location sources for testing",
			Info:        "Create fake location sources for testing. Malicious apps can use this to replace a returned location and / or status with actual location sources, such as GPS or network providers.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS",
			Description: "Access extra location provider commands",
			Info:        "Access additional commands provided by the location provider. Malicious applications can use this to interfere with GPS operation or other sources of location.",
		},

		report.ManifestPermission{
			Title:       "android.permission.INSTALL_LOCATION_PROVIDER",
			Description: "permission to install a location provider",
			Info:        "Create fake location sources for testing. Malicious applications can use this to replace a location and / or status returned with real location sources, such as GPS or network providers, or to monitor and report your location on an external source",
		},

		report.ManifestPermission{
			Title:       "android.permission.INTERNET",
			Description: "full internet access",
			Info:        "Allows the application to create network sockets.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ACCESS_NETWORK_STATE",
			Description: "view network status",
			Info:        "Allows the app to view the status of all networks.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ACCESS_WIFI_STATE",
			Description: "view Wi-Fi status",
			Info:        "Allows a viewing application as information about the status of Wi-Fi.",
		},

		report.ManifestPermission{
			Title:       "android.permission.BLUETOOTH",
			Description: "Create Bluetooth connections",
			Info:        "Allows the app to view the configuration of the local Bluetooth phone and to make connections to paired devices.",
		},

		report.ManifestPermission{
			Title:       "android.permission.NFC",
			Description: "Control near-field communication",
			Info:        "It allows the application to communicate with NFC (Near-Field Communication) tags, cards and readers.",
		},

		report.ManifestPermission{
			Title:       "android.permission.USE_SIP",
			Description: "Make / receive Internet calls",
			Info:        "Allows the application to use the SIP service to make / receive calls over the Internet.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ACCOUNT_MANAGER",
			Description: "Acts as the account manager service",
			Info:        "Allows application to call Account Authenticators",
		},

		report.ManifestPermission{
			Title:       "android.permission.GET_ACCOUNTS",
			Description: "discover registered accounts",
			Info:        "Allows the app to access a list of accounts identified by the phone.",
		},

		report.ManifestPermission{
			Title:       "android.permission.AUTHENTICATE_ACCOUNTS",
			Description: "acts as an account authenticator",
			Info:        "Allows the application to use the Account Manager's account authentication features, including creating accounts, as well as identifying and configuring their passwords.",
		},

		report.ManifestPermission{
			Title:       "android.permission.USE_CREDENTIALS",
			Description: "use as authentication credentials for an account",
			Info:        "Allows the application of request authentication tokens.",
		},

		report.ManifestPermission{
			Title:       "android.permission.MANAGE_ACCOUNTS",
			Description: "manage a list of accounts",
			Info:        "Allows application operations such as adding and removing accounts and deleting your password.",
		},

		report.ManifestPermission{
			Title:       "android.permission.MODIFY_AUDIO_SETTINGS",
			Description: "change your audio settings",
			Info:        "Allows the app to modify global audio settings, such as volume and routing.",
		},

		report.ManifestPermission{
			Title:       "android.permission.RECORD_AUDIO",
			Description: "record audio",
			Info:        "Allows the app to access the audio recording path.",
		},

		report.ManifestPermission{
			Title:       "android.permission.CAMERA",
			Description: "take photos and videos",
			Info:        "Allows the app to take photos and videos with the camera. This allows the application to collect images that the camera is viewing at any time.",
		},

		report.ManifestPermission{
			Title:       "android.permission.VIBRATE",
			Description: "control vibrator",
			Info:        "It allows a vibrator control application.",
		},

		report.ManifestPermission{
			Title:       "android.permission.FLASHLIGHT",
			Description: "control flashlight",
			Info:        "It allows a flashlight control application.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ACCESS_USB",
			Description: "Access USB devices",
			Info:        "Allows the app to access USB devices.",
		},

		report.ManifestPermission{
			Title:       "android.permission.HARDWARE_TEST",
			Description: "Test hardware",
			Info:        "Allows application to control various peripherals for hardware testing purposes.",
		},

		report.ManifestPermission{
			Title:       "android.permission.PROCESS_OUTGOING_CALLS",
			Description: "Intercept outgoing calls",
			Info:        "Allows the app to process outgoing calls and change the number to be dialed. Malicious applications can monitor, redirect or prevent outgoing calls.",
		},

		report.ManifestPermission{
			Title:       "android.permission.MODIFY_PHONE_STATE",
			Description: "Modify phone status",
			Info:        "Allows the application to control the telephony resources of the device. An application with permission can switch between networks, turn the phone's radio on and off and the like, without ever notifying you.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_PHONE_STATE",
			Description: "Read phone status and identity",
			Info:        "Allows the app to access the device's phone resources. An application with permission can determine the phone number and the serial number of this phone, if a call is active, the call number that is connected etc.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WRITE_EXTERNAL_STORAGE",
			Description: "Reads / modifies / deletes the contents of the SD card",
			Info:        "Allows an application to write to the SD card.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_EXTERNAL_STORAGE",
			Description: "Read the contents of the SD card",
			Info:        "Allows an application to read the SD card.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WRITE_SETTINGS",
			Description: "Modify global system settings",
			Info:        "Allows the application to modify the system configuration data. Malicious applications can corrupt the system configuration.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WRITE_SECURE_SETTINGS",
			Description: "Modify system security settings",
			Info:        "Allows application to modify system security settings data. It is not to be used with common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WRITE_GSERVICES",
			Description: "Modify the Google service map",
			Info:        "Allows the application to modify or map Google services. It is not to be used with common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.EXPAND_STATUS_BAR",
			Description: "expand / collect status bar",
			Info:        "Allows the app to expand or hide a status bar.",
		},

		report.ManifestPermission{
			Title:       "android.permission.GET_TASKS",
			Description: "recover running applications",
			Info:        "Allows the app to retrieve information about recently and recently running tasks. It can allow applications with intentions to discover private information about other applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.REORDER_TASKS",
			Description: "reorder running applications",
			Info:        "It allows the application of movement tasks for the foreground and background. Malicious applications can be used to open forward without control.",
		},

		report.ManifestPermission{
			Title:       "android.permission.CHANGE_CONFIGURATION",
			Description: "change user interface settings",
			Info:        "Allows the application to change the current configuration, such as locality or general font size.",
		},

		report.ManifestPermission{
			Title:       "android.permission.RESTART_PACKAGES",
			Description: "eliminate background processes",
			Info:        "It allows the application to remove background processes from other applications, even if the memory is not low.",
		},

		report.ManifestPermission{
			Title:       "android.permission.KILL_BACKGROUND_PROCESSES",
			Description: "eliminate background processes",
			Info:        "Allows the application to remove background processes from other applications, even if memory is not low",
		},

		report.ManifestPermission{
			Title:       "android.permission.FORCE_STOP_PACKAGES",
			Description: "force other applications to stop",
			Info:        "Allows the application to stop other applications forcibly.",
		},

		report.ManifestPermission{
			Title:       "android.permission.DUMP",
			Description: "retrieve internal system status",
			Info:        "Allows the app to retrieve the internal status of the system. Malicious applications can recover a wide variety of private and security information that they usually never use.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SYSTEM_ALERT_WINDOW",
			Description: "display system-level alerts",
			Info:        "Allows the application of system alert windows. Malicious apps can invade an entire phone screen.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SET_ANIMATION_SCALE",
			Description: "modify the overall speed of the animation",
			Info:        "Allows the app to change the overall speed of the animation (faster or slower animations) at any time.",
		},

		report.ManifestPermission{
			Title:       "android.permission.PERSISTENT_ACTIVITY",
			Description: "always make the application run",
			Info:        "It allows the application to make parts persistent, so that the system cannot use it for other applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.GET_PACKAGE_SIZE",
			Description: "measures the storage space of the application",
			Info:        "Allows the application to recover its code, data size and cache",
		},

		report.ManifestPermission{
			Title:       "android.permission.SET_PREFERRED_APPLICATIONS",
			Description: "set favorite apps",
			Info:        "Allows the app to modify your favorite applications. This can allow malicious applications to silently alter running applications, spoofing your existing applications to collect private data from you.",
		},

		report.ManifestPermission{
			Title:       "android.permission.RECEIVE_BOOT_COMPLETED",
			Description: "automatically start at startup",
			Info:        "Allows the application to start automatically as soon as the system ends. This may take longer to start the phone and allow the application to slow down the general phone, which is always in use.",
		},

		report.ManifestPermission{
			Title:       "android.permission.BROADCAST_STICKY",
			Description: "send fixed transmission",
			Info:        "It allows a persistent sending application, which remains after the transmission is finished. Malicious applications can make your phone slow or unstable, causing it to use a lot of memory.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WAKE_LOCK",
			Description: "prevent the phone from sleeping",
			Info:        "Allows the app to prevent the phone from going to sleep.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SET_WALLPAPER",
			Description: "set wallpaper",
			Info:        "Allows the app to set the system's wallpaper.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SET_WALLPAPER_HINTS",
			Description: "set wallpaper size tips",
			Info:        "Allows the app to set system wallpaper size tips.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SET_TIME",
			Description: "set time",
			Info:        "Allows a time change application on the phone.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SET_TIME_ZONE",
			Description: "set time zone",
			Info:        "Allows an application to change the phone time.",
		},

		report.ManifestPermission{
			Title:       "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
			Description: "mount and unmount file systems",
			Info:        "Allows you to apply and unmount file systems for removable storage.",
		},

		report.ManifestPermission{
			Title:       "android.permission.MOUNT_FORMAT_FILESYSTEMS",
			Description: "format external storage",
			Info:        "It allows a removable storage format application.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ASEC_ACCESS",
			Description: "Get information about internal storage",
			Info:        "Allows the app to get information about internal storage.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ASEC_CREATE",
			Description: "create internal storage",
			Info:        "Allows the app to create internal storage.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ASEC_DESTROY",
			Description: "destruction of internal storage",
			Info:        "Enables an application to destroy internal storage.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ASEC_MOUNT_UNMOUNT",
			Description: "mount / unmount internal storage",
			Info:        "Allows the application to mount / unmount internal storage.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ASEC_RENAME",
			Description: "rename internal storage",
			Info:        "Allows an application to rename internal storage.",
		},

		report.ManifestPermission{
			Title:       "android.permission.DISABLE_KEYGUARD",
			Description: "disable key lock",
			Info:        "Allows the application to change key lock and associated password security. A legitimate example of this is the disabled phone or key lock to receive a phone call and then reactivate or lock the keys when the call is complete.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_SYNC_SETTINGS",
			Description: "read sync settings",
			Info:        "Allows the application to read as synchronization settings, as if synchronization is enabled for contacts.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WRITE_SYNC_SETTINGS",
			Description: "write synchronization settings",
			Info:        "Allows the application to modify as synchronization settings, as if synchronization is enabled for contacts.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_SYNC_STATS",
			Description: "read sync statistics",
			Info:        "Allows the application to read as synchronization statistics; for example, the synchronization history that occurs.",
		},

		report.ManifestPermission{
			Title:       "android.permission.WRITE_APN_SETTINGS",
			Description: "write access point name settings",
			Info:        "It allows a modification application such as APN settings, such as Proxy and Port of any APN.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SUBSCRIBED_FEEDS_READ",
			Description: "read subscribed feeds",
			Info:        "Allows the app to receive details about the feeds currently synced.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SUBSCRIBED_FEEDS_WRITE",
			Description: "writes subscribed feeds",
			Info:        "Allows the app to modify your currently synced feeds. This can allow an application intent on changing its synchronized feeds.",
		},

		report.ManifestPermission{
			Title:       "android.permission.CHANGE_NETWORK_STATE",
			Description: "change network connectivity",
			Info:        "Allows the application to change or state the network connection.",
		},

		report.ManifestPermission{
			Title:       "android.permission.CHANGE_WIFI_STATE",
			Description: "change Wi-Fi status",
			Info:        "Allows the app to connect and disconnect Wi-Fi access points and make changes to configured Wi-Fi networks.",
		},

		report.ManifestPermission{
			Title:       "android.permission.CHANGE_WIFI_MULTICAST_STATE",
			Description: "allows Wi-Fi Multicast reception",
			Info:        "Allows the application to receive packets not addressed directly to your device. This can be useful in discovering services offered in threats. It consumes more energy than non-multicast mode.",
		},

		report.ManifestPermission{
			Title:       "android.permission.BLUETOOTH_ADMIN",
			Description: "bluetooth administration",
			Info:        "Allows the app to configure the local Bluetooth phone and to discover and search with remote devices.",
		},

		report.ManifestPermission{
			Title:       "android.permission.CLEAR_APP_CACHE",
			Description: "delete all data from the application cache",
			Info:        "Allows the application to free phone storage by excluding files in the application's cache directory. Access is very restricted to the system process.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_LOGS",
			Description: "read sensitive data from the log",
			Info:        "It allows an application to read the various system log files. This allows you to discover general information about who you are doing with the phone, including possible personal or private information.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SET_DEBUG_APP",
			Description: "enable application debugging",
			Info:        "Allows the application to activate debugging for another application. Malicious apps can use this to kill other apps.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SET_PROCESS_LIMIT",
			Description: "limit number of running processes",
			Info:        "It allows the application to control the maximum number of processes that will be executed. It is never necessary for common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SET_ALWAYS_FINISH",
			Description: "closes all applications in the background",
			Info:        "It allows the control application as activities always completed in the same way that they enter the background. They are never needed for common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SIGNAL_PERSISTENT_PROCESSES",
			Description: "sends Linux signals to applications",
			Info:        "Allows the app to request that the signal be sent to all persistent processes.",
		},

		report.ManifestPermission{
			Title:       "android.permission.DIAGNOSTIC",
			Description: "read / write to resources belonging to diag",
			Info:        "Allows the application to read and write to any resource belonging to the diag group; for example, files in / dev. This can affect the stability and security of the system. This should ONLY be used for hardware diagnostics used by the manufacturer or operator",
		},

		report.ManifestPermission{
			Title:       "android.permission.STATUS_BAR",
			Description: "change or modify the status bar",
			Info:        "Allows the app to disable the status bar or to add and remove icons from the system.",
		},

		report.ManifestPermission{
			Title:       "android.permission.STATUS_BAR_SERVICE",
			Description: "status bar",
			Info:        "Allows the application to be a status bar.",
		},

		report.ManifestPermission{
			Title:       "android.permission.FORCE_BACK",
			Description: "force the application to close",
			Info:        "The application allows any activity that is in the foreground to close and return. It should never be necessary for common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.UPDATE_DEVICE_STATS",
			Description: "modify battery statistics",
			Info:        "Allows you to change statistics collected from the battery. It is not to be used with common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.INTERNAL_SYSTEM_WINDOW",
			Description: "unauthorized windows are displayed",
			Info:        "It allows the creation of windows to be used by the internal system's user interface. It is not to be used with common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.MANAGE_APP_TOKENS",
			Description: "manage application tokens",
			Info:        "Allows applications to create and generate their unique tokens, ignoring their common Z order. It should never be necessary for common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.INJECT_EVENTS",
			Description: "press keys and control buttons",
			Info:        "Allows the app to deliver its own input events (key presses, etc.) to other apps. Malicious apps can use this to control the phone.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SET_ACTIVITY_WATCHER",
			Description: "monitors and controls all application launches",
			Info:        "It allows the application to monitor and control how the system starts activities. How malicious applications can completely compromise the system. This permission is only necessary for development, never for ordinary telephone use.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SHUTDOWN",
			Description: "partial shutdown",
			Info:        "Put or manage activities in a shutdown state. Do not perform a complete shutdown.",
		},

		report.ManifestPermission{
			Title:       "android.permission.STOP_APP_SWITCHES",
			Description: "prevent application exchanges",
			Info:        "Prevent the user from changing to another application.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_INPUT_STATE",
			Description: "record what you type and the actions you take",
			Info:        "Allows applications to observe the keys you press, even when interacting with another application (such as entering a password). It should never be necessary for common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.BIND_INPUT_METHOD",
			Description: "link to an input method",
			Info:        "Allows the owner to link to the top level interface of an input method. It should never be necessary for common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.BIND_WALLPAPER",
			Description: "link to wallpaper",
			Info:        "Allows the owner to link to the top-level wallpaper interface. It should never be necessary for common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.BIND_DEVICE_ADMIN",
			Description: "interact with the device administrator",
			Info:        "Allows the owner to send intentions to the device administrator. It should never be necessary for common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.SET_ORIENTATION",
			Description: "change screen orientation",
			Info:        "Allows the application to change the screen at any time. It should never be necessary for common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.INSTALL_PACKAGES",
			Description: "install apps directly",
			Info:        "Allows the application to install new packages or use Android. Malicious apps can use this to add new apps with arbitrarily powerful apps.",
		},

		report.ManifestPermission{
			Title:       "android.permission.REQUEST_INSTALL_PACKAGES",
			Description: "Enables a package installation request application.",
			Info:        "Malicious applications can use this to try to trick users into installing additional malicious packages.",
		},

		report.ManifestPermission{
			Title:       "android.permission.CLEAR_APP_USER_DATA",
			Description: "erase data from other applications",
			Info:        "Allows application of clear user data.",
		},

		report.ManifestPermission{
			Title:       "android.permission.DELETE_CACHE_FILES",
			Description: "excluding caches from other applications",
			Info:        "Allows the app to delete cache files.",
		},

		report.ManifestPermission{
			Title:       "android.permission.DELETE_PACKAGES",
			Description: "delete apps",
			Info:        "Allows the application to delete packages from Android. Malicious apps can use this to delete important apps.",
		},

		report.ManifestPermission{
			Title:       "android.permission.MOVE_PACKAGE",
			Description: "Move application resources",
			Info:        "Allows application resources from internal to external media applications and vice versa.",
		},

		report.ManifestPermission{
			Title:       "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
			Description: "enable or disable application components",
			Info:        "Allows the application to change if a component of another application is enabled or disabled. Malicious apps can use it to activate important phone features. It is important to be careful with permissions as it is possible to include application components that are unusable, inconsistent or unstable",
		},

		report.ManifestPermission{
			Title:       "android.permission.ACCESS_SURFACE_FLINGER",
			Description: "access SurfaceFlinger",
			Info:        "Allows the app to use the lower-level features of SurfaceFlinger.",
		},

		report.ManifestPermission{
			Title:       "android.permission.READ_FRAME_BUFFER",
			Description: "read frame buffer",
			Info:        "Allows the app to read the frame buffer content.",
		},

		report.ManifestPermission{
			Title:       "android.permission.BRICK",
			Description: "permanently disable the phone",
			Info:        "Allows the app to remove the entire phone permanently. That is very dangerous.",
		},

		report.ManifestPermission{
			Title:       "android.permission.REBOOT",
			Description: "force phone restart",
			Info:        "Allow a phone application or restart.",
		},

		report.ManifestPermission{
			Title:       "android.permission.DEVICE_POWER",
			Description: "turns the phone on or off",
			Info:        "Allows the app to turn the phone on or off.",
		},

		report.ManifestPermission{
			Title:       "android.permission.FACTORY_TEST",
			Description: "run in factory test mode",
			Info:        "Realice una prueba de bajo nivel del fabricante, permita el acceso completo al hardware del teléfono. Disponible solo cuando un teléfono se ejecuta en el modo de prueba del fabricante.",
		},

		report.ManifestPermission{
			Title:       "android.permission.BROADCAST_PACKAGE_REMOVED",
			Description: "send stream removed from package",
			Info:        "Allows the app to transmit a notification that an app package has been removed. Malicious applications can use this to eliminate any other running applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.BROADCAST_SMS",
			Description: "send incoming SMS transmission",
			Info:        "Allows the app to transmit a notification that an SMS message has been received. Malicious applications can use this to forge incoming SMS messages.",
		},

		report.ManifestPermission{
			Title:       "android.permission.BROADCAST_WAP_PUSH",
			Description: "send transmission received by WAP-PUSH",
			Info:        "Allows the app to transmit a notification that a WAP-PUSH message has been received. Malicious applications can use this to forge the receipt of MMS messages or to silently replace the content of any web page with malicious variants.",
		},

		report.ManifestPermission{
			Title:       "android.permission.MASTER_CLEAR",
			Description: "reset the system to factory defaults",
			Info:        "Allows the app to completely reset the system to factory settings, erasing all installed data, settings and applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.CALL_PRIVILEGED",
			Description: "call directly to any phone number",
			Info:        "Allows the application of any phone number, including emergency numbers, without your intervention. Malicious applications can make unnecessary and illegal calls to emergency services.",
		},

		report.ManifestPermission{
			Title:       "android.permission.PERFORM_CDMA_PROVISIONING",
			Description: "directly initiates CDMA phone setup",
			Info:        "Allows the application to start provisioning CDMA. Malicious applications may unnecessarily initiate CDMA provisioning",
		},

		report.ManifestPermission{
			Title:       "android.permission.CONTROL_LOCATION_UPDATES",
			Description: "control location update notifications",
			Info:        "Enables / disables radio location update notifications. It is not to be used with common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ACCESS_CHECKIN_PROPERTIES",
			Description: "access check-in properties",
			Info:        "Allows read / write access to properties loaded by the check-in service. It is not to be used with common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.PACKAGE_USAGE_STATS",
			Description: "update component usage statistics",
			Info:        "It allows the modification of the usage statistics of collected components. It is not to be used with common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.BATTERY_STATS",
			Description: "modify battery statistics",
			Info:        "It allows the modification of the statistics collected from the battery. It is not to be used with common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.BACKUP",
			Description: "backup and restore control system",
			Info:        "Allows the application to control the system's backup and restore mechanism. It is not to be used with common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.BIND_APPWIDGET",
			Description: "choose widgets",
			Info:        "Allows the app to tell the system which widgets can be used by which app. With this permission, applications can access personal data for other applications. It is not to be used with common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.CHANGE_BACKGROUND_DATA_SETTING",
			Description: "change the background data usage setting",
			Info:        "Allows the app to change the data usage setting in the background.",
		},

		report.ManifestPermission{
			Title: "android.permission.GLOBAL_SEARCH",
		},

		report.ManifestPermission{
			Title: "android.permission.GLOBAL_SEARCH_CONTROL",
		},

		report.ManifestPermission{
			Title: "android.permission.SET_WALLPAPER_COMPONENT",
		},
		report.ManifestPermission{
			Title:       "android.permission.ACCESS_CACHE_FILESYSTEM",
			Description: "access the cached file system",
			Info:        "Allows the application to read and write to the cached file system.",
		},

		report.ManifestPermission{
			Title:       "android.permission.COPY_PROTECTED_DATA",
			Description: "Allows you to call the standard container service to copy the content. It is not to be used with common applications.",
			Info:        "Allows you to call the standard container service to copy the content. It is not to be used with common applications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.C2D_MESSAGE",
			Description: "Allows the cloud to send messages to the device",
			Info:        "Allows the app to receive push notifications.",
		},

		report.ManifestPermission{
			Title:       "android.permission.ADD_VOICEMAIL",
			Description: "Add voice messages to the system",
			Info:        "Allows the app to add voice messages to the system.",
		},

		report.ManifestPermission{
			Title: "android.permission.ACCEPT_HANDOVER",
			Info:  "Allows the calling application to continue a call initiated in another application. An example is a video call application that wants to continue a voice call on the user's mobile network.",
		},

		report.ManifestPermission{
			Title: "android.permission.ACCESS_NOTIFICATION_POLICY",
			Info:  "Bookmark permission for apps that want to access the notification policy.",
		},

		report.ManifestPermission{
			Title: "android.permission.ANSWER_PHONE_CALLS",
			Info:  "Allows an application to answer calls.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_ACCESSIBILITY_SERVICE",
			Info:  "It must be required by an AccessibilityService, to ensure that only the system can link to it.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_AUTOFILL_SERVICE",
			Info:  "It must be required by an AutofillService, to ensure that only the system can be linked to it.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_CARRIER_MESSAGING_SERVICE",
			Info:  "The system process that is allowed to link to services in the operator's applications will have this permission.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_CARRIER_SERVICES",
			Info:  "The system process that can link to services in the operator's applications will have this permission. Operator applications must use this permission to protect their services to which only the system is authorized.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_CHOOSER_TARGET_SERVICE",
			Info:  "Must be required by a ChooserTargetService, to ensure that only the system can link to it",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_CONDITION_PROVIDER_SERVICE",
			Info:  "Must be required by a ConditionProviderService, to ensure that only the system can link to it",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_DREAM_SERVICE",
			Info:  "It must be required by a DreamService, to ensure that only the system can link to it.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_INCALL_SERVICE",
			Info:  "It must be required by an InCallService, to ensure that only the system can link to it.",
		},
		report.ManifestPermission{
			Title: "android.permission.BIND_MIDI_DEVICE_SERVICE",
			Info:  "It must be required by a MidiDeviceService, to ensure that only the system can be linked to it.",
		},
		report.ManifestPermission{
			Title: "android.permission.BIND_NFC_SERVICE",
			Info:  "It must be required by a HostApduService or OffHostApduService to ensure that only the system can link to it.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
			Info:  "It must be required by a NotificationListenerService, to ensure that only the system can link to it.",
		},
		report.ManifestPermission{
			Title: "android.permission.BIND_PRINT_SERVICE",
			Info:  "It must be required by a PrintService, to ensure that only the system can be linked to it.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_QUICK_SETTINGS_TILE",
			Info:  "Allows a connection application to third party quick setting blocks.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_REMOTEVIEWS",
			Info:  "It must be required by a RemoteViewsService, to ensure that only the system can link to it.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_SCREENING_SERVICE",
			Info:  "It must be required by a CallScreeningService, to ensure that only the system can be linked to it.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
			Info:  "It must be required by a ConnectionService, to ensure that only the system can link to it.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_TEXT_SERVICE",
			Info:  "It must be required by a TextService (for example, SpellCheckerService) to ensure that only the system can link to it.",
		},
		report.ManifestPermission{
			Title: "android.permission.BIND_TV_INPUT",
			Info:  "It must be required by a TvInputService to ensure that only the system can link to it.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_VISUAL_VOICEMAIL_SERVICE",
			Info:  "Must be required by a link",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_VOICE_INTERACTION",
			Info:  "It must be required by a VoiceInteractionService, to ensure that only the system can be linked to it.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_VPN_SERVICE",
			Info:  "It must be required by a VpnService, to ensure that only the system can be linked to it.",
		},

		report.ManifestPermission{
			Title: "android.permission.BIND_VR_LISTENER_SERVICE",
			Info:  "It must be required by a VrListenerService, to ensure that only the system can link to it.",
		},

		report.ManifestPermission{
			Title: "android.permission.BLUETOOTH_PRIVILEGED",
			Info:  "Allows applications to pair Bluetooth devices without user interaction and allows or disallows access to the phonebook or access to messages. This is not available for third party applications.",
		},

		report.ManifestPermission{
			Title: "android.permission.BODY_SENSORS",
			Info:  "It allows the application to access sensor data that the user uses to measure what is happening inside his body, such as heart rate.",
		},

		report.ManifestPermission{
			Title: "android.permission.CAPTURE_AUDIO_OUTPUT",
			Info:  "Enables an audio output capture application.",
		},

		report.ManifestPermission{
			Title: "android.permission.CAPTURE_SECURE_VIDEO_OUTPUT",
			Info:  "Enables a secure video output capture application.",
		},

		report.ManifestPermission{
			Title: "android.permission.CAPTURE_VIDEO_OUTPUT",
			Info:  "It allows a video output capture application.",
		},

		report.ManifestPermission{
			Title: "android.permission.FOREGROUND_SERVICE",
			Info:  "Allows the common application to use.",
		},

		report.ManifestPermission{
			Title: "android.permission.GET_ACCOUNTS_PRIVILEGED",
			Info:  "Allows access to the list of accounts in the Account Service.",
		},

		report.ManifestPermission{
			Title: "android.permission.INSTALL_SHORTCUT",
			Info:  "Allows the app to install a shortcut on the Launcher.",
		},

		report.ManifestPermission{
			Title: "android.permission.INSTANT_APP_FOREGROUND_SERVICE",
			Info:  "Allows the instant application to create services in the foreground.",
		},

		report.ManifestPermission{
			Title: "android.permission.LOCATION_HARDWARE",
			Info:  "Allows the app to use hardware localization features, such as the geofencing API.",
		},

		report.ManifestPermission{
			Title: "android.permission.MANAGE_DOCUMENTS",
			Info:  "Allows the app to manage access to documents, usually as part of a document selector.",
		},

		report.ManifestPermission{
			Title: "android.permission.MANAGE_OWN_CALLS",
			Info:  "Allows a calling application to manage its own calls through self-management.",
		},

		report.ManifestPermission{
			Title: "android.permission.MEDIA_CONTENT_CONTROL",
			Info:  "It allows the application to know what content is being played and to control its reproduction.",
		},

		report.ManifestPermission{
			Title: "android.permission.NFC_TRANSACTION_EVENT",
			Info:  "Allows applications to receive NFC transaction events.",
		},

		report.ManifestPermission{
			Title: "android.permission.READ_CALL_LOG",
			Info:  "Allows the app to read the user's call log.",
		},

		report.ManifestPermission{
			Title: "android.permission.READ_PHONE_NUMBERS",
			Info:  "Allows read access to the device's phone numbers. This is a subset of the resources provided by",
		},

		report.ManifestPermission{
			Title: "android.permission.READ_VOICEMAIL",
			Info:  "Allows the application to read voice messages in the system.",
		},

		report.ManifestPermission{
			Title: "android.permission.REQUEST_COMPANION_RUN_IN_BACKGROUND",
			Info:  "Allows a 'Companion' application to run in the background.",
		},

		report.ManifestPermission{
			Title: "android.permission.REQUEST_COMPANION_USE_DATA_IN_BACKGROUND",
			Info:  "Allows a 'Companion' application to use data in the background.",
		},

		report.ManifestPermission{
			Title: "android.permission.REQUEST_DELETE_PACKAGES",
			Info:  "It allows a request to exclude packages. API-driven applications.",
		},

		report.ManifestPermission{
			Title: "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
			Info:  "Permission that an application must maintain in order to use.",
		},

		report.ManifestPermission{
			Title: "android.permission.SEND_RESPOND_VIA_MESSAGE",
			Info:  "Allows the app (Phone) to send a request to other apps to handle the message reply action during incoming calls.",
		},

		report.ManifestPermission{
			Title: "android.permission.TRANSMIT_IR",
			Info:  "Allows you to use the device's IR transmitter, if available.",
		},

		report.ManifestPermission{
			Title: "android.permission.UNINSTALL_SHORTCUT",
			Info:  "Do not use this permission in your application. This permission is no longer supported.",
		},

		report.ManifestPermission{
			Title: "android.permission.USE_BIOMETRIC",
			Info:  "Allows the app to use biometric modalities compatible with the device.",
		},

		report.ManifestPermission{
			Title: "android.permission.USE_FINGERPRINT",
			Info:  "This constant has been deprecated at API level 28. Applications must require USE_BIOMETRIC instead.",
		},

		report.ManifestPermission{
			Title: "android.permission.WRITE_CALL_LOG",
			Info:  "Allows an application to write (but not read) the user's call log data.",
		},

		report.ManifestPermission{
			Title: "android.permission.WRITE_VOICEMAIL",
			Info:  "It allows the application to modify and remove existing voice errors in the system.",
		},
	}
}
